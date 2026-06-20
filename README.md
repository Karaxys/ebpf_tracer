# ebpf_tracer

Standalone Linux eBPF traffic tracer for capturing application HTTP traffic without running an inline proxy.

This repository is being developed independently from `karaxys_backend`. The immediate milestone is to prove reliable traffic capture, reassembly, and structured JSON output in this repo first. After that, the tracer can be integrated into Karaxys through a stable output contract.

## Current Status

Validated milestone:

```text
syscall tracepoints
  -> BPF ring buffer
  -> Go agent
  -> Kafka
  -> Go worker
  -> structured HTTP conversation JSON
```

Validated test target:

```text
Application: VAmPI
Image:       erev0s/vampi:latest
Host port:   3000
App port:    5000
```

VAmPI is only a test target. The long-term goal is generic application capture similar in spirit to Akto/Kubeshark: any target process/container/workload, with plain HTTP first and TLS plaintext capture later.

## What Works

- Loads a generated cilium/ebpf program.
- Filters capture by target PID in kernel space.
- Applies runtime kernel-side capture controls for max payload size, read/write syscall capture, and stdio fd filtering.
- Learns socket tuples keyed by pid, fd, and fd generation from `bind`, `connect`, `accept`, and `/proc` fallback sync.
- Applies kernel-side target and ignored port filtering when socket tuple metadata is known.
- Applies optional cgroup filtering for container target mode before payload copy.
- Emits up to four payload chunks per syscall, with original-size and captured-size loss metadata.
- Captures syscall-level `read`, `readv`, `recvfrom`, `write`, `writev`, `sendto`, and `close` traffic.
- Emits fixed-size raw events through a BPF ring buffer.
- Publishes raw events to Kafka.
- Publishes periodic agent metrics to a separate Kafka topic.
- Spools failed Kafka deliveries to a local JSONL file when configured.
- Publishes backend heartbeats and polls backend remote config when agent control credentials are provided.
- Reassembles request and response streams in the worker.
- Parses HTTP/1.x requests and responses.
- Emits structured JSON records.
- Tracks agent and worker diagnostics.

## Known Limits

- Container mode discovers target PIDs from the container cgroup. PID and PID-tree modes are still useful for local debugging.
- Flask debug mode, Gunicorn, Node clusters, and similar runtimes may spawn child workers; validate the selected target mode against the real serving processes.
- Socket/port filtering requires a learned socket tuple. The agent learns new sockets in kernel space and hydrates already-open sockets after the first successful `/proc` metadata resolution.
- TLS plaintext capture is not enabled in the production agent. See `docs/tls_plaintext_capture.md` and `bpf/tls_plaintext_prototype.bpf.c` for the uprobe plan and limitations.
- Kernel socket metadata currently carries port, role, and address family. IP addresses still come from user-space `/proc` metadata.
- Docker and Kubernetes metadata enrichment is best-effort. The agent parses cgroups in-process, reads Docker metadata from the local Docker Unix socket when present, and queries the Kubernetes API only when service-account credentials exist.

## Repository Layout

```text
.
├── bpf/
│   └── tracer.bpf.c              # eBPF C program
├── cmd/
│   ├── agent/                    # loads BPF, reads ringbuf, writes Kafka
│   └── worker/                   # consumes Kafka, reassembles, emits JSON
├── pkg/bpf/                      # generated bpf2go bindings and object
├── docker-compose.yml            # local Kafka
├── go.mod
└── README.md
```

## Prerequisites

- Linux with eBPF support.
- Root privileges for the agent.
- Docker.
- Go.
- Kafka from this repo's `docker-compose.yml`.

The currently checked-in generated BPF object allows the agent to build without regenerating BPF artifacts. If you change `bpf/tracer.bpf.c`, you need clang and cilium `bpf2go` generation support.

## Build

```bash
cd /home/shion/Documents/ebpf_tracer
mkdir -p bin
go build -o bin/agent ./cmd/agent
go build -o bin/worker ./cmd/worker
```

Run tests:

```bash
go test ./...
```

## One-Command Local VAmPI Capture

For local validation, this repo includes a wrapper that starts Kafka, starts the
VAmPI test target, builds the agent/worker, launches the worker, and runs the
agent against the VAmPI container:

```bash
make local-vampi
```

To send normalized conversations into Karaxys backend ingestion:

```bash
KARAXYS_BACKEND_URL=http://127.0.0.1:8081 \
KARAXYS_ENROLLMENT_TOKEN=<enrollment-token-from-backend> \
make local-vampi
```

For deterministic debugging, use a fresh Kafka topic per local run so a new
worker group does not replay stale messages from an older tracer build:

```bash
KAFKA_TOPIC="raw-network-traffic-$(date +%s)" \
KARAXYS_BACKEND_URL=http://127.0.0.1:8081 \
KARAXYS_ENROLLMENT_TOKEN=<enrollment-token-from-backend> \
make local-vampi
```

Fish shell:

```fish
set -x KAFKA_TOPIC raw-network-traffic-(date +%s)
set -x KARAXYS_BACKEND_URL http://127.0.0.1:8081
set -x KARAXYS_ENROLLMENT_TOKEN (string trim (cat /tmp/karaxys_enrollment_token))
make local-vampi
```

The script registers the agent through `POST /agents/register`, receives a
per-agent token, and uses that token for `POST /v1/ingest/conversations`.
The agent also uses the same token for `POST /agents/heartbeat` and
`GET /agents/config`, publishes metrics to `karaxys.agent.metrics`, and writes
Kafka delivery failures to `logs/agent-spool.jsonl`.
`KARAXYS_AGENT_TOKEN` is still accepted as a local compatibility fallback, but
the production flow should use enrollment tokens and per-agent credentials.

In another terminal, generate sample traffic:

```bash
make smoke-traffic
```

Expected successful worker/backend state:

- `logs/worker.log` shows `routedReq>0`, `routedResp>0`, `reqParsed>0`,
  `respParsed>0`, and `parsed>0`.
- Backend logs show `POST /v1/ingest/conversations | Status: 202`.
- Backend inventory contains three VAmPI endpoints from the smoke flow:
  `/createdb`, `/users/v1/register`, and `/users/v1/login`.
- Inventory records have `CaptureSource: ebpf`, `CaptureMode: container`, and
  redacted sensitive values in sample bodies.

Inventory check with fish:

```fish
set ACCESS_TOKEN (string trim (cat /tmp/karaxys_access_token))
curl -s "http://127.0.0.1:8081/inventory?limit=50" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq
```

The agent requires Linux eBPF privileges and will invoke `sudo` for the agent
process. Worker logs are written to `logs/worker.log`; failed sink deliveries
are written to `logs/worker-deadletters.jsonl` when backend ingestion is enabled.

If `logs/worker.log` shows `routedResp>0` but `routedReq=0`, the worker is only
receiving response bytes from Kafka and cannot build HTTP conversations. Stop the
agent, rebuild by rerunning `make local-vampi`, use a fresh `KAFKA_TOPIC`, then
send traffic again. Expected healthy counters after `make smoke-traffic` are
`routedReq>0`, `reqParsed>0`, `parsed>0`, followed by backend
`POST /v1/ingest/conversations | Status: 202` logs.

## End-To-End Workflow With VAmPI

### 1. Start Kafka

```bash
cd /home/shion/Documents/ebpf_tracer
docker compose up -d kafka
```

Create the raw event topic:

```bash
docker exec raven-kafka kafka-topics.sh \
  --bootstrap-server localhost:9092 \
  --create \
  --if-not-exists \
  --topic raw-network-traffic \
  --partitions 3 \
  --replication-factor 1
```

Verify:

```bash
docker exec raven-kafka kafka-topics.sh \
  --bootstrap-server localhost:9092 \
  --list
```

Expected:

```text
raw-network-traffic
```

### 2. Start VAmPI

VAmPI listens on port `5000` inside the container. Map host port `3000` to container port `5000`.

```bash
docker rm -f vampi-test 2>/dev/null || true
docker run -d --name vampi-test -p 3000:5000 erev0s/vampi:latest
```

Verify the app:

```bash
docker logs --tail 40 vampi-test
curl -i http://127.0.0.1:3000/
```

If VAmPI is running correctly, Docker logs should show Flask listening on `0.0.0.0:5000`.

### 3. Find The Serving PID

VAmPI runs Flask in debug mode and usually spawns a child Python process. Trace the child process that looks like `/usr/local/bin/python /vampi/app.py`.

```bash
docker top vampi-test -eo pid,ppid,comm,args
```

Bash:

```bash
export VAMPI_PID="$(docker top vampi-test -eo pid,ppid,comm,args | awk '$0 ~ "/vampi/app.py" {print $1; exit}')"
echo "$VAMPI_PID"
```

Fish:

```fish
set VAMPI_PID (docker top vampi-test -eo pid,ppid,comm,args | awk '$0 ~ "/vampi/app.py" {print $1; exit}')
echo $VAMPI_PID
```

The PID must be non-empty.

### 4. Start The Worker

Terminal 1:

Bash:

```bash
./bin/worker \
  -kafka-bootstrap localhost:9092 \
  -topic raw-network-traffic \
  -group-id "vampi-debug-$(date +%s)" \
  -offset-reset earliest \
  -pretty=true \
  -debug-payload=true
```

Fish:

```fish
./bin/worker \
  -kafka-bootstrap localhost:9092 \
  -topic raw-network-traffic \
  -group-id vampi-debug-(date +%s) \
  -offset-reset earliest \
  -pretty=true \
  -debug-payload=true
```

### 5. Start The Agent

Terminal 2:

Bash:

```bash
sudo ./bin/agent \
  -pid "$VAMPI_PID" \
  -kafka-bootstrap localhost:9092 \
  -topic raw-network-traffic \
  -fd-filter=false \
  -allow-non-socket-fds=true \
  -stats-interval 5s
```

Fish:

```fish
sudo ./bin/agent \
  -pid "$VAMPI_PID" \
  -kafka-bootstrap localhost:9092 \
  -topic raw-network-traffic \
  -fd-filter=false \
  -allow-non-socket-fds=true \
  -stats-interval 5s
```

For the first validation run, disabling the FD filter keeps capture broad and makes it easier to diagnose whether the selected PID is correct. `-allow-non-socket-fds=true` also tells the kernel-side fd gate not to drop stdio descriptors during this debug run.

### 6. Generate VAmPI Traffic

Terminal 3:

```bash
curl -i http://127.0.0.1:3000/createdb
```

Register a user:

```bash
curl -i -H 'Content-Type: application/json' \
  -d '{"username":"tracer","email":"tracer@123","password":"password123"}' \
  http://127.0.0.1:3000/users/v1/register
```

Log in:

```bash
curl -i -H 'Content-Type: application/json' \
  -d '{"username":"tracer","password":"password123"}' \
  http://127.0.0.1:3000/users/v1/login
```

Expected worker output:

```text
TRAFFIC GET /createdb -> 200 OK
TRAFFIC POST /users/v1/register -> 200 OK
TRAFFIC POST /users/v1/login -> 200 OK
```

Each record should include structured JSON with method, URL, host, path, request headers, request body, response status, and response body.

## Optional Port Filtering

Once broad PID capture works, run with socket FD filtering to reduce noise. Because VAmPI listens on container port `5000`, use `5000`, not host port `3000`.

```bash
sudo ./bin/agent \
  -pid "$VAMPI_PID" \
  -kafka-bootstrap localhost:9092 \
  -topic raw-network-traffic \
  -target-port 5000 \
  -fd-filter=true \
  -stats-interval 5s
```

This should remove noise from file descriptors such as Flask stdout/stderr logs.

## Kernel-Side Capture Controls

The agent now programs a `capture_config` eBPF map at startup. These controls are enforced before payloads are copied into ring-buffer events:

- `-max-payload-size`: maximum bytes copied per syscall payload. Default and upper bound is `16384`; the kernel emits up to four 4096-byte chunks per syscall.
- `-capture-read-syscalls`: capture `read`, `readv`, and `recvfrom` payloads. Default is `true`.
- `-capture-write-syscalls`: capture `write`, `writev`, and `sendto` payloads. Default is `true`.
- `-allow-non-socket-fds`: also enables kernel-side stdio fd capture for debug runs. Default production behavior drops fd `0`, `1`, and `2` before ring-buffer emission.

The read/write controls are syscall-direction controls, not inbound/outbound network-role controls. Target and ignored port filtering now runs in kernel space when a socket tuple is known; network role filtering and unknown tuples still fall back to user-space `/proc` metadata.

Container target mode also programs an `allowed_cgroups` map. When
`-cgroup-filter=true`, the kernel checks `bpf_get_current_cgroup_id()` before
payload copy, so unrelated containers on the same host are dropped early.

## Kernel-Side Socket Tuple And Port Filtering

The agent now also programs `target_ports` and `ignored_ports` eBPF maps when `-fd-filter=true`. The BPF program learns socket tuples from:

- `bind`: records local/listening port for server sockets.
- `connect`: records remote port for outbound client sockets.
- `accept` / `accept4`: promotes listener metadata to the accepted socket and records peer port when userspace provides an address buffer.
- `/proc` fallback sync: when the Go agent resolves socket metadata for an already-open fd, it writes that tuple back into the `socket_tuples` map so subsequent syscalls can be filtered in kernel space.

Kernel port filtering is conservative: if no tuple is known yet, the event is allowed through and user-space filtering remains the fallback. This avoids false negatives for long-running processes whose sockets existed before the agent attached.

## Diagnostics

Agent periodic stats:

```text
agent_stats[periodic] ring_records=... decoded=... data=... close=... produce_attempts=... delivery_successes=...
kernel_drops delta reserve=... copy_write=... copy_read=... iov_read=... missing_ctx=... noise=... fd_filter=... direction_filter=... port_filter=... cgroup_filter=...
```

Useful interpretation:

- `ring_records=0`: wrong PID, no traffic while the agent was running, or the target process is a child process.
- `decoded>0` and `produce_attempts=0`: events are being skipped before Kafka.
- `delivery_failures>0`: Kafka producer/broker problem.
- kernel `reserve>0`: ring buffer pressure.
- kernel `cgroup_filter>0`: the kernel dropped events outside the selected container cgroup.
- `logs/agent-spool.jsonl` non-empty: Kafka was unavailable or the local producer queue overflowed.
- `karaxys.agent.metrics` messages: periodic agent stats and kernel drop counters are being published.

Worker periodic stats:

```text
stats[periodic] received=... decoded=... parsed=... routedReq=... routedResp=... reqParsed=... respParsed=...
```

Useful interpretation:

- `received=0`: worker is not seeing Kafka messages.
- `routedReq>0` and `routedResp=0`: only request-side bytes are being captured.
- `reqPending` or `respPending` rising: parser has partial/incomplete data.
- `parsed>0`: structured conversation output is working.

## Current Event Flow

```text
target process syscalls
  -> bpf/tracer.bpf.c
  -> BPF ring buffer
  -> cmd/agent
  -> Kafka topic raw-network-traffic
  -> cmd/worker
  -> structured JSON
  -> Karaxys backend ingestion when -output-sink=http is enabled

cmd/agent
  -> Kafka topic karaxys.agent.metrics
  -> POST /agents/heartbeat
  -> GET /agents/config
  -> local JSONL spool on Kafka delivery failure
```

## Generated Files And Git Policy

`bpf/headers/vmlinux.h` is ignored because it is generated from the host kernel and can vary across machines:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/headers/vmlinux.h
```

`pkg/bpf/bpf_bpfel.o` is intentionally allowed in git because `pkg/bpf/bpf_bpfel.go` embeds it with `go:embed`. Without that object file, a fresh clone cannot build the current agent unless BPF generation is run first.

The architecture planning documents are ignored:

```text
karaxys_implementation_plan.md
standalone_ebpf_tracer_plan.md
```

## Regenerating BPF Bindings

Only needed after changing `bpf/tracer.bpf.c`.

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/headers/vmlinux.h
go generate ./pkg/bpf
```

Then rebuild:

```bash
go build -o bin/agent ./cmd/agent
```
## Sample Output

```json
{
  "_id": {
    "$oid": "6c9ae5a4e3c915a3fe894eb4"
  },
  "schema_version": "http.conversation.v1",
  "capture_source": "ebpf",
  "capture_mode": "container",
  "captured_at": {
    "$date": "2026-04-29T16:56:55.061966271Z"
  },
  "connection": {},
  "process": {
    "pid": 60129,
    "name": "python",
    "exe": "/usr/local/bin/python3.11"
  },
  "container": {
    "id": "f83a527c8a7f87d004d4361bfcdccc5d207f0edb2ff2f504d652300c5d7385b8",
    "name": "vampi-test",
    "image": "erev0s/vampi:latest",
    "runtime": "docker"
  },
  "loss": {},
  "http": {
    "request": {
      "method": "POST",
      "url": "http://127.0.0.1:3000/users/v1/login",
      "host": "127.0.0.1:3000",
      "path": "/users/v1/login",
      "headers": {
        "Accept": [
          "*/*"
        ],
        "Content-Length": [
          "49"
        ],
        "Content-Type": [
          "application/json"
        ],
        "User-Agent": [
          "curl/8.19.0"
        ]
      },
      "body": "{\n  \"username\": \"tracer\",\n  \"password\": \"password123\"\n}"
    },
    "response": {
      "status": "200 OK",
      "headers": {
        "Content-Length": [
          "225"
        ],
        "Content-Type": [
          "application/json"
        ],
        "Date": [
          "Wed, 29 Apr 2026 16:56:56 GMT"
        ],
        "Server": [
          "Werkzeug/2.2.3 Python/3.11.15"
        ]
      },
      "body": "{\n  \"auth_token\": \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Nzc0ODE4NzYsImlhdCI6MTc3NzQ4MTgxNiwic3ViIjoidHJhY2VyIn0.pleiyPXh6JpFxG4iMsAu5a6E4PuS5YPxGNPSSwCQUqE\",\n  \"message\": \"Successfully logged in.\",\n  \"status\": \"success\"\n}"
    }
  }
}
```
## Roadmap

Next production-grade steps:

1. Add validated OpenSSL/BoringSSL TLS plaintext capture as an optional module.
2. Validate Go `crypto/tls` capture only against an explicit Go version and architecture matrix.
3. Add Kubernetes DaemonSet manifests with least-privilege RBAC for pod metadata lookup.
4. Add load-test profiles for high-throughput API services and ring-buffer pressure.
5. Add signed release artifacts and a hardened deployment profile for production hosts.

## License

See [LICENSE](./LICENSE).

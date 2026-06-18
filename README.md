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
- Captures syscall-level `read`, `readv`, `recvfrom`, `write`, `writev`, `sendto`, and `close` traffic.
- Emits fixed-size raw events through a BPF ring buffer.
- Publishes raw events to Kafka.
- Reassembles request and response streams in the worker.
- Parses HTTP/1.x requests and responses.
- Emits structured JSON records.
- Tracks agent and worker diagnostics.

## Known Limits

- You currently need to provide the exact serving process PID.
- Flask debug mode, Gunicorn, Node clusters, and similar runtimes may spawn child workers; tracing the parent PID may not capture request traffic.
- Socket/port filtering is currently optional and should be made the default production path.
- TLS plaintext capture is not implemented yet.
- Connection metadata such as source/destination IP and port is not yet included in the normalized output.

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

The script registers the agent through `POST /agents/register`, receives a
per-agent token, and uses that token for `POST /v1/ingest/conversations`.
`KARAXYS_AGENT_TOKEN` is still accepted as a local compatibility fallback, but
the production flow should use enrollment tokens and per-agent credentials.

In another terminal, generate sample traffic:

```bash
make smoke-traffic
```

The agent requires Linux eBPF privileges and will invoke `sudo` for the agent
process. Worker logs are written to `logs/worker.log`; failed sink deliveries
are written to `logs/worker-deadletters.jsonl` when backend ingestion is enabled.

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
  -stats-interval 5s
```

Fish:

```fish
sudo ./bin/agent \
  -pid "$VAMPI_PID" \
  -kafka-bootstrap localhost:9092 \
  -topic raw-network-traffic \
  -stats-interval 5s
```

For the first validation run, do not enable the FD filter. This keeps capture broad and makes it easier to diagnose whether the selected PID is correct.

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
  -enable-user-fd-filter \
  -stats-interval 5s
```

This should remove noise from file descriptors such as Flask stdout/stderr logs.

## Diagnostics

Agent periodic stats:

```text
agent_stats[periodic] ring_records=... decoded=... data=... close=... produce_attempts=... delivery_successes=...
kernel_drops delta reserve=... copy_write=... copy_read=... iov_read=... missing_ctx=... noise=...
```

Useful interpretation:

- `ring_records=0`: wrong PID, no traffic while the agent was running, or the target process is a child process.
- `decoded>0` and `produce_attempts=0`: events are being skipped before Kafka.
- `delivery_failures>0`: Kafka producer/broker problem.
- kernel `reserve>0`: ring buffer pressure.

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
  "schema_version": "http.v1",
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
    "id": "f83a527c8a7f87d004d4361bfcdccc5d207f0edb2ff2f504d652300c5d7385b8"
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

1. Make socket/port filtering the default capture path.
2. Add container/process-tree discovery so child PIDs are traced automatically.
3. Add target modes:
   - `--pid`
   - `--container`
   - `--probe-all-pids`
4. Add source/destination IP and port metadata to emitted records.
5. Add ignored internal ports for Kafka, MongoDB, Redis, etc.
6. Add TLS plaintext capture with OpenSSL uprobes.
7. Add Go `crypto/tls` capture.
8. Add Karaxys adapter that maps normalized conversations to `TrafficLog`.

## License

See [LICENSE](./LICENSE).

# eBPF Tracer — Scrum Plan

---

## Overview

This document defines the full sprint-by-sprint execution plan for evolving `ebpf_tracer` into a target-agnostic HTTP traffic capture system. The plan is organized into milestones, each composed of focused sprints with clear deliverables and acceptance criteria.

---

## Current State (Milestone 0 — Baseline Complete)

The following capabilities have been validated and serve as the foundation for all subsequent work:

- Syscall tracepoints
- Ring buffer
- Go agent
- Kafka integration
- Worker
- HTTP reassembly
- Structured JSON output

**Remaining risk:** The original baseline proved feasibility, not production readiness.

### Current Implementation Status — 2026-04-29

The first implementation pass for Milestones 1–3 has been started and validated against VAmPI container capture.

Validated in the current branch:

- Container target mode can discover and trace the VAmPI serving process without manually selecting the Flask child PID.
- Agent captures syscall traffic from the target container and publishes to Kafka.
- Worker reconstructs complete HTTP/1.x conversations and emits complete endpoint JSON.
- Normalized non-redundant JSON output is now available by default through `-output-contract normalized`.
- Legacy/Karaxys-compatible output remains available through `-output-contract legacy`.
- Flow-level filtering now preserves request headers, request bodies, response headers, response bodies, and close events for a classified `(pid, fd, generation)` flow.
- Process metadata and container ID are emitted in normalized output.
- Explicit loss/truncation fields exist in the raw and normalized event contracts.
- Bounded in-agent queue, backpressure modes, health, readiness, and metrics endpoints have been introduced.

Known gaps still requiring hardening:

- Connection metadata is still not consistently populated in normalized output and requires validation/fix of socket lifecycle metadata capture.
- True BPF-side multi-chunk payload emission is not complete; current implementation exposes truncation/loss rather than guaranteeing full large-body reconstruction.
- Validation is currently strongest on VAmPI; Juice Shop, crAPI, httpbin/nginx, Go HTTP, and FastAPI/Gunicorn validation are still pending.
- Disk spool/WAL, Kafka circuit breaker behavior, and load-tested throughput targets are not complete.
- Kubernetes/container-runtime production metadata is not complete.

---

## Execution Order Summary

| Phase | Focus |
|---|---|
| 1 | Generic Capture Foundation |
| 2 | Capture Completeness |
| 3 | Resiliency and Throughput |
| 4 | Container and Kubernetes Productionization |
| 5 | TLS Plaintext Capture |
| 6 | Analyzer Integration |
| 7 | Product Maturity |

---

---

# Milestone 1 — Generic Capture Foundation

---

## Sprint 1: Target Control Plane

### Objective
Make the tracer target-agnostic and safe to attach to arbitrary local and containerized applications.

### Deliverables

- `--pid <pid>` targeting
- `--pid-tree <pid>` targeting
- `--container <container-name-or-id>` targeting
- `--all-pids` mode
- Process discovery and child process discovery
- Dynamic target map updates at runtime
- Target lifecycle logging (active PIDs, dead PID removal)

### Notes
The existing `target_pids` BPF map remains the mechanism. The Go agent owns target discovery and refresh. Support for `--k8s-namespace`, `--pod`, and `--label-selector` is deferred to Milestone 4.

### Acceptance Criteria

- [x] Captures VAmPI without manually identifying the Flask child PID.
- [ ] Captures Juice Shop by container name.
- [ ] Captures crAPI service containers by container ID or name.
- [x] Captures existing child processes via container PID discovery.
- [x] Logs active traced PIDs and removes entries for terminated processes during target refresh.
- [x] Application availability is unaffected if the tracer starts, stops, or crashes in VAmPI validation.
- [ ] Validate child processes spawned after tracer startup across Gunicorn/Node/FastAPI targets.

---

## Sprint 2: Default Socket Filtering and Connection Metadata

### Objective
Enable production-safe default filtering and enrich all captured events with full connection metadata.

### Deliverables

**Socket Filtering**
- Socket FD filtering enabled by default
- Port-based filtering: `--target-ports`, `--ignore-ports`
- Inbound/outbound classification: `--capture-inbound`, `--capture-outbound`
- Broad capture available only via explicit opt-in: `--allow-non-socket-fds`, `--disable-fd-filter`
- Filtered and skipped event counts reported in logs/metrics

**Connection Metadata**
- Local IP and port
- Remote IP and port
- Protocol and address family
- PID and process name
- Executable path
- Container ID and name (where available)
- Capture direction: inbound / outbound / unknown

**Normalized Contract v1**

Every emitted conversation must include:

```json
{
  "schema_version": "1",
  "capture_source": "ebpf",
  "capture_mode": "pid | container | all-pids",
  "captured_at": "<ISO8601>",
  "request": {},
  "response": {},
  "connection": {
    "src_ip": "",
    "src_port": 0,
    "dst_ip": "",
    "dst_port": 0
  },
  "process": {
    "pid": 0,
    "name": "",
    "exe": ""
  },
  "container": {
    "id": "",
    "name": ""
  },
  "loss": {},
  "method": "",
  "url": "",
  "host": "",
  "path": "",
  "req_headers": {},
  "req_body": "",
  "resp_status": 0,
  "resp_body": ""
}
```

### Acceptance Criteria

- [x] stdout, stderr, and file I/O noise is excluded by default for the validated VAmPI flow.
- [x] Internal infrastructure ports (Kafka, Mongo, Redis) are ignorable via config.
- [ ] Juice Shop, crAPI, and VAmPI all produce clean HTTP conversations without per-app code changes.
- [x] Filtered and skipped event counts are surfaced in metrics or logs.
- [x] Existing downstream field shape is not broken; legacy mode remains available.
- [x] Normalized non-redundant conversation schema is implemented.
- [x] Worker tests validate schema output.
- [ ] Raw event and normalized conversation schemas need formal README/API documentation.
- [ ] Connection metadata must be consistently populated and validated for short-lived and keep-alive sockets.

---

---

# Milestone 2 — Capture Completeness and Reassembly

---

## Sprint 3: Multi-Chunk Payload Capture

### Objective
Eliminate the 4096-byte payload ceiling and introduce explicit truncation and loss semantics.

### Deliverables

- Multi-chunk capture for large `read` and `write` payloads
- Multi-chunk capture for `recvfrom` and `sendto`
- Improved `readv`/`writev` handling
- Original syscall length vs. captured length tracking
- Truncation and loss flags on events
- Configurable max body and stream limits with explicit overflow records
- Ring buffer, Kafka queue, and worker stream overflow visibility
- Sequence-gap detection in worker
- Tests for request and response bodies exceeding one BPF event

### Acceptance Criteria

- [ ] A request body larger than 4096 bytes is fully reconstructed.
- [ ] A response body larger than 4096 bytes is fully reconstructed.
- [x] Events can carry original size vs captured size and loss metadata.
- [ ] Bodies exceeding the configured maximum are explicitly flagged as policy-truncated in output.
- [x] Ring buffer drops, Kafka queue drops, worker stream overflows, and parser gaps are surfaced in metrics or logs.
- [ ] No silent truncation or silent drop paths remain.

---

## Sprint 4: Robust HTTP Reassembly

### Objective
Harden the HTTP reassembly layer to handle production-grade traffic reliably.

### Deliverables

- Stronger session keying using connection metadata
- Request/response pipelining support
- HTTP keep-alive support
- Chunked transfer encoding support
- Gzip, deflate, and br decompression policy
- Response-without-Content-Length handling
- Out-of-order and gap detection
- Bounded memory eviction policy
- Malformed HTTP stream isolation

### Acceptance Criteria

- [ ] Pipelined and keep-alive connections are correctly reassembled.
- [ ] Chunked transfer encoded bodies are decoded and complete.
- [ ] A single malformed stream does not affect other active sessions.
- [ ] Worker memory does not grow unboundedly under sustained load.

---

---

# Milestone 3 — Throughput and Resiliency

---

## Sprint 5: Agent Performance Hardening

### Objective
Validate and enforce performance constraints to ensure zero measurable impact on instrumented applications.

### Deliverables

- Configurable ring buffer size
- Batched Kafka production
- Partition key strategy by connection or session
- Producer queue pressure metrics
- CPU and memory usage caps
- Graceful degradation policy
- Zero application-impact validation
- Benchmark harness

### Performance Targets

| Metric | Target |
|---|---|
| App CPU overhead (normal load) | < 2–5% |
| App crash risk if tracer fails | None |
| Sustained local event throughput | Thousands of events/sec |
| Silent drop paths | None |

*Exact thresholds should be measured against target hardware and workloads rather than assumed.*

### Acceptance Criteria

- [ ] Benchmark harness produces repeatable results.
- [ ] Application processes show no syscall failures or crashes when tracer is attached, stopped, or restarted.
- [ ] CPU and memory usage remain within configured caps under sustained load.

---

## Sprint 6: Durable Buffering and Backpressure Policy

### Objective
Define and implement a deliberate, explicit failure policy for Kafka unavailability and downstream pressure.

### Deliverables

- Defined behavior when Kafka is unavailable
- Local bounded in-memory queue
- Optional disk spool / WAL for production mode
- Drop policy applied only after configured limits, with explicit counters
- Circuit breaker around Kafka producer
- Health and readiness endpoints
- Self-monitoring metrics

### Backpressure Modes

| Mode | Behavior |
|---|---|
| `strict` | Block internal pipeline; preserve events until buffer is full |
| `best-effort` | Drop oldest or newest events with explicit counters |
| `sampled` | Reduce capture volume proportionally under pressure |
| `metadata-only` | Preserve conversation metadata; drop bodies under pressure |

### Acceptance Criteria

- [ ] Kafka outage does not cause silent event loss.
- [x] Bounded local in-memory queue exists.
- [x] Backpressure modes exist: `best-effort`, `strict`, `drop-newest`, `drop-oldest`.
- [x] Queue/drop events are counted and surfaced in metrics.
- [ ] Disk spool/WAL for production mode is implemented.
- [ ] Circuit breaker recovers automatically when Kafka becomes available.
- [x] Health and readiness endpoints exist.
- [ ] Health and readiness endpoints need production-grade degraded-state validation.

---

---

# Milestone 4 — Container and Kubernetes Readiness

---

## Sprint 7: Container Runtime Support

### Objective
Enable first-class container-aware capture with rich metadata.

### Deliverables

- Docker container discovery
- Container ID, name, and image labels on all events
- Cgroup association for PID-to-container mapping
- Container restart handling
- Multi-container support
- Per-container include/exclude filters

### Validation Targets

- VAmPI
- Juice Shop
- crAPI
- Custom Docker Compose applications

### Acceptance Criteria

- [ ] Container name and ID are present on all captured events for containerized targets.
- [ ] Container restarts are handled without tracer reconfiguration.
- [ ] Multiple containers on the same host can be captured concurrently.

---

## Sprint 8: Kubernetes DaemonSet Deployment

### Objective
Deliver a production-ready Kubernetes deployment model.

### Deliverables

- DaemonSet manifest or Helm chart
- Privileged and security context documentation
- Namespace selector
- Pod selector
- Label selector
- Service metadata enrichment
- Node metadata on events
- Pod restart handling
- Rolling upgrade strategy

### Acceptance Criteria

- [ ] DaemonSet deploys cleanly to a standard Kubernetes cluster.
- [ ] Namespace, pod, and label selectors correctly restrict capture scope.
- [ ] Pod restarts are handled transparently.
- [ ] Helm chart passes `helm lint`.

---

---

# Milestone 5 — Protocol Coverage

---

## Sprint 9: HTTP/1.x Production Polish

### Deliverables

- Complete HTTP/1.0 and HTTP/1.1 coverage
- Chunked request and response handling
- Compressed body handling
- Multipart form handling
- Binary body policy
- Redaction hooks
- Configurable max body policy
- Optional body hashing
- Content-type-based capture behavior

---

## Sprint 10: HTTP/2 and gRPC Planning and Prototype

### Deliverables

- Decision document: parse HTTP/2 frames from plaintext vs. reconstruct post-TLS-decryption
- h2c (HTTP/2 cleartext) support where practical
- gRPC metadata and body framing investigation
- Test service for gRPC
- Capture contract extensions for HTTP/2 and gRPC

*This sprint may follow TLS work if most HTTP/2 and gRPC traffic in target environments is TLS-only.*

---

---

# Milestone 6 — TLS Plaintext Capture

---

## Sprint 11: OpenSSL TLS Capture

### Deliverables

- uprobes for `SSL_read` and `SSL_write`
- Support for `SSL_read_ex` and `SSL_write_ex`
- libssl path discovery and per-process library resolution
- TLS event flagging
- Correlation to connection metadata
- Tests with nginx, curl, and OpenSSL-linked applications

---

## Sprint 12: TLS Runtime Expansion

### Deliverables

- Investigation and implementation coverage for: BoringSSL, LibreSSL, NSS
- Node.js OpenSSL behavior documentation
- Python OpenSSL behavior documentation
- Java TLS feasibility assessment (separate strategy may be required due to JVM internals)

---

## Sprint 13: Go `crypto/tls` Capture

### Deliverables

- Go symbol discovery strategy
- Version-specific compatibility plan
- Uprobe attachment for Go TLS read/write paths where feasible
- Documented fallback limitations
- Tests with Go HTTPS services
- Event contract parity with OpenSSL TLS events

---

---

# Milestone 7 — Security, Privacy, and Policy Controls

---

## Sprint 14: Sensitive Data Controls

### Deliverables

- Header redaction
- Body redaction hooks
- JWT and token masking
- Password field masking
- Configurable allow/deny body capture by content type
- Per-service capture policy
- Metadata-only mode
- Audit logs for capture policy changes

---

## Sprint 15: RBAC and Operational Safety

### Deliverables

- Least privilege documentation
- Capabilities and security context documentation
- Signing and checksum verification for BPF objects
- Configuration validation on startup
- Safe defaults for all modes
- Dry-run mode
- Explicit warnings for `--all-pids` mode
- Per-target resource limits

---

---

# Milestone 8 — Analyzer Integration

---

## Sprint 16: Analyzer Adapter

### Deliverables

- Normalized capture contract mapped to downstream `TrafficLog` format
- Preserved analyzer and scanner interfaces
- `source = ebpf` field on all forwarded events
- Migration configuration:
  - Proxy mode
  - eBPF mode
  - Dual mode (both simultaneously)
- Adapter integration tests

*This sprint begins only after the standalone normalized contract is stable.*

---

## Sprint 17: Dual-Path Parity

### Deliverables

- Side-by-side operation of proxy and eBPF capture paths
- Captured endpoint comparison
- Method, path, status, and body presence comparison
- Missing conversation detection
- Parity statistics report
- Rollback-to-proxy support

### Acceptance Criteria

- [ ] eBPF path matches or exceeds proxy capture coverage for plain HTTP traffic.
- [ ] Differences are explained by TLS, plaintext, or runtime limitations.

---

## Sprint 18: Controlled Proxy Deprecation

### Deliverables

- Feature flag rollout mechanism
- Staged deployment process
- Rollback plan
- Operational dashboard
- Cutover checklist
- Removal of proxy dependency from default deployment

---

---

# Milestone 9 — Observability and Product-Grade Operations

---

## Sprint 19: Metrics and Dashboards

### Prometheus-Style Metrics to Deliver

- Ring buffer records and drops
- Event decode failures
- Kafka delivery failures and queue pressure
- Worker parse failures
- Stream evictions
- Body truncations
- Active targets and active sessions
- Events/sec and bytes/sec
- Per-container and per-node statistics

---

## Sprint 20: Health, Readiness, and Diagnostics

### Deliverables

- `/healthz` endpoint
- `/readyz` endpoint
- `/metrics` endpoint
- Diagnostics dump endpoint
- Config dump endpoint (secrets redacted)
- Target discovery debug endpoint and logs
- BPF attachment status reporting
- Kernel compatibility checks on startup

---

---

# Milestone 10 — Scale and Reliability Certification

---

## Sprint 21: Load Testing Framework

### Load Test Tools

- k6
- wrk
- vegeta
- hey
- Custom large body generator
- Multi-container Docker Compose scenario
- Kubernetes test namespace

### Test Scenarios

| Scenario | Description |
|---|---|
| Small requests, high RPS | Baseline throughput |
| Large JSON bodies | Payload completeness under volume |
| Mixed body sizes | Realistic traffic simulation |
| Concurrent keep-alive | Connection multiplexing |
| Service restart | Target recovery |
| Tracer restart | Agent recovery |
| Kafka outage | Backpressure and buffering |
| Worker crash and restart | Worker resilience |
| Node pressure | System-level stress |

---

## Sprint 22: Performance Tuning

### Deliverables

- Tuned ring buffer sizes
- Kafka batching defaults
- Worker concurrency model
- Partitioning strategy
- Memory caps
- Eviction policy
- CPU and memory profile results
- Regression thresholds in CI

---

---

# Milestone 11 — CI/CD and Release Engineering

---

## Sprint 23: Automated Build and Test Pipeline

### Deliverables

- Go unit tests
- BPF build validation
- BPF object reproducibility checks
- Integration tests gated by Linux/eBPF environment availability
- Docker image build
- Image scanning
- Release artifacts

---

## Sprint 24: Packaging

### Deliverables

- Standalone binary distribution
- Docker image
- Helm chart
- Docker Compose example
- Sample configuration files
- Production hardening guide
- Troubleshooting guide

---

---

# Milestone 12 — Advanced Product Capabilities

The following are post-foundation candidates, sequenced after core capture, resiliency, and integration work is complete.

| Capability | Notes |
|---|---|
| Service map generation | Requires connection metadata foundation |
| API inventory generation | Requires HTTP reassembly foundation |
| OpenAPI schema inference | Post-inventory |
| Endpoint deduplication | Post-inventory |
| Auth and session correlation | Post-connection metadata |
| GraphQL parsing | Protocol extension |
| WebSocket capture | Protocol extension |
| gRPC decoding | Follows HTTP/2 work |
| HTTP/2 stream reconstruction | Follows Sprint 10 |
| Sampling strategies | Follows backpressure work |
| Distributed multi-node correlation | Follows Kubernetes work |
| PCAP-style export | Standalone feature |
| SIEM and webhook integrations | Integration layer |
| Traffic replay and export | Post-inventory |

---

---

# Generic Validation Matrix

All sprints through Milestone 2 must be validated against the following target matrix. Validation against VAmPI alone is insufficient.

| Target | Runtime | Purpose |
|---|---|---|
| VAmPI | Python / Flask | Baseline regression |
| OWASP Juice Shop | Node.js / Express | Node process model, JSON-heavy APIs |
| crAPI | Multi-service | Realistic API and microservice traffic |
| nginx / httpbin | Native / proxy | Controlled, predictable HTTP |
| Small Go HTTP service | Go | Prep for Go TLS work |
| Python FastAPI / Gunicorn | Multiprocess | Child PID and process-tree validation |

### Per-Target Test Coverage

For each target, validate:

- `--pid`
- `--pid-tree`
- `--container`
- Socket filtering on
- Large request body
- Large response body
- Concurrent load
- Process restart
- Tracer restart
- Kafka unavailable and recovered

---

---

# Immediate Next Sprint Checklist

## Current Completion Summary

Completed or substantially implemented:

- [x] `--pid`, `--pid-tree`, `--container`, `--all-pids` modes
- [x] Default flow/socket filtering path
- [x] Target and ignored port controls
- [x] Process and container ID metadata on events
- [x] Normalized schema v1
- [x] Non-redundant `-output-contract normalized` JSON output
- [x] Legacy compatibility via `-output-contract legacy`
- [x] Explicit truncation and loss fields
- [x] Bounded local queue and basic backpressure modes
- [x] `/healthz`, `/readyz`, and `/metrics`
- [x] VAmPI container validation for complete HTTP JSON output

Not yet complete:

- [ ] Reliable source/destination connection metadata in normalized output
- [ ] True BPF-side multi-chunk large-payload capture
- [x] Juice Shop validation
- [x] crAPI validation
- [x] Large body validation
- [ ] Kafka outage/backpressure validation
- [ ] Disk spool/WAL
- [ ] Load and resilience benchmark harness

## Next Sprint — Sprint 2A: Connection Metadata Hardening

Objective: make `connection` metadata reliable for short-lived and keep-alive HTTP sockets.

Deliverables:

- [ ] Validate `accept`/`accept4` socket lifecycle events after BPF regeneration.
- [ ] Ensure agent caches connection metadata by `(pid, fd, generation)` at socket creation time.
- [ ] Populate normalized `connection.src_ip`, `connection.src_port`, `connection.dst_ip`, `connection.dst_port`, `protocol`, `family`, and `role`.
- [ ] Add debug logs/metrics for socket metadata events, cache hits, and cache misses.
- [ ] Add integration validation for VAmPI `Connection: close` and keep-alive requests.
- [ ] Add fallback handling for client/outbound flows using `connect` lifecycle events.

Acceptance Criteria:

- [ ] VAmPI normalized output contains non-empty connection metadata.
- [ ] Keep-alive requests retain correct connection metadata across multiple conversations.
- [ ] Short-lived `Connection: close` sockets do not produce empty `connection` objects.

## Next Sprint — Sprint 2B: Multi-Target Validation

Objective: prove target-agnostic behavior beyond VAmPI.

Deliverables:

- [ ] Add reproducible validation commands for OWASP Juice Shop.
- [ ] Add reproducible validation commands for crAPI.
- [ ] Add validation target for nginx/httpbin.
- [ ] Add validation target for FastAPI/Gunicorn process-tree behavior.
- [ ] Capture examples for GET, POST, JSON request body, JSON response body, and error responses.

Acceptance Criteria:

- [ ] VAmPI, Juice Shop, and crAPI all emit complete normalized endpoint JSON without per-app code changes.
- [ ] Container mode works for all validation targets.
- [ ] PID-tree mode works for multiprocess targets.

## Next Sprint — Sprint 3A: True Large Payload Completeness

Objective: eliminate the current fixed single-event payload ceiling for normal configured body limits.

Deliverables:

- [ ] Implement verifier-safe BPF chunk emission for large `read`, `write`, `recvfrom`, and `sendto` buffers.
- [ ] Improve `readv`/`writev` multi-segment capture beyond current segment cap where verifier-safe.
- [ ] Preserve original syscall length, chunk index, chunk count, and sequence order.
- [ ] Worker tests for request and response bodies larger than 4096 bytes.
- [ ] Explicit policy truncation when configured max body/stream limits are exceeded.

Acceptance Criteria:

- [ ] Request bodies larger than 4096 bytes reconstruct completely under configured limits.
- [ ] Response bodies larger than 4096 bytes reconstruct completely under configured limits.
- [ ] Any truncation is explicit in `loss`, never silent.

## Next Sprint — Sprint 3B: Resilience Validation and Disk Spool

Objective: make downstream pressure behavior production-grade.

Deliverables:

- [ ] Kafka outage test plan and automated script.
- [ ] Disk spool/WAL for production mode.
- [ ] Kafka circuit breaker with recovery behavior.
- [ ] Metrics for spool depth, spool bytes, replay count, and replay failures.
- [ ] Load tests with small/high-RPS and large-body scenarios.

Acceptance Criteria:

- [ ] Kafka outage does not crash the agent or target application.
- [ ] Event loss is explicit and counted if configured limits are exceeded.
- [ ] Agent recovers and resumes publishing when Kafka returns.

Explicitly still out of scope until the above are complete:

- OpenSSL TLS capture
- Go TLS capture
- Analyzer adapter
- Proxy deprecation

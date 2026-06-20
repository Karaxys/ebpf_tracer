# TLS Plaintext Capture Plan

Karaxys syscall capture can reconstruct plaintext HTTP only when the application
writes plaintext bytes to the kernel. Once an application uses TLS, syscall
tracepoints usually see encrypted TLS records, not HTTP. Plaintext TLS capture
therefore requires user-space probes on crypto library functions before bytes
are encrypted or after bytes are decrypted.

## Current Status

- Syscall capture remains the default production path for plaintext HTTP.
- TLS plaintext capture is not enabled in the running agent.
- `bpf/tls_plaintext_prototype.bpf.c` documents the first uprobe event contract
  for OpenSSL/BoringSSL-style `SSL_read` and `SSL_write` capture.
- Go `crypto/tls` capture is treated as a separate research path because Go
  binaries are commonly statically linked and do not expose a stable C ABI.

## OpenSSL and BoringSSL Model

The production implementation should attach uprobes and uretprobes to:

- `SSL_write(SSL *ssl, const void *buf, int num)`
- `SSL_read(SSL *ssl, void *buf, int num)`

Recommended behavior:

- On function entry, store `(pid, tid, ssl pointer, buffer pointer, requested length, direction)`.
- On return, read only `ret` bytes when `ret > 0`.
- Cap bytes by the same remote `max_payload_size` policy used for syscall capture.
- Emit a TLS plaintext event keyed by `(pid, tid, ssl pointer)` plus sequence and chunk metadata.
- Join TLS plaintext streams with socket metadata using `SSL_get_fd` if available, or a user-space resolver that maps SSL pointers to file descriptors.

Security constraints:

- Only enable TLS probes for explicit PID, container, or Kubernetes workload targets.
- Keep all-pids TLS capture disabled.
- Keep target and ignored-port filtering active.
- Treat TLS payloads as sensitive and rely on backend redaction before persistence.
- Publish TLS probe metrics separately from syscall metrics so capture gaps are visible.

Operational risks:

- Library symbol names and calling conventions vary by OpenSSL, BoringSSL, LibreSSL, distro, and build flags.
- Static linking may remove dynamic symbols.
- Probe attachment can fail when libraries are stripped or loaded after agent startup.
- High-volume TLS workloads can produce more plaintext bytes than syscall HTTP capture.

## Go TLS Feasibility

Go TLS capture is harder than OpenSSL/BoringSSL capture:

- Go applications frequently statically link `crypto/tls`.
- Function symbols and stack layouts are not a stable public ABI.
- Compiler inlining and register ABI changes can break probe offsets across Go versions.
- Reading Go slice/string internals safely from eBPF requires version-specific care.

Recommended production approach:

- Prefer service-mesh, gateway, SDK, or explicit test-environment plaintext capture for Go TLS services.
- Treat Go TLS uprobes as an opt-in compatibility module with a tested matrix by Go version and architecture.
- Start with lab validation against known Go versions before exposing this as a supported feature.

## Limitations To Document In Product

- eBPF syscall capture cannot decrypt TLS.
- TLS plaintext capture may require elevated host privileges and workload-specific probe compatibility.
- TLS payloads can contain secrets; collection must be explicitly authorized by the project owner.
- Unsupported TLS stacks should degrade to encrypted-traffic metadata, not silent partial HTTP records.
- For production SaaS deployments, users should be told exactly which workloads have plaintext capture enabled.

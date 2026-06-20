// TLS plaintext uprobe prototype.
//
// This file is intentionally not referenced by pkg/bpf/gen.go and is not loaded
// by the production agent. It records the event contract and probe strategy for
// the future OpenSSL/BoringSSL module without changing the validated syscall
// tracer.

#ifdef KARAXYS_TLS_UPROBE_PROTOTYPE

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TLS_MAX_CHUNK_SIZE 4096
#define TLS_DIRECTION_READ 0
#define TLS_DIRECTION_WRITE 1

struct tls_call_ctx {
    __u64 ssl_ptr;
    __u64 buf_ptr;
    __u32 requested;
    __u8 direction;
};

struct tls_plaintext_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    __u64 ssl_ptr;
    __u32 seq;
    __u16 chunk_index;
    __u16 chunk_count;
    __u8 direction;
    __u32 original_size;
    __u32 size;
    char payload[TLS_MAX_CHUNK_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct tls_call_ctx);
} tls_active_calls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} tls_events SEC(".maps");

static __always_inline __u64 tls_tid_key(void)
{
    return bpf_get_current_pid_tgid();
}

static __always_inline int remember_tls_call(const void *ssl, const void *buf, int requested, __u8 direction)
{
    if (!ssl || !buf || requested <= 0) {
        return 0;
    }

    struct tls_call_ctx ctx = {
        .ssl_ptr = (__u64)ssl,
        .buf_ptr = (__u64)buf,
        .requested = (__u32)requested,
        .direction = direction,
    };
    __u64 key = tls_tid_key();
    bpf_map_update_elem(&tls_active_calls, &key, &ctx, BPF_ANY);
    return 0;
}

static __always_inline int emit_tls_return_event(int ret)
{
    __u64 key = tls_tid_key();
    struct tls_call_ctx *ctx = bpf_map_lookup_elem(&tls_active_calls, &key);
    if (!ctx) {
        return 0;
    }
    bpf_map_delete_elem(&tls_active_calls, &key);

    if (ret <= 0) {
        return 0;
    }

    __u32 captured = ret > TLS_MAX_CHUNK_SIZE ? TLS_MAX_CHUNK_SIZE : (__u32)ret;
    struct tls_plaintext_event *event = bpf_ringbuf_reserve(&tls_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid_tgid >> 32;
    event->tid = (__u32)pid_tgid;
    event->ssl_ptr = ctx->ssl_ptr;
    event->seq = 0;
    event->chunk_index = 0;
    event->chunk_count = ret > TLS_MAX_CHUNK_SIZE ? 2 : 1;
    event->direction = ctx->direction;
    event->original_size = (__u32)ret;
    event->size = captured;
    bpf_probe_read_user(event->payload, captured, (const void *)ctx->buf_ptr);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("uprobe/SSL_write")
int karaxys_ssl_write_entry(struct pt_regs *ctx)
{
    return remember_tls_call((const void *)PT_REGS_PARM1(ctx), (const void *)PT_REGS_PARM2(ctx), (int)PT_REGS_PARM3(ctx), TLS_DIRECTION_WRITE);
}

SEC("uretprobe/SSL_write")
int karaxys_ssl_write_return(struct pt_regs *ctx)
{
    return emit_tls_return_event((int)PT_REGS_RC(ctx));
}

SEC("uprobe/SSL_read")
int karaxys_ssl_read_entry(struct pt_regs *ctx)
{
    return remember_tls_call((const void *)PT_REGS_PARM1(ctx), (const void *)PT_REGS_PARM2(ctx), (int)PT_REGS_PARM3(ctx), TLS_DIRECTION_READ);
}

SEC("uretprobe/SSL_read")
int karaxys_ssl_read_return(struct pt_regs *ctx)
{
    return emit_tls_return_event((int)PT_REGS_RC(ctx));
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#endif

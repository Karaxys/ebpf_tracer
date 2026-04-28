//go:build ignore

#include "headers/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_PAYLOAD_SIZE 4096
#define DIR_READ 0
#define DIR_WRITE 1
#define MAX_IOVEC_SEGMENTS 6
#define EVENT_DATA 0
#define EVENT_CLOSE 1
#define DROP_METRIC_MAX 8

enum drop_metric_idx {
    DROP_RINGBUF_RESERVE = 0,
    DROP_COPY_WRITE = 1,
    DROP_COPY_READ = 2,
    DROP_IOV_READ = 3,
    DROP_MISSING_CONTEXT = 4,
    DROP_NOISE = 5,
};

struct api_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    __u32 fd;
    __u32 generation;
    __u32 seq;
    __u32 size;
    __u16 chunk_index;
    __u16 chunk_count;
    __u8 direction;
    __u8 event_type;
    __u8 flags;
    __u8 _pad;
    __u8 payload[MAX_PAYLOAD_SIZE];
};

struct read_context {
    __u32 fd;
    __u32 generation;
    __u32 iovcnt;
    __u8 is_iov;
    __u8 _pad0[3];
    __u64 buf_addr;
    __u32 buf_len;
    __u32 _pad1;
    __u64 iov_addr;
};

struct user_iovec {
    __u64 iov_base;
    __u64 iov_len;
};

struct sys_enter_ctx {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    __s64 id;
    __u64 args[6];
};

struct sys_exit_ctx {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    __s64 id;
    __s64 ret;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} target_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct read_context);
} active_reads SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, __u32);
} fd_generations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, __u32);
} event_seqnos SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, DROP_METRIC_MAX);
    __type(key, __u32);
    __type(value, __u64);
} drop_metrics SEC(".maps");

static __always_inline bool should_trace(__u32 pid) {
    __u8 *is_target = bpf_map_lookup_elem(&target_pids, &pid);
    if (is_target && *is_target == 1) {
        return true;
    }
    return false;
}

static __always_inline void inc_drop(__u32 idx) {
    if (idx >= DROP_METRIC_MAX) {
        return;
    }

    __u64 *counter = bpf_map_lookup_elem(&drop_metrics, &idx);
    if (!counter) {
        return;
    }

    __sync_fetch_and_add(counter, 1);
}

static __always_inline bool is_noise_counter(const struct api_event *event) {
    if (event->size != 8) {
        return false;
    }

    if (!(event->payload[0] == 1 || event->payload[0] == 2)) {
        return false;
    }

    return event->payload[1] == 0 && event->payload[2] == 0 &&
           event->payload[3] == 0 && event->payload[4] == 0 &&
           event->payload[5] == 0 && event->payload[6] == 0 &&
           event->payload[7] == 0;
}

static __always_inline __u64 fd_key(__u32 pid, __u32 fd) {
    return ((__u64)pid << 32) | fd;
}

static __always_inline __u32 get_or_init_generation(__u32 pid, __u32 fd) {
    __u64 key = fd_key(pid, fd);
    __u32 *existing = bpf_map_lookup_elem(&fd_generations, &key);
    if (existing) {
        return *existing;
    }

    __u32 init = 1;
    bpf_map_update_elem(&fd_generations, &key, &init, BPF_ANY);
    return init;
}

static __always_inline void bump_generation(__u32 pid, __u32 fd, __u32 current_generation) {
    __u64 key = fd_key(pid, fd);
    __u32 next = current_generation + 1;
    bpf_map_update_elem(&fd_generations, &key, &next, BPF_ANY);
    bpf_map_delete_elem(&event_seqnos, &key);
}

static __always_inline __u32 next_seq(__u32 pid, __u32 fd) {
    __u64 key = fd_key(pid, fd);
    __u32 *existing = bpf_map_lookup_elem(&event_seqnos, &key);
    if (existing) {
        __u32 seq = *existing;
        __u32 next = seq + 1;
        bpf_map_update_elem(&event_seqnos, &key, &next, BPF_ANY);
        return seq;
    }

    __u32 init = 1;
    bpf_map_update_elem(&event_seqnos, &key, &init, BPF_ANY);
    return 0;
}

static __always_inline int emit_data_event(__u64 id,
                                           __u32 pid,
                                           __u32 fd,
                                           __u32 generation,
                                           __u8 direction,
                                           const char *buf,
                                           __u32 count,
                                           __u16 chunk_index,
                                           __u16 chunk_count) {
    if (!buf || count == 0) {
        return 0;
    }

    __u32 final_size = count < MAX_PAYLOAD_SIZE ? count : MAX_PAYLOAD_SIZE;

    struct api_event *event = bpf_ringbuf_reserve(&events, sizeof(struct api_event), 0);
    if (!event) {
        inc_drop(DROP_RINGBUF_RESERVE);
        return 0;
    }

    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = (__u32)id;
    event->fd = fd;
    event->generation = generation;
    event->seq = next_seq(pid, fd);
    event->size = final_size;
    event->chunk_index = chunk_index;
    event->chunk_count = chunk_count;
    event->direction = direction;
    event->event_type = EVENT_DATA;
    event->flags = 0;

    if (bpf_probe_read_user(&event->payload, event->size, buf) < 0) {
        if (direction == DIR_WRITE) {
            inc_drop(DROP_COPY_WRITE);
        } else {
            inc_drop(DROP_COPY_READ);
        }
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    if (is_noise_counter(event)) {
        inc_drop(DROP_NOISE);
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    bpf_ringbuf_submit(event, 0);
    return final_size;
}

static __always_inline int emit_write_event(__u64 id, __u32 pid, __u32 fd, __u32 generation, const char *buf, size_t count) {
    return emit_data_event(id, pid, fd, generation, DIR_WRITE, buf, (__u32)count, 0, 1);
}

static __always_inline int read_iovec_entry(__u64 iov_addr, __u32 index, struct user_iovec *iov) {
    if (!iov_addr || !iov || index >= MAX_IOVEC_SEGMENTS) {
        return -1;
    }

    __u64 entry_addr = iov_addr + ((__u64)index * sizeof(struct user_iovec));
    if (bpf_probe_read_user(iov, sizeof(*iov), (const void *)entry_addr) < 0) {
        inc_drop(DROP_IOV_READ);
        return -1;
    }

    if (iov->iov_base == 0 || iov->iov_len == 0) {
        return -1;
    }

    return 0;
}

static __always_inline int emit_writev_events(__u64 id,
                                              __u32 pid,
                                              __u32 fd,
                                              __u32 generation,
                                              __u64 iov_addr,
                                              __u32 iovcnt) {
    __u32 capped = iovcnt > MAX_IOVEC_SEGMENTS ? MAX_IOVEC_SEGMENTS : iovcnt;
    if (capped == 0) {
        return 0;
    }

    __u16 chunk_count = 0;
#pragma unroll
    for (int i = 0; i < MAX_IOVEC_SEGMENTS; i++) {
        if ((__u32)i >= capped) {
            break;
        }

        struct user_iovec iov = {};
        if (read_iovec_entry(iov_addr, i, &iov) < 0) {
            continue;
        }

        chunk_count++;
    }

    if (chunk_count == 0) {
        return 0;
    }

    __u16 chunk_index = 0;
#pragma unroll
    for (int i = 0; i < MAX_IOVEC_SEGMENTS; i++) {
        if ((__u32)i >= capped) {
            break;
        }

        struct user_iovec iov = {};
        if (read_iovec_entry(iov_addr, i, &iov) < 0) {
            continue;
        }

        emit_data_event(id,
                        pid,
                        fd,
                        generation,
                        DIR_WRITE,
                        (const char *)iov.iov_base,
                        (__u32)iov.iov_len,
                        chunk_index,
                        chunk_count);
        chunk_index++;
    }

    return 0;
}

static __always_inline int emit_close_event(__u64 id, __u32 pid, __u32 fd, __u32 generation) {
    struct api_event *event = bpf_ringbuf_reserve(&events, sizeof(struct api_event), 0);
    if (!event) {
        inc_drop(DROP_RINGBUF_RESERVE);
        return 0;
    }

    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = (__u32)id;
    event->fd = fd;
    event->generation = generation;
    event->seq = next_seq(pid, fd);
    event->size = 0;
    event->chunk_index = 0;
    event->chunk_count = 0;
    event->direction = DIR_WRITE;
    event->event_type = EVENT_CLOSE;
    event->flags = 0;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

static __always_inline int remember_read_context(__u64 id,
                                                 __u32 fd,
                                                 __u32 generation,
                                                 __u64 buf_addr,
                                                 __u32 buf_len,
                                                 __u64 iov_addr,
                                                 __u32 iovcnt,
                                                 __u8 is_iov) {
    struct read_context read_ctx = {};
    read_ctx.fd = fd;
    read_ctx.generation = generation;
    read_ctx.iovcnt = iovcnt;
    read_ctx.is_iov = is_iov;
    read_ctx.buf_addr = buf_addr;
    read_ctx.buf_len = buf_len;
    read_ctx.iov_addr = iov_addr;
    bpf_map_update_elem(&active_reads, &id, &read_ctx, BPF_ANY);
    return 0;
}

static __always_inline int emit_readv_events(__u64 id, __u32 pid, struct read_context *read_ctx, __u32 total_read) {
    __u32 capped = read_ctx->iovcnt > MAX_IOVEC_SEGMENTS ? MAX_IOVEC_SEGMENTS : read_ctx->iovcnt;
    if (capped == 0 || !read_ctx->iov_addr) {
        return 0;
    }

    __u64 remaining = total_read;
    __u16 chunk_count = 0;

#pragma unroll
    for (int i = 0; i < MAX_IOVEC_SEGMENTS; i++) {
        if ((__u32)i >= capped || remaining == 0) {
            break;
        }

        struct user_iovec iov = {};
        if (read_iovec_entry(read_ctx->iov_addr, i, &iov) < 0) {
            continue;
        }

        __u32 seg_len = iov.iov_len > remaining ? (__u32)remaining : (__u32)iov.iov_len;
        if (seg_len == 0) {
            continue;
        }

        chunk_count++;
        remaining -= seg_len;
    }

    if (chunk_count == 0) {
        return 0;
    }

    remaining = total_read;
    __u16 chunk_index = 0;

#pragma unroll
    for (int i = 0; i < MAX_IOVEC_SEGMENTS; i++) {
        if ((__u32)i >= capped || remaining == 0) {
            break;
        }

        struct user_iovec iov = {};
        if (read_iovec_entry(read_ctx->iov_addr, i, &iov) < 0) {
            continue;
        }

        __u32 seg_len = iov.iov_len > remaining ? (__u32)remaining : (__u32)iov.iov_len;
        if (seg_len == 0) {
            continue;
        }

        emit_data_event(id,
                        pid,
                        read_ctx->fd,
                        read_ctx->generation,
                        DIR_READ,
                        (const char *)iov.iov_base,
                        seg_len,
                        chunk_index,
                        chunk_count);
        chunk_index++;
        remaining -= seg_len;
    }

    return 0;
}

static __always_inline int emit_read_event(__u64 id, __u32 pid, long ret) {
    struct read_context *read_ctx = bpf_map_lookup_elem(&active_reads, &id);
    if (!read_ctx) {
        inc_drop(DROP_MISSING_CONTEXT);
        return 0;
    }

    if (ret <= 0) {
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }

    __u32 total_read = (__u32)ret;

    if (!read_ctx->is_iov) {
        __u32 max_copy = total_read;
        if (max_copy > MAX_PAYLOAD_SIZE) {
            max_copy = MAX_PAYLOAD_SIZE;
        }
        if (read_ctx->buf_len > 0 && max_copy > read_ctx->buf_len) {
            max_copy = read_ctx->buf_len;
        }

        emit_data_event(id,
                        pid,
                        read_ctx->fd,
                        read_ctx->generation,
                        DIR_READ,
                        (const char *)read_ctx->buf_addr,
                        max_copy,
                        0,
                        1);
    } else {
        emit_readv_events(id, pid, read_ctx, total_read);
    }

    bpf_map_delete_elem(&active_reads, &id);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_enter_write(void *ctx_void) {
    struct sys_enter_ctx *ctx = ctx_void;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    if (!should_trace(pid)) {
        return 0;
    }

    __u32 fd = (__u32)ctx->args[0];
    __u32 generation = get_or_init_generation(pid, fd);
    return emit_write_event(id, pid, fd, generation, (const char *)ctx->args[1], (size_t)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_writev")
int trace_sys_enter_writev(void *ctx_void) {
    struct sys_enter_ctx *ctx = ctx_void;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    if (!should_trace(pid)) {
        return 0;
    }

    __u64 iov_addr = (__u64)ctx->args[1];
    int iovcnt = (int)ctx->args[2];
    if (iovcnt <= 0) {
        return 0;
    }

    __u32 fd = (__u32)ctx->args[0];
    __u32 generation = get_or_init_generation(pid, fd);
    __u32 capped_iovcnt = iovcnt > MAX_IOVEC_SEGMENTS ? MAX_IOVEC_SEGMENTS : iovcnt;
    return emit_writev_events(id, pid, fd, generation, iov_addr, capped_iovcnt);
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sys_enter_sendto(void *ctx_void) {
    struct sys_enter_ctx *ctx = ctx_void;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    if (!should_trace(pid)) {
        return 0;
    }

    __u32 fd = (__u32)ctx->args[0];
    __u32 generation = get_or_init_generation(pid, fd);
    return emit_write_event(id, pid, fd, generation, (const char *)ctx->args[1], (size_t)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_sys_enter_read(void *ctx_void) {
    struct sys_enter_ctx *ctx = ctx_void;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    if (!should_trace(pid)) {
        return 0;
    }

    __u32 fd = (__u32)ctx->args[0];
    __u32 generation = get_or_init_generation(pid, fd);
    __u32 count = (__u32)ctx->args[2];
    return remember_read_context(id, fd, generation, (__u64)ctx->args[1], count, 0, 0, 0);
}

SEC("tracepoint/syscalls/sys_enter_readv")
int trace_sys_enter_readv(void *ctx_void) {
    struct sys_enter_ctx *ctx = ctx_void;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    if (!should_trace(pid)) {
        return 0;
    }

    __u64 iov_addr = (__u64)ctx->args[1];
    int iovcnt = (int)ctx->args[2];
    if (iovcnt <= 0) {
        return 0;
    }

    __u32 fd = (__u32)ctx->args[0];
    __u32 generation = get_or_init_generation(pid, fd);
    __u32 capped_iovcnt = iovcnt > MAX_IOVEC_SEGMENTS ? MAX_IOVEC_SEGMENTS : iovcnt;
    return remember_read_context(id, fd, generation, 0, 0, iov_addr, capped_iovcnt, 1);
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_sys_enter_recvfrom(void *ctx_void) {
    struct sys_enter_ctx *ctx = ctx_void;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    if (!should_trace(pid)) {
        return 0;
    }

    __u32 fd = (__u32)ctx->args[0];
    __u32 generation = get_or_init_generation(pid, fd);
    __u32 len = (__u32)ctx->args[2];
    return remember_read_context(id, fd, generation, (__u64)ctx->args[1], len, 0, 0, 0);
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_sys_enter_close(void *ctx_void) {
    struct sys_enter_ctx *ctx = ctx_void;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    if (!should_trace(pid)) {
        return 0;
    }

    __u32 fd = (__u32)ctx->args[0];
    if (fd <= 2) {
        return 0;
    }

    __u32 generation = get_or_init_generation(pid, fd);
    emit_close_event(id, pid, fd, generation);
    bump_generation(pid, fd, generation);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_sys_exit_read(void *ctx_void) {
    struct sys_exit_ctx *ctx = ctx_void;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    if (!should_trace(pid)) {
        return 0;
    }

    return emit_read_event(id, pid, ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_readv")
int trace_sys_exit_readv(void *ctx_void) {
    struct sys_exit_ctx *ctx = ctx_void;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    if (!should_trace(pid)) {
        return 0;
    }

    return emit_read_event(id, pid, ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int trace_sys_exit_recvfrom(void *ctx_void) {
    struct sys_exit_ctx *ctx = ctx_void;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    if (!should_trace(pid)) {
        return 0;
    }

    return emit_read_event(id, pid, ctx->ret);
}

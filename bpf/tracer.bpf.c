//go:build ignore

#include "headers/vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_PAYLOAD_SIZE 4096
#define MAX_PAYLOAD_CHUNKS 4
#define MAX_TOTAL_CAPTURE_SIZE (MAX_PAYLOAD_SIZE * MAX_PAYLOAD_CHUNKS)
#define DIR_READ 0
#define DIR_WRITE 1
#define MAX_IOVEC_SEGMENTS 6
#define EVENT_DATA 0
#define EVENT_CLOSE 1
#define EVENT_SOCKET 2
#define DROP_METRIC_MAX 10
#define CONFIG_KEY_MAX_PAYLOAD_SIZE 0
#define CONFIG_KEY_CAPTURE_READS 1
#define CONFIG_KEY_CAPTURE_WRITES 2
#define CONFIG_KEY_CAPTURE_STDIO 3
#define CONFIG_KEY_TARGET_PORTS_ENABLED 4
#define CONFIG_KEY_CGROUP_FILTER_ENABLED 5
#define CAPTURE_CONFIG_MAX 6
#define AF_INET 2
#define AF_INET6 10
#define SOCKET_ROLE_UNKNOWN 0
#define SOCKET_ROLE_INBOUND 1
#define SOCKET_ROLE_OUTBOUND 2
#define SOCKET_TUPLE_LOCAL 1
#define SOCKET_TUPLE_REMOTE 2
#define TCP_PROTO 6

enum drop_metric_idx {
    DROP_RINGBUF_RESERVE = 0,
    DROP_COPY_WRITE = 1,
    DROP_COPY_READ = 2,
    DROP_IOV_READ = 3,
    DROP_MISSING_CONTEXT = 4,
    DROP_NOISE = 5,
    DROP_FD_FILTER = 6,
    DROP_DIRECTION_FILTER = 7,
    DROP_PORT_FILTER = 8,
    DROP_CGROUP_FILTER = 9,
};

struct api_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    __u32 fd;
    __u32 generation;
    __u32 seq;
    __u32 size;
    __u32 original_size;
    __u16 chunk_index;
    __u16 chunk_count;
    __u8 direction;
    __u8 event_type;
    __u8 flags;
    __u8 _pad;
    __u16 local_port;
    __u16 remote_port;
    __u8 socket_family;
    __u8 socket_role;
    __u8 socket_tuple_flags;
    __u8 _pad2;
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

struct socket_key {
    __u32 pid;
    __u32 fd;
    __u32 generation;
};

struct socket_tuple {
    __u16 family;
    __u16 local_port;
    __u16 remote_port;
    __u8 role;
    __u8 flags;
};

struct accept_context {
    __u32 listener_fd;
    __u32 listener_generation;
    __u64 sockaddr_addr;
};

struct sockaddr_in_probe {
    __u16 sin_family;
    __be16 sin_port;
    __u32 sin_addr;
};

struct sockaddr_in6_probe {
    __u16 sin6_family;
    __be16 sin6_port;
    __u32 sin6_flowinfo;
    __u8 sin6_addr[16];
    __u32 sin6_scope_id;
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
    __uint(max_entries, 65536);
    __type(key, struct socket_key);
    __type(value, struct socket_tuple);
} socket_tuples SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct accept_context);
} active_accepts SEC(".maps");

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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CAPTURE_CONFIG_MAX);
    __type(key, __u32);
    __type(value, __u32);
} capture_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, __u8);
} target_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, __u8);
} ignored_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u8);
} allowed_cgroups SEC(".maps");

static __always_inline void inc_drop(__u32 idx);
static __always_inline __u32 config_value(__u32 key, __u32 fallback);

static __always_inline bool should_trace(__u32 pid) {
    __u8 *is_target = bpf_map_lookup_elem(&target_pids, &pid);
    if (!is_target || *is_target != 1) {
        return false;
    }

    if (config_value(CONFIG_KEY_CGROUP_FILTER_ENABLED, 0) == 1) {
        __u64 cgroup_id = bpf_get_current_cgroup_id();
        __u8 *is_allowed = bpf_map_lookup_elem(&allowed_cgroups, &cgroup_id);
        if (!is_allowed || *is_allowed != 1) {
            inc_drop(DROP_CGROUP_FILTER);
            return false;
        }
    }

    return true;
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

static __always_inline __u32 config_value(__u32 key, __u32 fallback) {
    __u32 *value = bpf_map_lookup_elem(&capture_config, &key);
    if (!value) {
        return fallback;
    }
    return *value;
}

static __always_inline __u32 effective_max_payload_size() {
    __u32 max_payload = config_value(CONFIG_KEY_MAX_PAYLOAD_SIZE, MAX_PAYLOAD_SIZE);
    if (max_payload == 0 || max_payload > MAX_TOTAL_CAPTURE_SIZE) {
        return MAX_TOTAL_CAPTURE_SIZE;
    }
    return max_payload;
}

static __always_inline bool direction_enabled(__u8 direction) {
    if (direction == DIR_READ) {
        return config_value(CONFIG_KEY_CAPTURE_READS, 1) == 1;
    }
    if (direction == DIR_WRITE) {
        return config_value(CONFIG_KEY_CAPTURE_WRITES, 1) == 1;
    }
    return true;
}

static __always_inline bool should_capture_fd(__s64 fd_raw) {
    if (fd_raw > 2) {
        return true;
    }

    if (config_value(CONFIG_KEY_CAPTURE_STDIO, 0) == 1) {
        return true;
    }

    inc_drop(DROP_FD_FILTER);
    return false;
}

static __always_inline struct socket_key make_socket_key(__u32 pid, __u32 fd, __u32 generation) {
    struct socket_key key = {};
    key.pid = pid;
    key.fd = fd;
    key.generation = generation;
    return key;
}

static __always_inline int read_sockaddr_port(__u64 sockaddr_addr, __u16 *family, __u16 *port) {
    if (!sockaddr_addr || !family || !port) {
        return -1;
    }

    __u16 addr_family = 0;
    if (bpf_probe_read_user(&addr_family, sizeof(addr_family), (const void *)sockaddr_addr) < 0) {
        return -1;
    }

    if (addr_family == AF_INET) {
        struct sockaddr_in_probe addr = {};
        if (bpf_probe_read_user(&addr, sizeof(addr), (const void *)sockaddr_addr) < 0) {
            return -1;
        }
        *family = AF_INET;
        *port = bpf_ntohs(addr.sin_port);
        return 0;
    }

    if (addr_family == AF_INET6) {
        struct sockaddr_in6_probe addr6 = {};
        if (bpf_probe_read_user(&addr6, sizeof(addr6), (const void *)sockaddr_addr) < 0) {
            return -1;
        }
        *family = AF_INET6;
        *port = bpf_ntohs(addr6.sin6_port);
        return 0;
    }

    return -1;
}

static __always_inline bool target_port_match(__u16 port) {
    if (port == 0) {
        return false;
    }
    __u8 *exists = bpf_map_lookup_elem(&target_ports, &port);
    return exists && *exists == 1;
}

static __always_inline bool ignored_port_match(__u16 port) {
    if (port == 0) {
        return false;
    }
    __u8 *exists = bpf_map_lookup_elem(&ignored_ports, &port);
    return exists && *exists == 1;
}

static __always_inline bool tuple_has_target_port(const struct socket_tuple *tuple) {
    if (!tuple) {
        return false;
    }
    if ((tuple->flags & SOCKET_TUPLE_LOCAL) && target_port_match(tuple->local_port)) {
        return true;
    }
    if ((tuple->flags & SOCKET_TUPLE_REMOTE) && target_port_match(tuple->remote_port)) {
        return true;
    }
    return false;
}

static __always_inline bool tuple_has_both_ports(const struct socket_tuple *tuple) {
    if (!tuple) {
        return false;
    }
    return (tuple->flags & SOCKET_TUPLE_LOCAL) && (tuple->flags & SOCKET_TUPLE_REMOTE);
}

static __always_inline bool tuple_has_ignored_port(const struct socket_tuple *tuple) {
    if (!tuple) {
        return false;
    }
    if ((tuple->flags & SOCKET_TUPLE_LOCAL) && ignored_port_match(tuple->local_port)) {
        return true;
    }
    if ((tuple->flags & SOCKET_TUPLE_REMOTE) && ignored_port_match(tuple->remote_port)) {
        return true;
    }
    return false;
}

static __always_inline bool socket_tuple_allowed(__u32 pid, __u32 fd, __u32 generation) {
    struct socket_key key = make_socket_key(pid, fd, generation);
    struct socket_tuple *tuple = bpf_map_lookup_elem(&socket_tuples, &key);
    if (!tuple) {
        return true;
    }

    if (tuple_has_ignored_port(tuple)) {
        inc_drop(DROP_PORT_FILTER);
        return false;
    }

    if (config_value(CONFIG_KEY_TARGET_PORTS_ENABLED, 0) == 1 &&
        tuple_has_both_ports(tuple) &&
        !tuple_has_target_port(tuple)) {
        inc_drop(DROP_PORT_FILTER);
        return false;
    }

    return true;
}

static __always_inline void update_socket_tuple(__u32 pid,
                                                __u32 fd,
                                                __u32 generation,
                                                __u16 family,
                                                __u16 local_port,
                                                __u16 remote_port,
                                                __u8 role,
                                                __u8 flags) {
    struct socket_key key = make_socket_key(pid, fd, generation);
    struct socket_tuple tuple = {};
    struct socket_tuple *existing = bpf_map_lookup_elem(&socket_tuples, &key);
    if (existing) {
        tuple = *existing;
    }

    if (family == AF_INET || family == AF_INET6) {
        tuple.family = family;
    }
    if (flags & SOCKET_TUPLE_LOCAL) {
        tuple.local_port = local_port;
        tuple.flags |= SOCKET_TUPLE_LOCAL;
    }
    if (flags & SOCKET_TUPLE_REMOTE) {
        tuple.remote_port = remote_port;
        tuple.flags |= SOCKET_TUPLE_REMOTE;
    }
    if (role != SOCKET_ROLE_UNKNOWN) {
        tuple.role = role;
    }

    bpf_map_update_elem(&socket_tuples, &key, &tuple, BPF_ANY);
}

static __always_inline void delete_socket_tuple(__u32 pid, __u32 fd, __u32 generation) {
    struct socket_key key = make_socket_key(pid, fd, generation);
    bpf_map_delete_elem(&socket_tuples, &key);
}

static __always_inline void fill_event_socket_metadata(struct api_event *event,
                                                       __u32 pid,
                                                       __u32 fd,
                                                       __u32 generation) {
    event->local_port = 0;
    event->remote_port = 0;
    event->socket_family = 0;
    event->socket_role = SOCKET_ROLE_UNKNOWN;
    event->socket_tuple_flags = 0;
    event->_pad2 = 0;

    struct socket_key key = make_socket_key(pid, fd, generation);
    struct socket_tuple *tuple = bpf_map_lookup_elem(&socket_tuples, &key);
    if (!tuple) {
        return;
    }

    event->local_port = tuple->local_port;
    event->remote_port = tuple->remote_port;
    if (tuple->family == AF_INET) {
        event->socket_family = 4;
    } else if (tuple->family == AF_INET6) {
        event->socket_family = 6;
    }
    event->socket_role = tuple->role;
    event->socket_tuple_flags = tuple->flags;
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

static __always_inline int emit_data_chunk(__u64 id,
                                           __u32 pid,
                                           __u32 fd,
                                           __u32 generation,
                                           __u8 direction,
                                           const char *buf,
                                           __u32 chunk_size,
                                           __u32 original_size,
                                           __u16 chunk_index,
                                           __u16 chunk_count) {
    if (!direction_enabled(direction)) {
        inc_drop(DROP_DIRECTION_FILTER);
        return 0;
    }

    if (!buf || chunk_size == 0) {
        return 0;
    }

    if (!socket_tuple_allowed(pid, fd, generation)) {
        return 0;
    }

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
    event->size = chunk_size;
    event->original_size = original_size;
    event->chunk_index = chunk_index;
    event->chunk_count = chunk_count;
    event->direction = direction;
    event->event_type = EVENT_DATA;
    event->flags = 0;
    fill_event_socket_metadata(event, pid, fd, generation);

    if (bpf_probe_read_user(&event->payload, chunk_size, buf) < 0) {
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
    return chunk_size;
}

static __always_inline int emit_data_event(__u64 id,
                                           __u32 pid,
                                           __u32 fd,
                                           __u32 generation,
                                           __u8 direction,
                                           const char *buf,
                                           __u32 count,
                                           __u32 original_size,
                                           __u16 chunk_index,
                                           __u16 chunk_count) {
    if (!buf || count == 0) {
        return 0;
    }

    __u32 max_payload = effective_max_payload_size();
    __u32 capture_size = count < max_payload ? count : max_payload;
    __u16 chunks = (capture_size + MAX_PAYLOAD_SIZE - 1) / MAX_PAYLOAD_SIZE;
    if (chunks == 0) {
        return 0;
    }
    if (chunks > MAX_PAYLOAD_CHUNKS) {
        chunks = MAX_PAYLOAD_CHUNKS;
    }

    __u32 emitted = 0;
#pragma unroll
    for (int i = 0; i < MAX_PAYLOAD_CHUNKS; i++) {
        if ((__u16)i >= chunks) {
            break;
        }
        __u32 offset = (__u32)i * MAX_PAYLOAD_SIZE;
        if (offset >= capture_size) {
            break;
        }
        __u32 remaining = capture_size - offset;
        __u32 chunk_size = remaining < MAX_PAYLOAD_SIZE ? remaining : MAX_PAYLOAD_SIZE;
        emitted += emit_data_chunk(id,
                                   pid,
                                   fd,
                                   generation,
                                   direction,
                                   buf + offset,
                                   chunk_size,
                                   original_size,
                                   chunk_index + (__u16)i,
                                   chunk_count > chunks ? chunk_count : chunks);
    }
    return emitted;
}

static __always_inline int emit_write_event(__u64 id, __u32 pid, __u32 fd, __u32 generation, const char *buf, size_t count) {
    return emit_data_event(id, pid, fd, generation, DIR_WRITE, buf, (__u32)count, (__u32)count, 0, 1);
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

static __always_inline int read_msghdr_iov(__u64 msg_addr, __u64 *iov_addr, __u32 *iovcnt) {
    if (!msg_addr || !iov_addr || !iovcnt) {
        return -1;
    }

    struct user_msghdr msg = {};
    if (bpf_probe_read_user(&msg, sizeof(msg), (const void *)msg_addr) < 0) {
        return -1;
    }

    if (!msg.msg_iov || msg.msg_iovlen == 0) {
        return -1;
    }

    __u64 raw_iovcnt = msg.msg_iovlen;
    if (raw_iovcnt > MAX_IOVEC_SEGMENTS) {
        raw_iovcnt = MAX_IOVEC_SEGMENTS;
    }
    if (raw_iovcnt == 0) {
        return -1;
    }

    *iov_addr = (__u64)msg.msg_iov;
    *iovcnt = (__u32)raw_iovcnt;
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

        __u32 chunk_size = (__u32)iov.iov_len;
        if (chunk_size > MAX_PAYLOAD_SIZE) {
            chunk_size = MAX_PAYLOAD_SIZE;
        }
        emit_data_chunk(id,
                        pid,
                        fd,
                        generation,
                        DIR_WRITE,
                        (const char *)iov.iov_base,
                        chunk_size,
                        (__u32)iov.iov_len,
                        chunk_index,
                        chunk_count);
        chunk_index++;
    }

    return 0;
}

static __always_inline int emit_control_event(__u64 id,
                                              __u32 pid,
                                              __u32 fd,
                                              __u32 generation,
                                              __u8 event_type) {
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
    event->original_size = 0;
    event->chunk_index = 0;
    event->chunk_count = 0;
    event->direction = DIR_WRITE;
    event->event_type = event_type;
    event->flags = 0;
    fill_event_socket_metadata(event, pid, fd, generation);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

static __always_inline int emit_close_event(__u64 id, __u32 pid, __u32 fd, __u32 generation) {
    return emit_control_event(id, pid, fd, generation, EVENT_CLOSE);
}

static __always_inline int emit_socket_event(__u64 id, __u32 pid, __u32 fd, __u32 generation) {
    return emit_control_event(id, pid, fd, generation, EVENT_SOCKET);
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

        __u32 chunk_size = seg_len;
        if (chunk_size > MAX_PAYLOAD_SIZE) {
            chunk_size = MAX_PAYLOAD_SIZE;
        }
        emit_data_chunk(id,
                        pid,
                        read_ctx->fd,
                        read_ctx->generation,
                        DIR_READ,
                        (const char *)iov.iov_base,
                        chunk_size,
                        seg_len,
                        chunk_index,
                        chunk_count);
        chunk_index++;
        remaining -= seg_len;
    }

    return 0;
}

static __always_inline int emit_simple_read_event(__u64 id, __u32 pid, long ret) {
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
    __u32 max_copy = total_read;
    if (max_copy > effective_max_payload_size()) {
        max_copy = effective_max_payload_size();
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
                    total_read,
                    0,
                    1);

    bpf_map_delete_elem(&active_reads, &id);
    return 0;
}

static __always_inline int emit_iov_read_event(__u64 id, __u32 pid, long ret) {
    struct read_context *read_ctx = bpf_map_lookup_elem(&active_reads, &id);
    if (!read_ctx) {
        inc_drop(DROP_MISSING_CONTEXT);
        return 0;
    }

    if (ret <= 0) {
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }

    emit_readv_events(id, pid, read_ctx, (__u32)ret);

    bpf_map_delete_elem(&active_reads, &id);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bind")
int trace_sys_enter_bind(void *ctx_void) {
    struct sys_enter_ctx *ctx = ctx_void;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    if (!should_trace(pid)) {
        return 0;
    }

    if (!should_capture_fd((__s64)ctx->args[0])) {
        return 0;
    }

    __u16 family = 0;
    __u16 port = 0;
    if (read_sockaddr_port((__u64)ctx->args[1], &family, &port) < 0) {
        return 0;
    }

    __u32 fd = (__u32)ctx->args[0];
    __u32 generation = get_or_init_generation(pid, fd);
    update_socket_tuple(pid, fd, generation, family, port, 0, SOCKET_ROLE_INBOUND, SOCKET_TUPLE_LOCAL);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_sys_enter_connect(void *ctx_void) {
    struct sys_enter_ctx *ctx = ctx_void;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    if (!should_trace(pid)) {
        return 0;
    }

    if (!should_capture_fd((__s64)ctx->args[0])) {
        return 0;
    }

    __u16 family = 0;
    __u16 port = 0;
    if (read_sockaddr_port((__u64)ctx->args[1], &family, &port) < 0) {
        return 0;
    }

    __u32 fd = (__u32)ctx->args[0];
    __u32 generation = get_or_init_generation(pid, fd);
    update_socket_tuple(pid, fd, generation, family, 0, port, SOCKET_ROLE_OUTBOUND, SOCKET_TUPLE_REMOTE);
    return emit_socket_event(id, pid, fd, generation);
}

static __always_inline int remember_accept_context(__u64 id, __u32 pid, __u32 listener_fd, __u64 sockaddr_addr) {
    struct accept_context accept_ctx = {};
    accept_ctx.listener_fd = listener_fd;
    accept_ctx.listener_generation = get_or_init_generation(pid, listener_fd);
    accept_ctx.sockaddr_addr = sockaddr_addr;
    bpf_map_update_elem(&active_accepts, &id, &accept_ctx, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept")
int trace_sys_enter_accept(void *ctx_void) {
    struct sys_enter_ctx *ctx = ctx_void;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    if (!should_trace(pid)) {
        return 0;
    }

    if (!should_capture_fd((__s64)ctx->args[0])) {
        return 0;
    }

    return remember_accept_context(id, pid, (__u32)ctx->args[0], (__u64)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_sys_enter_accept4(void *ctx_void) {
    struct sys_enter_ctx *ctx = ctx_void;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    if (!should_trace(pid)) {
        return 0;
    }

    if (!should_capture_fd((__s64)ctx->args[0])) {
        return 0;
    }

    return remember_accept_context(id, pid, (__u32)ctx->args[0], (__u64)ctx->args[1]);
}

static __always_inline void promote_accepted_socket(__u64 id, __u32 pid, __u32 accepted_fd, __u32 accepted_generation) {
    struct accept_context *accept_ctx = bpf_map_lookup_elem(&active_accepts, &id);
    if (!accept_ctx) {
        return;
    }

    struct socket_key listener_key = make_socket_key(pid, accept_ctx->listener_fd, accept_ctx->listener_generation);
    struct socket_tuple *listener_tuple = bpf_map_lookup_elem(&socket_tuples, &listener_key);
    if (listener_tuple && (listener_tuple->flags & SOCKET_TUPLE_LOCAL)) {
        update_socket_tuple(pid,
                            accepted_fd,
                            accepted_generation,
                            listener_tuple->family,
                            listener_tuple->local_port,
                            0,
                            SOCKET_ROLE_INBOUND,
                            SOCKET_TUPLE_LOCAL);
    }

    __u16 remote_family = 0;
    __u16 remote_port = 0;
    if (read_sockaddr_port(accept_ctx->sockaddr_addr, &remote_family, &remote_port) == 0) {
        update_socket_tuple(pid,
                            accepted_fd,
                            accepted_generation,
                            remote_family,
                            0,
                            remote_port,
                            SOCKET_ROLE_INBOUND,
                            SOCKET_TUPLE_REMOTE);
    }
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_enter_write(void *ctx_void) {
    struct sys_enter_ctx *ctx = ctx_void;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    if (!should_trace(pid)) {
        return 0;
    }

    if (!direction_enabled(DIR_WRITE)) {
        inc_drop(DROP_DIRECTION_FILTER);
        return 0;
    }

    __u32 fd = (__u32)ctx->args[0];
    if (!should_capture_fd((__s64)ctx->args[0])) {
        return 0;
    }
    __u32 generation = get_or_init_generation(pid, fd);
    if (!socket_tuple_allowed(pid, fd, generation)) {
        return 0;
    }
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

    if (!direction_enabled(DIR_WRITE)) {
        inc_drop(DROP_DIRECTION_FILTER);
        return 0;
    }

    __u64 iov_addr = (__u64)ctx->args[1];
    int iovcnt = (int)ctx->args[2];
    if (iovcnt <= 0) {
        return 0;
    }

    __u32 fd = (__u32)ctx->args[0];
    if (!should_capture_fd((__s64)ctx->args[0])) {
        return 0;
    }
    __u32 generation = get_or_init_generation(pid, fd);
    if (!socket_tuple_allowed(pid, fd, generation)) {
        return 0;
    }
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

    if (!direction_enabled(DIR_WRITE)) {
        inc_drop(DROP_DIRECTION_FILTER);
        return 0;
    }

    __u32 fd = (__u32)ctx->args[0];
    if (!should_capture_fd((__s64)ctx->args[0])) {
        return 0;
    }
    __u32 generation = get_or_init_generation(pid, fd);
    if (!socket_tuple_allowed(pid, fd, generation)) {
        return 0;
    }
    return emit_write_event(id, pid, fd, generation, (const char *)ctx->args[1], (size_t)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_sys_enter_sendmsg(void *ctx_void) {
    struct sys_enter_ctx *ctx = ctx_void;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    if (!should_trace(pid)) {
        return 0;
    }

    if (!direction_enabled(DIR_WRITE)) {
        inc_drop(DROP_DIRECTION_FILTER);
        return 0;
    }

    __u32 fd = (__u32)ctx->args[0];
    if (!should_capture_fd((__s64)ctx->args[0])) {
        return 0;
    }
    __u32 generation = get_or_init_generation(pid, fd);
    if (!socket_tuple_allowed(pid, fd, generation)) {
        return 0;
    }

    __u64 iov_addr = 0;
    __u32 iovcnt = 0;
    if (read_msghdr_iov((__u64)ctx->args[1], &iov_addr, &iovcnt) < 0) {
        return 0;
    }
    return emit_writev_events(id, pid, fd, generation, iov_addr, iovcnt);
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
    if (!should_capture_fd((__s64)ctx->args[0])) {
        return 0;
    }
    if (!direction_enabled(DIR_READ)) {
        inc_drop(DROP_DIRECTION_FILTER);
        return 0;
    }
    __u32 generation = get_or_init_generation(pid, fd);
    if (!socket_tuple_allowed(pid, fd, generation)) {
        return 0;
    }
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
    if (!should_capture_fd((__s64)ctx->args[0])) {
        return 0;
    }
    if (!direction_enabled(DIR_READ)) {
        inc_drop(DROP_DIRECTION_FILTER);
        return 0;
    }
    __u32 generation = get_or_init_generation(pid, fd);
    if (!socket_tuple_allowed(pid, fd, generation)) {
        return 0;
    }
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
    if (!should_capture_fd((__s64)ctx->args[0])) {
        return 0;
    }
    if (!direction_enabled(DIR_READ)) {
        inc_drop(DROP_DIRECTION_FILTER);
        return 0;
    }
    __u32 generation = get_or_init_generation(pid, fd);
    if (!socket_tuple_allowed(pid, fd, generation)) {
        return 0;
    }
    __u32 len = (__u32)ctx->args[2];
    return remember_read_context(id, fd, generation, (__u64)ctx->args[1], len, 0, 0, 0);
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int trace_sys_enter_recvmsg(void *ctx_void) {
    struct sys_enter_ctx *ctx = ctx_void;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    if (!should_trace(pid)) {
        return 0;
    }

    __u32 fd = (__u32)ctx->args[0];
    if (!should_capture_fd((__s64)ctx->args[0])) {
        return 0;
    }
    if (!direction_enabled(DIR_READ)) {
        inc_drop(DROP_DIRECTION_FILTER);
        return 0;
    }
    __u32 generation = get_or_init_generation(pid, fd);
    if (!socket_tuple_allowed(pid, fd, generation)) {
        return 0;
    }

    __u64 iov_addr = 0;
    __u32 iovcnt = 0;
    if (read_msghdr_iov((__u64)ctx->args[1], &iov_addr, &iovcnt) < 0) {
        return 0;
    }
    return remember_read_context(id, fd, generation, 0, 0, iov_addr, iovcnt, 1);
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
    if (!should_capture_fd((__s64)ctx->args[0])) {
        return 0;
    }

    __u32 generation = get_or_init_generation(pid, fd);
    if (socket_tuple_allowed(pid, fd, generation)) {
        emit_close_event(id, pid, fd, generation);
    }
    delete_socket_tuple(pid, fd, generation);
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

    if (!direction_enabled(DIR_READ)) {
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }

    return emit_simple_read_event(id, pid, ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_readv")
int trace_sys_exit_readv(void *ctx_void) {
    struct sys_exit_ctx *ctx = ctx_void;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    if (!should_trace(pid)) {
        return 0;
    }

    if (!direction_enabled(DIR_READ)) {
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }

    return emit_iov_read_event(id, pid, ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int trace_sys_exit_recvfrom(void *ctx_void) {
    struct sys_exit_ctx *ctx = ctx_void;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    if (!should_trace(pid)) {
        return 0;
    }

    if (!direction_enabled(DIR_READ)) {
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }

    return emit_simple_read_event(id, pid, ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_recvmsg")
int trace_sys_exit_recvmsg(void *ctx_void) {
    struct sys_exit_ctx *ctx = ctx_void;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    if (!should_trace(pid)) {
        return 0;
    }

    if (!direction_enabled(DIR_READ)) {
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }

    return emit_iov_read_event(id, pid, ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_accept")
int trace_sys_exit_accept(void *ctx_void) {
    struct sys_exit_ctx *ctx = ctx_void;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    if (!should_trace(pid)) {
        return 0;
    }

    if (ctx->ret < 0) {
        bpf_map_delete_elem(&active_accepts, &id);
        return 0;
    }

    __u32 fd = (__u32)ctx->ret;
    __u32 generation = get_or_init_generation(pid, fd);
    promote_accepted_socket(id, pid, fd, generation);
    bpf_map_delete_elem(&active_accepts, &id);
    return emit_socket_event(id, pid, fd, generation);
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int trace_sys_exit_accept4(void *ctx_void) {
    struct sys_exit_ctx *ctx = ctx_void;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    if (!should_trace(pid)) {
        return 0;
    }

    if (ctx->ret < 0) {
        bpf_map_delete_elem(&active_accepts, &id);
        return 0;
    }

    __u32 fd = (__u32)ctx->ret;
    __u32 generation = get_or_init_generation(pid, fd);
    promote_accepted_socket(id, pid, fd, generation);
    bpf_map_delete_elem(&active_accepts, &id);
    return emit_socket_event(id, pid, fd, generation);
}

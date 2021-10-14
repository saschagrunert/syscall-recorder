#include <vmlinux.h>

#include <asm-generic/errno.h>
#include <bpf/bpf_helpers.h>

#include "syscallrecorder.h"

const volatile pid_t pid = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, struct data_t);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} data SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline void * lookup_or_init(void * map, const u32 key)
{
    void * const value = bpf_map_lookup_elem(map, &key);
    if (value) {
        return value;
    }

    static const struct data_t init;
    int err = bpf_map_update_elem(map, &key, &init, BPF_NOEXIST);
    if (err && err != -EEXIST) {
        return NULL;
    }

    return bpf_map_lookup_elem(map, &key);
}

SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit(struct trace_event_raw_sys_exit * args)
{
    // In case of an interrupt
    if (args->id == -1) {
        return 0;
    }

    // Filter the PID
    if (bpf_get_current_pid_tgid() >> 32 != pid) {
        return 0;
    }

    // Update the data
    struct data_t * value = lookup_or_init(&data, args->id);
    if (value) {
        __sync_fetch_and_add(&value->count, 1);

        if (args->ret == -1) {
            __sync_fetch_and_add(&value->count_failed, 1);
        }
    }

    return 0;
}

SEC("raw_tracepoint/sched_process_exit")
int process_exit(struct bpf_raw_tracepoint_args * args)
{
    if (bpf_get_current_pid_tgid() >> 32 == pid) {
        struct event_t event = {.stop = true};
        return bpf_perf_event_output(args, &events, BPF_F_CURRENT_CPU, &event,
                                     sizeof(event));
    }
    return 0;
}

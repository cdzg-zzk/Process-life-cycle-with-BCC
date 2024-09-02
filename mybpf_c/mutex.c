#include <uapi/linux/ptrace.h>
#include <linux/mutex.h>

BPF_HASH(lock_start, u32, u64);
struct mutex_wait_data_t {
    struct mutex *lock;
    u64 slot;
};
BPF_HISTOGRAM(lock_latency_ns, struct mutex_wait_data_t);
struct mutex_wait_event_t {
    u64 ts;
    u64 duration;
    void *lock;
};
BPF_PERF_OUTPUT(mutex_wait_result);
int trace_mutex_lock(struct pt_regs *ctx, struct mutex *lock)
{
    u32 pid = bpf_get_current_pid_tgid();
    // bpf_trace_printk("mutex wait pid: %d", pid);

    u64 ts = bpf_ktime_get_ns();
    u32 tid = bpf_get_current_pid_tgid() >> 32;
    lock_start.update(&tid, &ts);

    return 0;
}


int trace_mutex_lock_end(struct pt_regs *ctx, struct mutex *lock)
{
    u32 pid = bpf_get_current_pid_tgid();
    u32 tid = bpf_get_current_pid_tgid() >> 32;
    u64 *start_ts = lock_start.lookup(&tid);
    if (start_ts != NULL) {
        u64 curr_ts = bpf_ktime_get_ns();
        u64 duration = curr_ts - *start_ts;
        struct mutex_wait_data_t mutex_wait_data = {};
        mutex_wait_data.lock = lock;
        mutex_wait_data.slot = bpf_log2(duration);
        lock_latency_ns.increment(mutex_wait_data);
        lock_start.delete(&tid);
        struct mutex_wait_event_t event = {};
        event.ts = curr_ts;
        event.duration = duration;
        event.lock = (void*)lock;
        bpf_trace_printk("nihaoya");
        mutex_wait_result.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}

int trace_mutex_lock_interruptible_end(struct pt_regs *ctx, struct mutex *lock, int ret)
{
    u32 pid = bpf_get_current_pid_tgid();
    u32 tid = bpf_get_current_pid_tgid() >> 32;
    if(ret != 0) {
        return 0;
    }
    u64 *start_ts = lock_start.lookup(&tid);
    if (start_ts != NULL && ret == 0) {
        u64 curr_ts = bpf_ktime_get_ns();
        u64 duration = curr_ts - *start_ts;
        struct mutex_wait_data_t mutex_wait_data = {};
        mutex_wait_data.lock = lock;
        mutex_wait_data.slot = bpf_log2(duration);
        lock_latency_ns.increment(mutex_wait_data);
        lock_start.delete(&tid);
        struct mutex_wait_event_t event = {};
        event.ts = curr_ts;
        event.duration = duration;
        // event.lock = lock;
        mutex_wait_result.perf_submit(ctx, &event, sizeof(event));
    }
    return 0;
}
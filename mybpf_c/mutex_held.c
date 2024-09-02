#include <uapi/linux/ptrace.h>
#include <linux/mutex.h>

BPF_HASH(lock_addr, u64, struct mutex *);
BPF_HASH(held_start, struct mutex *, u64);
struct lock_held_data_t {
    struct mutex * mutex_ptr;
    u64 slot;
};
BPF_HISTOGRAM(held_time_ns, struct lock_held_data_t);

struct mutex_held_event_t {
    u64 ts;
    u64 duration;
    void *lock;
};
BPF_PERF_OUTPUT(mutex_held_result);

int mutex_lock_enter(struct pt_regs *ctx, struct mutex *lock)
{
    u64 tid = bpf_get_current_pid_tgid();
    // if(tid < 4000) {
    //     return 0;
    // }
    // bpf_trace_printk("mutex held pid: %d", tid);
    lock_addr.update(&tid, &lock);
    return 0;
}

int mutex_lock_return(struct pt_regs *ctx)
{
    u64 tid = bpf_get_current_pid_tgid();
    struct mutex **lock_ptr = lock_addr.lookup(&tid);
    if (lock_ptr) {
        u64 nsecs = bpf_ktime_get_ns();
        struct mutex * lock_address = *lock_ptr;
        held_start.update(&lock_address, &nsecs);
        lock_addr.delete(&tid);
    }
    return 0;
}

int mutex_trylock_interruptible_return(struct pt_regs *ctx, int retval)
{
    u64 tid = bpf_get_current_pid_tgid();
    struct mutex **lock_ptr = lock_addr.lookup(&tid);
    if (lock_ptr && retval == 0) {
        u64 nsecs = bpf_ktime_get_ns();
        struct mutex * lock_address = *lock_ptr;
        held_start.update(&lock_address, &nsecs);
        lock_addr.delete(&tid);
    }
    return 0;
}

int mutex_exit(struct pt_regs *ctx, struct mutex *lock)
{
    u64 *held_start_ns = held_start.lookup(&lock);
    if (held_start_ns) {
        u64 nsecs = bpf_ktime_get_ns();
        u64 held_time = nsecs - *held_start_ns;
        struct lock_held_data_t lock_held_data = {};
        lock_held_data.mutex_ptr = lock;
        lock_held_data.slot = bpf_log2(held_time);
        held_time_ns.increment(lock_held_data);
        held_start.delete(&lock);
        struct mutex_held_event_t event = {};
        event.ts = nsecs;
        event.duration = held_time;
        event.lock = (void*)lock;
        bpf_trace_printk("send");
        mutex_held_result.perf_submit(ctx, &event, sizeof(event));
        bpf_trace_printk("end");
    }
    return 0;
}
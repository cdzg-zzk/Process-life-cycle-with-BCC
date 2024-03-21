#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#ifdef CPUDIST
typedef struct entry_key {
    u32 pid;
    u32 cpu;
} entry_key_t;

typedef struct pid_key {
    u64 id;
    u64 slot;
} pid_key_t;

BPF_HASH(start, entry_key_t, u64, MAX_PID);
BPF_HISTOGRAM(dist);
BPF_HISTOGRAM(target_dist, pid_key_t, MAX_PID);
static inline void store_start(u32 pid, u32 cpu, u64 ts)
{
    // filter idle process(pid == 0)
    if (IDLE_FILTER)
        return;

    // BUILD_TARGET_PID
    // if(pid != target_pid) {
    //     entry_key_t entry_key = { .pid = pid, .cpu = (pid == 0 ? cpu : 0xFFFFFFFF) };
    //     start.update(&entry_key, &ts);
    // }
    entry_key_t entry_key = { .pid = pid, .cpu = (pid == 0 ? cpu : 0xFFFFFFFF) };
    start.update(&entry_key, &ts);
}

static inline void update_hist(u32 pid, u32 cpu, u64 ts)
{
    // if (PID_FILTER)
    //     return;

    if (IDLE_FILTER)
        return;

    entry_key_t entry_key = { .pid = pid, .cpu = (pid == 0 ? cpu : 0xFFFFFFFF) };
    u64 *tsp = start.lookup(&entry_key);
    if (tsp == 0)
        return;

    if (ts < *tsp) {
        // Probably a clock issue where the recorded on-CPU event had a
        // timestamp later than the recorded off-CPU event, or vice versa.
        return;
    }
    BUILD_TARGET_PID
    u64 delta = ts - *tsp;
    delta /= 1000000;    // mesc
    if (pid == target_pid) {
        pid_key_t key = {.id = pid, .slot = bpf_log2l(delta)};
        target_dist.increment(key);
    }
    dist.atomic_increment(bpf_log2l(delta));
}

int cpu_sched_switch(struct pt_regs *ctx, struct task_struct *prev)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32, pid = pid_tgid;
    u32 cpu = bpf_get_smp_processor_id();

    u32 prev_pid = prev->pid;
    u32 prev_tgid = prev->tgid;
    if (IDLE_FILTER)
        return 0;
    store_start(prev_pid, cpu, ts);


BAIL:
    update_hist(pid, cpu, ts);

    return 0;
}

#endif
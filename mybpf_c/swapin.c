#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

struct key_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};
struct swapin_event_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(swapin_counts, struct key_t, u64);
BPF_PERF_OUTPUT(swapin_result);
int kprobe__swap_readpage(struct pt_regs *ctx)
{
    u64 *val, zero = 0;
    u32 pid = bpf_get_current_pid_tgid();
    struct key_t key = {.pid = pid};
    struct swapin_event_t swapin_event = {.pid = pid};
    swapin_event.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&swapin_event.comm, sizeof(swapin_event.comm));
    // BUILD_TARGET_PID
    // if(pid == target_pid){
    //     swapin_result.perf_submit(ctx, &key, sizeof(key));
    // }
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    val = swapin_counts.lookup_or_init(&key, &zero);
    ++(*val);
    return 0;
}
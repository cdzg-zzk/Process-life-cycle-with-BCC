#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
// 测量一个进程被剥夺CPU时长，也可以加到task_switch中，只需要加一个queue，struct
// (start应该是不需要的， 如果没有delete)

struct key_t {
    u32 pid;
    int user_stack_id;
    int kernel_stack_id;
    char name[TASK_COMM_LEN];
};
BPF_HASH(counts, struct key_t);
BPF_HASH(start, u32);
BPF_STACK_TRACE(stack_traces, 16384);

int oncpu(struct pt_regs *ctx, struct task_struct *prev) {
    u32 prev_pid = prev->pid;
    u64 ts, *tsp;
    u32 curr_pid = bpf_get_current_pid_tgid();
    BUILD_TARGET_PID
    if((prev_pid != target_pid) && (curr_pid != target_pid)) {
        return 0;
    }
    if(prev_pid == target_pid) {
        ts = bpf_ktime_get_ns();
        start.update(&prev_pid, &ts);
    }

    // get the current thread's start time


    tsp = start.lookup(&curr_pid);
    if (tsp == 0) {
        return 0;        // missed start or filtered
    }

    // calculate current thread's delta time
    u64 t_start = *tsp;
    u64 t_end = bpf_ktime_get_ns();
    start.delete(&curr_pid);
    if (t_start > t_end) {
        return 0;
    }
    u64 delta = t_end - t_start;
    delta = delta / 1000;
    u64 MINBLOCK_US = 1;
    u64 MAXBLOCK_US = 0xfffffffffffffffe;
    if ((delta < MINBLOCK_US) || (delta > MAXBLOCK_US)) {
        return 0;
    }

    // create map key
    struct key_t key = {};

    key.pid = curr_pid;
    key.user_stack_id = USER_STACK_GET;
    key.kernel_stack_id = KERNEL_STACK_GET;
    bpf_get_current_comm(&key.name, sizeof(key.name));

    counts.increment(key, delta);
    return 0;
}
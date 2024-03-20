#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#ifdef EXIT_T
// exit
struct exit_data_t {
    u64 start_time;
    u64 exit_time;
    u32 pid;
    u32 ppid;
    int exit_code;
    u32 sig_info;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(exit_result);

TRACEPOINT_PROBE(sched, sched_process_exit)
{
    struct task_struct *task = (typeof(task))bpf_get_current_task();
    BUILD_TARGET_PID
    if (task->pid == target_pid) { return 0; }

    struct exit_data_t data = {};


    // data.start_time = PROCESS_START_TIME_NS;
    data.start_time = task->start_time;
    data.exit_time = bpf_ktime_get_ns();
    data.pid = task->tgid;
    data.ppid = task->real_parent->pid;
    data.exit_code = task->exit_code >> 8;
    data.sig_info = task->exit_code & 0xFF;
    bpf_get_current_comm(&data.task, sizeof(data.task));

    exit_result.perf_submit(args, &data, sizeof(data));
    return 0;
}
#endif

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

// exit
struct exit_data_t {
    u64 start_time;
    u64 exit_time;
    u32 pid;
    u32 ppid;
    int exit_code;
    u32 sig_info;
    u8 terminate;
    u64 utime;
    u64 stime;
    u64 nvcsw;
    u64 nivcsw;
    long min_flt;
    long maj_flt;
};
// BPF_PERF_OUTPUT(exit_result);
BPF_QUEUE(exit_queue, struct exit_data_t, 100);
TRACEPOINT_PROBE(sched, sched_process_exit)
{
    bpf_trace_printk("exit");
    struct task_struct *task = (typeof(task))bpf_get_current_task();
    BUILD_TARGET_PID
    if (task->tgid != target_pid) { return 0; }

    struct exit_data_t data = {};
    if (task->tgid == target_pid) {
        data.terminate = 1;
    } else {
        data.terminate = 0;
    }

    data.start_time = task->start_time;
    data.exit_time = bpf_ktime_get_ns();
    data.pid = task->tgid;
    data.ppid = task->real_parent->pid;
    data.exit_code = task->exit_code >> 8;
    data.sig_info = task->exit_code & 0xFF;
    // bpf_probe_read_kernel(&data.utime, sizeof(data.utime), &task->utime);
    // bpf_probe_read_kernel(&data.utime, sizeof(data.stime), &task->stime);
    // bpf_probe_read_kernel(&data.utime, sizeof(data.nvcsw), &task->nvcsw);
    // bpf_probe_read_kernel(&data.utime, sizeof(data.nivcsw), &task->nivcsw);
    // bpf_probe_read_kernel(&data.utime, sizeof(data.min_flt), &task->min_flt);
    // bpf_probe_read_kernel(&data.utime, sizeof(data.maj_flt), &task->maj_flt);
    // task->utime;
    // tas->stime;
    // task->nvcsw;
    // task->nivcsw;
    // task->min_flt;
    // task->maj_flt;
    exit_queue.push(&data, BPF_EXIST);
    return 0;
}

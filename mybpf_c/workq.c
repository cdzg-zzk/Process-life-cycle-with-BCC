#include <uapi/linux/ptrace.h>
#include <linux/tracepoint.h>
#include <linux/workqueue.h>

BPF_HASH(start, u32);
BPF_HASH(wqfunc, u32, void*);

struct workq_data_t {
    void* funcptr;
    u64 slot;
};
BPF_HISTOGRAM(hist, struct workq_data_t);

TRACEPOINT_PROBE(workqueue, workqueue_execute_start)
{
    u32 pid = bpf_get_current_pid_tgid();
    bpf_trace_printk("workq ppid: %d", pid);
    BUILD_TARGET_PID
    // if(target_pid != pid) {
    //     return 0;
    // }
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    void* funcptr = args->function;
    wqfunc.update(&pid, &funcptr);
    return 0;
}

TRACEPOINT_PROBE(workqueue, workqueue_execute_end)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 *tsp = start.lookup(&pid);
    void **funcptr2 = wqfunc.lookup(&pid);
    if (tsp != NULL && funcptr2 != NULL) {
        u64 dur = (bpf_ktime_get_ns() - *tsp) / 1000;
        struct workq_data_t workq_data = {};
        workq_data.funcptr = *funcptr2;
        workq_data.slot = bpf_log2(dur);
        hist.increment(workq_data);
        start.delete(&pid);
        wqfunc.delete(&pid);
    }
    return 0;
}
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

#define SYSCALLS
#ifdef CONTEXT_SWITCH
// for runqueue latency
BPF_HASH(runqueue_start, u32);
BPF_PERF_OUTPUT(runqueue_result);
struct runqueue_data_t {
    u64 timestamp;
    u64 latency;
};
// record enqueue timestamp
static inline int trace_enqueue(u32 target_pid, u32 pid)
{
    if(target_pid != pid){
        return 0;
    }
    u64 ts = bpf_ktime_get_ns();
    runqueue_start.update(&pid, &ts);
    return 0;
}
int trace_wake_up_new_task(struct pt_regs *ctx, struct task_struct *p)
{
    BUILD_TARGET_PID
    return trace_enqueue(target_pid, p->pid);
}
int trace_ttwu_do_wakeup(struct pt_regs *ctx, struct rq *rq, struct task_struct *p, int wake_flags)
{
    BUILD_TARGET_PID
    return trace_enqueue(target_pid, p->pid);
}

// for context-switch
struct target_switch_data_t {
    u64 start_timestamp;
    u64 duration;
    u32 prev_pid;
    u8 valuntary;
};
BPF_ARRAY(switch_out_valuntary, u64, 1);          // 自愿换出
BPF_ARRAY(switch_out_invaluntary, u64, 1);         // 非自愿换出

BPF_ARRAY(switch_case, struct target_switch_data_t, 1); // 一次执行

BPF_PERF_OUTPUT(switch_result);

// track finish_task_switch(struct task_struct *prev)
int record_switch(struct pt_regs *ctx, struct task_struct *prev) {
    u32 curr_pid = bpf_get_current_pid_tgid();
    u32 prev_pid = prev->pid;
    // 在这里引入target pid
    BUILD_TARGET_PID
    // 已经有了targe_pid

    if((curr_pid != target_pid) && (prev_pid != target_pid)) {
        bpf_trace_printk("have no target process");
        return 0;
    }
    if(curr_pid == prev_pid) {
        bpf_trace_printk("not switch");
    }
    u64 time_ns = bpf_ktime_get_ns();
    
    int index_0 = 0;
    struct target_switch_data_t switch_data_0 = {};
    struct target_switch_data_t* switch_data = switch_case.lookup_or_try_init(&index_0, &switch_data_0);
    // bpf_trace_printk("target_pid: %u prev_pid: %u  next_pid: %u\\n", target_pid,prev_pid,curr_pid);
    if (switch_data && prev_pid == target_pid) {       // switch-out  
        if (prev->STATE_FIELD == TASK_RUNNING) {
            runqueue_start.update(&prev_pid, &time_ns);
            switch_data->valuntary = 0;
            switch_out_invaluntary.atomic_increment(index_0);
            bpf_trace_printk("invaluntary cs");
        } else {
            switch_data->valuntary = 1;
            switch_out_valuntary.atomic_increment(index_0);
            bpf_trace_printk("valuntary cs");
        }
        switch_data->duration = time_ns - switch_data->start_timestamp;                      

        switch_result.perf_submit(ctx, switch_data, sizeof(*switch_data));
        // switch_case.update(&index_0, &switch_data_0);
    } else if(switch_data && curr_pid == target_pid) {                         // switch-in
        // 更新切回的timestamp
        switch_data->start_timestamp = time_ns;
        switch_data->prev_pid = prev->pid;
        // bpf_probe_read_kernel_str(&switch_data->prev_comm, sizeof(switch_data->prev_comm), prev->comm);
        switch_case.update(&index_0, switch_data);
        // 换入，停止计时
        u64 *tsp, delta;
        // fetch timestamp and calculate delta
        tsp = runqueue_start.lookup(&curr_pid);
        if (!tsp || tsp == 0) {
            delta = 0;   // missed enqueue
        } else {
            delta = time_ns - *tsp;
        }
        struct runqueue_data_t runq_event = {time_ns, delta};
        runqueue_result.perf_submit(ctx, &runq_event, sizeof(runq_event));
        // runqueue_result.perf_submit(ctx, &delta, sizeof(delta));

    } else if(!switch_data) {
        bpf_trace_printk("have null ptr!!\\n");
    }
    // switch_result.perf_submit(ctx, &time_ns, sizeof(time_ns));
    return 0;
}
#endif


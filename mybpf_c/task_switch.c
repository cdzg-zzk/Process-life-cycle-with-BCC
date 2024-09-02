#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/preempt.h>
#include <uapi/linux/ptrace.h>

enum SCHED_ENTRY
{
    NONE = 0,
    SCHEDULE = 1,
    PREEMPT_IRQ = 2,
    TIMEOUT = 3,
};
struct sched_entry_data_t {
    enum SCHED_ENTRY entry;
    int need_sched;
};
BPF_HASH(sched_entry, u32, struct sched_entry_data_t);
struct target_switchout_data_t {
    u64 timestamp;
    u64 duration;
    u32 next_pid;
    char next_comm[TASK_COMM_LEN];
    u32 state;
    enum SCHED_ENTRY entry;
    int need_sched;
    // u64 nvcsw;
    // u64 nivcsw;

};
struct target_switchin_data_t {
    u64 timestamp;
    u32 prev_pid;
    char prev_comm[TASK_COMM_LEN];
    u32 state;
    enum SCHED_ENTRY entry;
    int need_sched;
};
BPF_ARRAY(timestamp, u64, 1);          // context-switch的耗时: finish_task_switch - pick_task
BPF_HASH(start_time, u32, u64);         // 进程占用CPU时间: switch-out - switch-in
BPF_HASH(runqueue_start, u32);
BPF_HASH(waitqueue_start, u32);
BPF_QUEUE(switch_in_queue, struct target_switchin_data_t, 10240);
BPF_QUEUE(switch_out_queue, struct target_switchout_data_t, 10240);
struct runqueue_data_t {
    u64 timestamp;
    u64 latency;
};
struct waitqueue_data_t {
    int state;
    u32 pid;
    u64 timestamp;
    u64 latency;
};
BPF_QUEUE(runqueue_queue, struct runqueue_data_t, 10240);
BPF_QUEUE(waitqueue_queue, struct waitqueue_data_t, 10240);
// record enqueue timestamp
static inline int
my_test_bit(int nr, const void * addr)
{
    return (1UL & (((const int *) addr)[nr >> 5] >> (nr & 31))) != 0UL;
}

BPF_HASH(judge_time_out, u32, u8);
int trace_prepare_to_wait_event_end(struct pt_regs *ctx, struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry, int state, long ret)
{
    u32 pid = bpf_get_current_pid_tgid();
    // bpf_trace_printk("hello enter wait queue pid: %d", pid);
    BUILD_TARGET_PID

    if(target_pid != pid) {
        return 0;
    }

    bpf_trace_printk("hello enter target wait queue ret: %d", PT_REGS_RC(ctx));

    u64 time_ns = bpf_ktime_get_ns();
    u64* tsp = waitqueue_start.lookup(&pid);
    if(tsp == NULL || *tsp == 0) {
        waitqueue_start.update(&pid, &time_ns);
    }
    return 0;
}

int trace_finish_wait(struct pt_regs *ctx, struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry)
{
    u32 pid = bpf_get_current_pid_tgid();
    // bpf_trace_printk("hello exit wait queue pid: %d", pid);
    BUILD_TARGET_PID
    if(target_pid != pid) {
        return 0;
    }
    bpf_trace_printk("hello exit target wait queue pid: %d", pid);

    u64 time_ns = bpf_ktime_get_ns();
    struct task_struct *task = (typeof(task))bpf_get_current_task();
    u64* tsp = waitqueue_start.lookup(&pid);
    if(tsp == NULL || *tsp == 0)
    {
        return 0;
    }
    struct waitqueue_data_t data = {};
    data.timestamp = time_ns;
    data.latency = time_ns - *tsp;
    data.state = task->STATE_FIELD;
    data.pid = pid;
    *tsp = 0;
    waitqueue_start.update(&pid, tsp);
    waitqueue_queue.push(&data, BPF_EXIST);
    return 0;
}
int trace_wake_up_common(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    // bpf_trace_printk("hello wake up wait queue pid: %d", pid);
    BUILD_TARGET_PID
    if(target_pid != pid) {
        return 0;
    }
    bpf_trace_printk("hello wake up target wait queue pid: %d", pid);
    return 0;
}
int trace_resched_curr(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    BUILD_TARGET_PID
    if(target_pid != pid) {
        return 0;
    }
    u8* res = judge_time_out.lookup(&pid);
    if(!res || *res != 1) {
        return 0;
    }
    if(*res == 1)
    {
        *res = 2;
        judge_time_out.update(&pid, res);
    }
    bpf_trace_printk("resched: %d", *res);

    return 0;
}
int trace_scheduler_tick(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    // BUILD_TARGET_PID
    // if(target_pid != pid) {
    //     return 0;
    // }
    u8 start = 1;
    judge_time_out.update(&pid, &start);
    bpf_trace_printk("start: %d", start);

    return 0;
}
int trace_scheduler_tick_end(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    // BUILD_TARGET_PID
    // if(target_pid != pid) {
    //     return 0;
    // }
    u8* res = judge_time_out.lookup(&pid);
    if(!res) {
        return 0;
    }
    if(*res == 2) {
        *res = 3;
        judge_time_out.update(&pid, res);
    }
    bpf_trace_printk("end: %d", *res);
    return 0;
}
static inline int trace_enqueue(u32 target_pid, u32 pid)
{
    u64 ts = bpf_ktime_get_ns();
    runqueue_start.update(&pid, &ts);
    return 0;
}
int trace_wake_up_new_task(struct pt_regs *ctx, struct task_struct *p)
{

    BUILD_TARGET_PID
    if(target_pid != p->pid) {
        return 0;
    }
    bpf_trace_printk("wake_up_new_task");
    return trace_enqueue(target_pid, p->pid);
}
int trace_ttwu_do_wakeup(struct pt_regs *ctx, struct rq *rq, struct task_struct *p, int wake_flags)
{
    BUILD_TARGET_PID
    if(target_pid != p->pid) {
        return 0;
    }
    return trace_enqueue(target_pid, p->pid);
}

KFUNC_PROBE(schedule)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct task_struct *task = (typeof(task))bpf_get_current_task();
    unsigned int tif_flag;
    bpf_probe_read_kernel(&tif_flag, sizeof(tif_flag), &task->thread_info.flags);
    int need_resched = my_test_bit(3, (const void*)&tif_flag);

    struct sched_entry_data_t data = {};
    data.need_sched = need_resched;
    data.entry = SCHEDULE;
    u8* res = judge_time_out.lookup(&pid);
    if(res && *res == 3)
    {
        bpf_trace_printk("schedule: timeout");
        data.entry = TIMEOUT;
    } 
    if(res) {
        *res = -1;
        judge_time_out.update(&pid, res);
    }
    // bpf_trace_printk("schedule: need_resched: %d", need_resched);
    sched_entry.update(&pid, &data);
    return 0;
}
KFUNC_PROBE(preempt_schedule_irq)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct task_struct *task = (typeof(task))bpf_get_current_task();
    unsigned int tif_flag;
    bpf_probe_read_kernel(&tif_flag, sizeof(tif_flag), &task->thread_info.flags);
    int need_resched = my_test_bit(3, (const void*)&tif_flag);

    struct sched_entry_data_t data = {};
    data.need_sched = need_resched;
    data.entry = PREEMPT_IRQ;
    sched_entry.update(&pid, &data);
    // bpf_trace_printk("preempt_schedule_irq: need_resched: %d", need_resched);

    return 0;
}
KFUNC_PROBE(pick_next_task)
{
    u64 time_ns = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    struct task_struct *task = (typeof(task))bpf_get_current_task();
    unsigned int tif_flag;
    bpf_probe_read_kernel(&tif_flag, sizeof(tif_flag), &task->thread_info.flags);
    int need_resched = my_test_bit(3, (const void*)&tif_flag);
    u32 index = 0;
    timestamp.update(&index, &time_ns);
    // bpf_trace_printk("pick_next_task:  need_resched %d:", need_resched);
    struct sched_entry_data_t *tmp_entry = sched_entry.lookup(&pid);
    if(tmp_entry == NULL) {     // 没有schedule 和preempt_irq，直接从__schedule过来的
        struct sched_entry_data_t data = {};
        data.entry = NONE;
        data.need_sched = need_resched;
        sched_entry.update(&pid, &data);
    }
    return 0;
}

BPF_ARRAY(count_cs_cost, bool);
int record_switch(struct pt_regs *ctx, struct task_struct *prev) {
    u32 curr_pid = bpf_get_current_pid_tgid();
    u32 prev_pid = prev->pid;
    // 每次切换来了都要如此操作
    struct sched_entry_data_t *tmp_entry = sched_entry.lookup(&prev_pid);
    if(tmp_entry == NULL) {
        bpf_trace_printk("entry exit");
        return 0;
    }
    struct sched_entry_data_t entry_data = *tmp_entry;
    tmp_entry->entry = NONE;
    sched_entry.update(&prev_pid, tmp_entry);
    // 在这里引入target pid
    BUILD_TARGET_PID
    // 已经有了targe_pid
    if((curr_pid != target_pid) && (prev_pid != target_pid)) {
        return 0;
    }

    // bpf_trace_printk("finish task switch: %d  :%d ", entry_data.entry, entry_data.need_sched);
    if(curr_pid == prev_pid) {
        bpf_trace_printk("task switch: not switch");
    }
    u64 time_ns = bpf_ktime_get_ns();
    
    u64 zero = 0;

    if (prev_pid == target_pid) {       // switch-out  

        struct target_switchout_data_t data = {};
        u64* start_timestamp = start_time.lookup(&prev_pid);       // switch-in的时刻
        if(start_timestamp){
            data.duration = time_ns - *start_timestamp;                      
        }
        struct task_struct *curr = (typeof(curr))bpf_get_current_task();
        data.timestamp = time_ns;
        data.state = prev->STATE_FIELD;
        if(data.state == TASK_RUNNING) {
            runqueue_start.update(&prev_pid, &time_ns);
        }

        data.next_pid = curr_pid;
        data.entry = entry_data.entry;
        data.need_sched = entry_data.need_sched;
        bpf_get_current_comm(&data.next_comm, sizeof(data.next_comm));
        // bpf_probe_read_kernel(&data.nvcsw, sizeof(data.nvcsw), &curr->nvcsw);
        // bpf_probe_read_kernel(&data.nivcsw, sizeof(data.nivcsw), &curr->nivcsw);
        // switch_result.perf_submit(ctx, switch_data, sizeof(*switch_data));
        switch_out_queue.push(&data, BPF_EXIST);
        // switch_case.update(&index_0, &switch_data_0);
    } else if(curr_pid == target_pid) {                         // switch-in
        // 更新切回的timestamp
        // bpf_trace_printk("switch in");
        struct target_switchin_data_t data = {};
        data.timestamp = time_ns;
        data.prev_pid = prev->pid;
        data.state = prev->STATE_FIELD;
        data.entry = entry_data.entry;
        data.need_sched = entry_data.need_sched;
        bpf_probe_read_kernel_str(&data.prev_comm, sizeof(data.prev_comm), prev->comm);
        switch_in_queue.push(&data, BPF_EXIST);
        // 换入，停止计时
        u64 *tsp, delta;
        // fetch timestamp and calculate delta
        tsp = runqueue_start.lookup(&curr_pid);
        if (!tsp || tsp == 0) {
            delta = 0;   // missed enqueue
            return 0;
        } else {
            delta = time_ns - *tsp;
        }
        struct runqueue_data_t runq_event = {time_ns, delta};

        runqueue_queue.push(&runq_event, BPF_EXIST);
        start_time.update(&curr_pid, &time_ns);
    }
    bool count_cost_flag = true;
    u32 index = 0;
    count_cs_cost.update(&index, &count_cost_flag);
    return 0;
}
struct context_switch_data_t {
    u64 timestamp;
    u64 cost;
};
BPF_QUEUE(cs_cost_queue, struct context_switch_data_t, 10240);
int record_switch_end(struct pt_regs *ctx, struct task_struct *prev) {
    u32 index = 0;
    bool* flag_ptr = count_cs_cost.lookup(&index);
    if(!flag_ptr || *flag_ptr == false) {
        return 0;
    }
    *flag_ptr = false;
    count_cs_cost.update(&index, flag_ptr);
    u64 time_ns = bpf_ktime_get_ns();
    u64 *start_switch_ts = timestamp.lookup(&index);
    struct context_switch_data_t data = {};
    data.timestamp = time_ns;
    if(!start_switch_ts){
        return 0;
    }
    data.cost = time_ns - *start_switch_ts;
    cs_cost_queue.push(&data, BPF_EXIST);
    return 0;
}
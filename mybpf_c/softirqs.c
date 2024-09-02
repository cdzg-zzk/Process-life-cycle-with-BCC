#include <uapi/linux/ptrace.h>

// 可能还要记录何时结束软中断
typedef struct softirq_entry_key {
    u32 pid;
    u32 cpu;
} softirq_entry_key_t;
typedef struct soft_irq_enter_data {
    u32 vec;
    u64 timestamp;
} soft_irq_enter_data_t;
typedef struct soft_irq_exit_data {
    u32 vec;
    u64 duration;
    u64 timestamp;
} soft_irq_exit_data_t;

struct soft_val {
    u64 ts;
    u32 vec;
};

BPF_HASH(softorqs_start, softirq_entry_key_t, struct soft_val);
BPF_QUEUE(softirq_enter_queue, soft_irq_enter_data_t, 1024);
BPF_QUEUE(softirq_exit_queue, soft_irq_exit_data_t, 1024);

TRACEPOINT_PROBE(irq, softirq_entry)
{
    u32 curr_pid = bpf_get_current_pid_tgid();
    BUILD_TARGET_PID
    if(curr_pid != target_pid) {
        return 0;
    }
    struct soft_val val = {};
    softirq_entry_key_t key = {};
    u32 cpu = bpf_get_smp_processor_id();

    key.pid = curr_pid;
    key.cpu = cpu;
    val.ts = bpf_ktime_get_ns();
    val.vec = args->vec;
    soft_irq_enter_data_t data = {};
    data.timestamp = val.ts;
    data.vec = args->vec;
    softirq_enter_queue.push(&data, BPF_EXIST);
    softorqs_start.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(irq, softirq_exit)
{
    // bpf_trace_printk("soft_irq");
    u32 curr_pid = bpf_get_current_pid_tgid();
    BUILD_TARGET_PID
    if(curr_pid != target_pid) {
        return 0;
    }
    bpf_trace_printk("target soft irq");
    struct soft_val *valp;
    soft_irq_exit_data_t data = {};
    softirq_entry_key_t entry_key = {};
    u32 cpu = bpf_get_smp_processor_id();
    u64 ts = bpf_ktime_get_ns();

    entry_key.pid = curr_pid;
    entry_key.cpu = cpu;

    // fetch timestamp and calculate delta
    valp = softorqs_start.lookup(&entry_key);
    if (valp == NULL) {
        return 0;   // missed start
    }
    data.timestamp = ts;
    data.duration = ts - valp->ts;
    data.vec = valp->vec; 
    softirq_exit_queue.push(&data, BPF_EXIST);
    softorqs_start.delete(&entry_key);
    return 0;
}
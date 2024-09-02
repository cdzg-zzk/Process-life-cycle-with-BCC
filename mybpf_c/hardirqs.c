#include <uapi/linux/ptrace.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/interrupt.h>

// 可能需要新增一个poll buffer来体现，什么时候发生的硬中断

// Add cpu_id as part of key for irq entry event to handle the case which irq
// is triggered while idle thread(swapper/x, tid=0) for each cpu core.
// Please see more detail at pull request #2804, #3733.
typedef struct hardirq_entry_key {
    u32 pid;
    u32 cpu_id;
}hardirq_entry_key_t;

// typedef struct irq_enter_key {
//     char name[32];
//     u64 duration;
//     u64
// } irq_key_t;
typedef struct irq_exit_key {
    char name[32];
    u64 duration;
    u64 timestamp;
    int ret;
    int state;
} irq_exit_key;
typedef struct irq_enter_key {
    char name[32];
    int state;
    u64 timestamp;
} irq_enter_key;
typedef struct irq_name {
    char name[32];
} irq_name_t;

BPF_HASH(hardirq_start, hardirq_entry_key_t);
BPF_HASH(irqnames, hardirq_entry_key_t, irq_name_t);
BPF_QUEUE(irq_exit_queue, irq_exit_key, 1024);
BPF_QUEUE(irq_enter_queue, irq_enter_key, 1024);

TRACEPOINT_PROBE(irq, irq_handler_entry)
{
    hardirq_entry_key_t key = {};
    u32 cpu = bpf_get_smp_processor_id();

    key.pid = bpf_get_current_pid_tgid();
    key.cpu_id = cpu;
    BUILD_TARGET_PID
    if(target_pid != key.pid) {
        return 0;
    }
    u64 ts = bpf_ktime_get_ns();
    irq_name_t name = {};

    TP_DATA_LOC_READ_STR(&name.name, name, sizeof(name));
    irqnames.update(&key, &name);
    hardirq_start.update(&key, &ts);
    irq_enter_key data = {};
    data.timestamp = ts;
    bpf_probe_read_kernel(&data.name, sizeof(data.name), name.name);
    struct task_struct *task = (typeof(task))bpf_get_current_task();
    data.state = task->STATE_FIELD;
    irq_enter_queue.push(&data, BPF_EXIST);
    return 0;
}

TRACEPOINT_PROBE(irq, irq_handler_exit)
{
    u64 *tsp, delta;
    irq_name_t *namep;
    hardirq_entry_key_t key = {};
    u32 cpu = bpf_get_smp_processor_id();

    key.pid = bpf_get_current_pid_tgid();
    key.cpu_id = cpu;
    BUILD_TARGET_PID
    if(target_pid != key.pid) {
        return 0;
    }
    // check ret value of irq handler is not IRQ_NONE to make sure
    // the current event belong to this irq handler
    if (args->ret != IRQ_NONE) {
        // fetch timestamp and calculate delta
        tsp = hardirq_start.lookup(&key);
        namep = irqnames.lookup(&key);
        if (tsp == 0 || namep == 0) {
            return 0;   // missed start
        }

        char *name = (char *)namep->name;
        u64 ts = bpf_ktime_get_ns();
        delta = ts - *tsp;

        // store as sum or histogram
        irq_exit_key data = {};
        data.duration = delta;
        bpf_probe_read_kernel(&data.name, sizeof(data.name), name);
        data.timestamp = ts;
        data.ret = args->ret;
        struct task_struct *task = (typeof(task))bpf_get_current_task();
        data.state = task->STATE_FIELD;
        irq_exit_queue.push(&data, BPF_EXIST);
    }

    hardirq_start.delete(&key);
    irqnames.delete(&key);
    return 0;
}
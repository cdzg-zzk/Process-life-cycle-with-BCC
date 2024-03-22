#include <uapi/linux/ptrace.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/interrupt.h>

// Add cpu_id as part of key for irq entry event to handle the case which irq
// is triggered while idle thread(swapper/x, tid=0) for each cpu core.
// Please see more detail at pull request #2804, #3733.
typedef struct entry_key {
    u32 pid;
    u32 cpu_id;
} entry_key_t;

typedef struct irq_key {
    char name[32];
    u64 slot;
} irq_key_t;

typedef struct irq_name {
    char name[32];
} irq_name_t;

BPF_HASH(start, entry_key_t);
BPF_HASH(irqnames, entry_key_t, irq_name_t);
BPF_HISTOGRAM(hardirqs_dist, irq_key_t);

TRACEPOINT_PROBE(irq, irq_handler_entry)
{
    struct entry_key key = {};
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
    start.update(&key, &ts);
    return 0;
}

TRACEPOINT_PROBE(irq, irq_handler_exit)
{
    u64 *tsp, delta;
    irq_name_t *namep;
    struct entry_key key = {};
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
        tsp = start.lookup(&key);
        namep = irqnames.lookup(&key);
        if (tsp == 0 || namep == 0) {
            return 0;   // missed start
        }

        char *name = (char *)namep->name;
        delta = bpf_ktime_get_ns() - *tsp;

        // store as sum or histogram
        irq_key_t key = {.slot = bpf_log2l(delta / 1000)};
        bpf_probe_read_kernel(&key.name, sizeof(key.name), name);
        hardirqs_dist.atomic_increment(key);
    }

    start.delete(&key);
    irqnames.delete(&key);
    return 0;
}
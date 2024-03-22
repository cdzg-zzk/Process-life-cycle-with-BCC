#include <uapi/linux/ptrace.h>

typedef struct entry_key {
    u32 pid;
    u32 cpu;
} entry_key_t;

typedef struct irq_key {
    u32 vec;
    u64 slot;
} irq_key_t;

typedef struct account_val {
    u64 ts;
    u32 vec;
} account_val_t;

BPF_HASH(softorqs_start, entry_key_t, account_val_t);
BPF_HISTOGRAM(softirqs_dist, irq_key_t);

TRACEPOINT_PROBE(irq, softirq_entry)
{
    u32 curr_pid = bpf_get_current_pid_tgid();
    if(curr_pid != 1) {
        return 0;
    }
    account_val_t val = {};
    entry_key_t key = {};
    u32 cpu = bpf_get_smp_processor_id();

    key.pid = curr_pid;
    key.cpu = cpu;
    val.ts = bpf_ktime_get_ns();
    val.vec = args->vec;

    softorqs_start.update(&key, &val);

    return 0;
}

TRACEPOINT_PROBE(irq, softirq_exit)
{
    u32 curr_pid = bpf_get_current_pid_tgid();
    if(curr_pid != 1) {
        return 0;
    }
    u64 delta;
    u32 vec;
    account_val_t *valp;
    irq_key_t key = {0};
    entry_key_t entry_key = {};
    u32 cpu = bpf_get_smp_processor_id();


    entry_key.pid = curr_pid;
    entry_key.cpu = cpu;

    // fetch timestamp and calculate delta
    valp = softorqs_start.lookup(&entry_key);
    if (valp == 0) {
        return 0;   // missed start
    }
    delta = bpf_ktime_get_ns() - valp->ts;
    vec = valp->vec;

    // store as sum or histogram
    key.vec = vec; 
    key.slot = bpf_log2l(delta / 1000);
    softirqs_dist.atomic_increment(key);

    softorqs_start.delete(&entry_key);
    return 0;
}
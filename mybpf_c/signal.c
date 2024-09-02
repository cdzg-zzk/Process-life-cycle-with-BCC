#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// BPF_PERF_OUTPUT(signal_generate_result);
// BPF_PERF_OUTPUT(signal_deliver_result);

typedef struct signal_generate_data_t {
    unsigned int from_pid;
    unsigned int to_pid;
    int sig;
    int errno;
    int res;
    unsigned long long timestamp;
    char from_comm[16];
    char to_comm[16];
}signal_generate_data_t;
typedef struct signal_deliver_data_t {
    unsigned int pid;
    int sig;
    int errno;
    unsigned long long timestamp;
    char comm[16];
}signal_deliver_data_t;

BPF_QUEUE(signal_generate_queue, signal_generate_data_t, 1024);
BPF_QUEUE(signal_deliver_queue, signal_deliver_data_t, 1024);

TRACEPOINT_PROBE(signal, signal_generate) {
    BUILD_TARGET_PID
    u32 pid = bpf_get_current_pid_tgid();

    struct signal_generate_data_t generate_data = {};
    generate_data.from_pid = pid;
    generate_data.to_pid = args->pid;
    if(generate_data.from_pid != target_pid && generate_data.to_pid != target_pid) {
        return 0;
    }
    generate_data.timestamp = bpf_ktime_get_ns();
    generate_data.errno = args->errno;
    generate_data.sig = args->sig;
    generate_data.res = args->result;
    bpf_probe_read_kernel(&generate_data.to_comm, sizeof(generate_data.to_comm), args->comm);
    bpf_get_current_comm(&generate_data.from_comm, sizeof(generate_data.from_comm));
    // signal_generate_result.perf_submit(args, &generate_data, sizeof(generate_data));
    signal_generate_queue.push(&generate_data, BPF_EXIST);
    return 0;
}
TRACEPOINT_PROBE(signal, signal_deliver) {
    BUILD_TARGET_PID
    u32 pid = bpf_get_current_pid_tgid();
    if(pid != target_pid) {
        return 0;
    }
    struct signal_deliver_data_t deliver_data = {};
    deliver_data.pid = pid;
    deliver_data.sig = args->sig;
    deliver_data.timestamp = bpf_ktime_get_ns();
    deliver_data.errno = args->errno;
    bpf_get_current_comm(&deliver_data.comm, sizeof(deliver_data.comm));
    // signal_deliver_result.perf_submit(args, &deliver_data, sizeof(deliver_data));
    signal_deliver_queue.push(&deliver_data, BPF_EXIST);
    return 0;
}


struct handle_signal_t {
    u64 timestamp;
    u64 duration;
};
BPF_QUEUE(new_signal_queue, struct handle_signal_t, 1024);
BPF_HASH(new_signal_start, u32, u64);
int trace_get_signal(struct pt_regs *ctx, struct ksignal *ksig)
{
    BUILD_TARGET_PID
    u32 pid = bpf_get_current_pid_tgid();
    bpf_trace_printk("hello new signal: pid: %d,  target pid: %d", pid, target_pid);
    if(pid != target_pid) {
        return 0;
    }
    u64 time_ns = bpf_ktime_get_ns(); 
    new_signal_start.update(&pid, &time_ns);   
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_rt_sigreturn)
{
    BUILD_TARGET_PID
    u32 pid = bpf_get_current_pid_tgid();
    bpf_trace_printk("hello new sigreturn: pid: %d,  target pid: %d", pid, target_pid);
    if(pid != target_pid) {
        return 0;
    }
    u64 time_ns = bpf_ktime_get_ns();
    u64 *start_tsp = new_signal_start.lookup(&pid);
    if(start_tsp == 0) {
        return 0;
    }
    u64 duration = time_ns - *start_tsp;
    struct handle_signal_t data = {};
    data.timestamp = time_ns;
    data.duration = duration;
    // bpf_probe_read_kernel(&data.sig, sizeof(data.sig), &ksig->sig);
    // bpf_trace_printk("hello new signal end: sig: %d", data.sig);
    new_signal_queue.push(&data, BPF_EXIST);
    return 0;
}
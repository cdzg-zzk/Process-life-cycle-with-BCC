#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#ifdef SYSCALLS
struct syscalls_data_t {   // for other process
    u64 count;
    u64 total_ns;
};
struct syscalls_entry_data_t {   // for target process
    u32 flag_latency; //进入还是退出       // enter:0, exit:latency
    u32 syscall_nr;
    u64 timestamp;
};
BPF_HASH(syscalls_start, u32, u64); // all processes
BPF_HASH(process_syscalls, u32, struct syscalls_data_t); // all processes
BPF_ARRAY(count_syscalls, u32, 1); // for target process
#ifdef FILTER_FAILED
BPF_HASH(process_failed_syscalls, u32, u32); // all processes
#endif
BPF_PERF_OUTPUT(syscalls_result);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
#ifdef FILTER_SYSCALL_NR                    // 这里需要filter systemlcalls的编号
    if (args->id != FILTER_SYSCALL_NR)
        return 0;
#endif

    u64 start_timestamp = bpf_ktime_get_ns();
    BUILD_TARGET_PID                        // filter pid，各种不同处理
    // if(pid != target_pid) {
    if(pid == target_pid) {
        struct syscalls_entry_data_t submit_data = {0, start_timestamp, args->id};
        syscalls_result.perf_submit(args, &submit_data, sizeof(submit_data));
        count_syscalls.increment(0);
        // syscalls_result.perf_submit(args, &pid, sizeof(pid));
    } 
    syscalls_start.update(&pid, &start_timestamp);
    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
#ifdef FILTER_SYSCALL_NR
    if (args->id != FILTER_SYSCALL_NR)
        return 0;
#endif
    u64 end_timestamp = bpf_ktime_get_ns();

#ifdef FILTER_FAILED
    u32 zero = 0;
    if (args->ret < 0) {
        u32* counts = process_failed_syscalls.lookup_or_try_init(&pid, &zero);
        lock_xadd(counts, 1);
        return 0;
    }
#endif
    BUILD_TARGET_PID
    u64 *start_ns = syscalls_start.lookup(&pid);
    if (!start_ns) {
        bpf_trace_printk("miss syscall start trace");
        return 0;
    }
    struct syscalls_data_t* val;
    struct syscalls_data_t zero_data = {};
    val = process_syscalls.lookup_or_try_init(&pid, &zero_data);
    u32 latency = end_timestamp - *start_ns;
    if (val) {
        lock_xadd(&val->count, 1);
        lock_xadd(&val->total_ns, latency);
    }
    if(pid == target_pid) {
    // if(pid != target_pid) {
        // bpf_trace_printk("end a system call");
        struct syscalls_entry_data_t submit_data = {latency, end_timestamp, args->id};
        syscalls_result.perf_submit(args, &submit_data, sizeof(submit_data));      
    }
    return 0;
}
#endif
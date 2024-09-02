// #include <uapi/linux/ptrace.h>
// #include <linux/sched.h>
// #include <uapi/linux/ptrace.h>

// struct syscalls_start_data_t {   // for target process
//     u64 timestamp;
//     u32 syscall_nr;
// };
// struct syscalls_end_data_t {   // for target process
//     u32 latency; //进入还是退出       // enter:0, exit:latency
//     u32 syscall_nr;
//     u64 timestamp;
// };

// BPF_QUEUE(syscalls_start_queue, struct syscalls_start_data_t, 1024);
// BPF_QUEUE(syscalls_end_queue, struct syscalls_end_data_t, 1024);

// BPF_HASH(syscalls_start, u32, u64);
// BPF_ARRAY(failed_syscalls_count, u32, 1);

// #ifdef FILTER_FAILED
// BPF_HASH(process_failed_syscalls, u32, u32); // all processes
// #endif
// // BPF_PERF_OUTPUT(syscalls_result);

// TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
//     bpf_trace_printk("1");
//     u32 pid = bpf_get_current_pid_tgid();

//     BUILD_TARGET_PID                        // filter pid，各种不同处理

//     if(pid != target_pid) {
//         bpf_trace_printk("%d %d", target_pid, pid);

//         return 0;
//     }
// #ifdef FILTER_SYSCALL_NR                    // 这里需要filter systemlcalls的编号
//     if (args->id != FILTER_SYSCALL_NR)
//         return 0;
// #endif

//     u64 start_timestamp = bpf_ktime_get_ns();

//     struct syscalls_start_data_t start_data = {};
//     start_data.syscall_nr = args->id;
//     start_data.timestamp = start_timestamp;
//     bpf_trace_printk("syscall start");
//     syscalls_start_queue.push(&start_data, BPF_EXIST);
//     // syscalls_result.perf_submit(args, &submit_data, sizeof(submit_data));
//     syscalls_start.update(&pid, &start_timestamp);
//     return 0;
// }

// TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
//     bpf_trace_printk("1");
//     u32 pid = bpf_get_current_pid_tgid();

//     BUILD_TARGET_PID
//     if(pid != target_pid) {
//         return 0;
//     }
// #ifdef FILTER_SYSCALL_NR
//     if (args->id != FILTER_SYSCALL_NR)
//         return 0;
// #endif
//     u64 end_timestamp = bpf_ktime_get_ns();

//     u32 zero = 0;
//     u32 one = 1;
//     if (args->ret < 0) {
//         u32* counts = failed_syscalls_count.lookup_or_try_init(&zero, &one);
//         if(counts != NULL) {
//             lock_xadd(counts, 1);
//         }
//         return 0;
//     }


//     u64 *start_ns = syscalls_start.lookup(&pid);
//     if (start_ns == NULL) {
//         bpf_trace_printk("miss syscall start trace");
//         return 0;
//     }

//     u64 latency = end_timestamp - *start_ns;

//     struct syscalls_end_data_t end_data = {};
//     end_data.latency = latency;
//     end_data.syscall_nr = args->id;
//     end_data.timestamp = end_timestamp;
//     bpf_trace_printk("syscall exit");
//     syscalls_end_queue.push(&end_data, BPF_EXIST);   
//     return 0;
// }



// TRACEPOINT_PROBE(syscalls, sys_enter_read) {
//     bpf_trace_printk("reaed....");
// }

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>


struct syscalls_start_data_t {   // for target process
    u32 syscall_nr;
    u64 timestamp;
};
struct syscalls_end_data_t {   // for target process
    u32 latency; 
    u32 syscall_nr;
    u64 timestamp;
    long ret;
};
BPF_HASH(syscall_start, u32, u64);
BPF_QUEUE(start_queue, struct syscalls_start_data_t, 1024);
BPF_QUEUE(end_queue, struct syscalls_end_data_t, 1024);
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u32 pid = bpf_get_current_pid_tgid();
    BUILD_TARGET_PID
    if(pid != target_pid)
        return 0;
    u64 t = bpf_ktime_get_ns();
    u32 key = args->id;
    syscall_start.update(&key, &t);
    struct syscalls_start_data_t data = {};
    data.timestamp = t;
    data.syscall_nr = key;
    start_queue.push(&data, BPF_EXIST);
    return 0;
}


TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    u32 pid = bpf_get_current_pid_tgid();
    BUILD_TARGET_PID
    if(pid != target_pid)
        return 0;

    u64 t = bpf_ktime_get_ns();
    // if (args->ret != -FILTER_ERRNO)
    //     return 0;

    u32 key = args->id;

    u64 *start_ns = syscall_start.lookup(&key);
    if (!start_ns)
        return 0;
    struct syscalls_end_data_t data = {};
    data.syscall_nr = args->id;
    data.latency = t-*start_ns;
    data.timestamp = t;
    data.ret = args->ret;
    end_queue.push(&data, BPF_EXIST);
    
    return 0;
}
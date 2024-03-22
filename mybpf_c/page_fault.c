#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/mm.h>

BPF_ARRAY(target_page_fault_kernel_count, u64, 1);      // target process
BPF_ARRAY(page_fault_kernel_count, u64, 1);             // all processes
TRACEPOINT_PROBE(exceptions, page_fault_kernel) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 error_code = 0;
    BUILD_TARGET_PID
    if(pid == target_pid){
        target_page_fault_kernel_count.atomic_increment(0);
    }
    page_fault_kernel_count.atomic_increment(0);
    return 0;
}

BPF_ARRAY(target_page_fault_user_count, u64, 1);      // target process
BPF_ARRAY(page_fault_user_count, u64, 1);             // all processes
TRACEPOINT_PROBE(exceptions, page_fault_user) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 error_code = 0;
    BUILD_TARGET_PID
    if(pid == target_pid){
        target_page_fault_user_count.atomic_increment(0);
    }
    page_fault_user_count.atomic_increment(0);
    return 0;
}


// int process(struct pt_regs *regs, unsigned long error_code, unsigned long address)
// {
//     bpf_trace_printk("page_fault: %d", error_code);
//     return 0;
// }
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/mm.h>

struct page_fault_t {
    u64 ret;
    u64 timestamp;
    u64 latency;
    u32 flags;  
    bool major;
    bool retry;
};
// u64 address;
BPF_HASH(exec_start, u32, u64);
BPF_HASH(retry_map, u32, bool);
BPF_QUEUE(page_fault_queue, struct page_fault_t, 1024);

int handle_mm_fault_enter(struct pt_regs *ctx, struct vm_area_struct *vma, unsigned long address,
			   unsigned int flags, struct pt_regs *regs)
{
    u32 pid = bpf_get_current_pid_tgid();
    BUILD_TARGET_PID
    if(pid != target_pid) {
        return 0;
    }
    bpf_trace_printk("enter: flags: %d", flags & (1<<5));
    u64 current_time = bpf_ktime_get_ns();
    exec_start.update(&pid, &current_time);
    return 0;
}

int handle_mm_fault_exit(struct pt_regs *ctx, struct vm_area_struct *vma, unsigned long address,
			   unsigned int flags, struct pt_regs *regs)
{
    u32 pid = bpf_get_current_pid_tgid();
    BUILD_TARGET_PID
    if(pid != target_pid) {
        return 0;
    }
    unsigned long ret = (unsigned long)PT_REGS_RC(ctx);
    u64 *start_ts;
    start_ts = exec_start.lookup(&pid);

    exec_start.delete(&pid);
    struct page_fault_t data = {};
    u64 time_ns = bpf_ktime_get_ns();
    data.timestamp = time_ns;
    data.ret = ret;
    if (start_ts) {
        data.latency = time_ns - *start_ts; 
    } else {
        data.latency = time_ns - 0;
    }

    data.flags = flags;
    // data.address = address;
    // data.retry = (ret & 0x000400) && (data.flags & (1 << 2));
    data.retry = (ret & 0x000400);
    bool* redo = retry_map.lookup(&pid);
    bool tmp = false;

    retry_map.update(&pid, &data.retry);
    if(ret & (0x000400 | 0x000001 | 0x000002 | 0x000040 | 0x000010 | 0x000020 | 0x000800))
        data.major = false;
    else {
        if(!redo) {
            tmp = false; 
        } else {
            tmp = *redo;
        }
        // data.major = (ret & 4) || (flags & (1 << 5));
        data.major = (ret & 4) || tmp;
    }

    page_fault_queue.push(&data, BPF_EXIST);
    return 0;
}
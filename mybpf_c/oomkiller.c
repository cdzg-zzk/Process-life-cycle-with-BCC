#include <uapi/linux/ptrace.h>
#include <linux/oom.h>

struct data_t {
    u32 fpid;
    u32 tpid;
    u64 pages;
    char fcomm[TASK_COMM_LEN];
    char tcomm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(oomkiller_event);

void kprobe__oom_kill_process(struct pt_regs *ctx, struct oom_control *oc, const char *message)
{
    struct task_struct *p = oc->chosen;
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    data.fpid = pid;
    data.tpid = p->tgid;
    data.pages = oc->totalpages;
    bpf_get_current_comm(&data.fcomm, sizeof(data.fcomm));
    bpf_probe_read_kernel(&data.tcomm, sizeof(data.tcomm), p->comm);
    oomkiller_event.perf_submit(ctx, &data, sizeof(data));
}
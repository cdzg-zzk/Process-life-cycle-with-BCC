#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/cpufreq.h>
// cpufreq
BPF_HISTOGRAM(freq_hist, u64, 25);

TRACEPOINT_PROBE(power, cpu_frequency)
{
    u32 pid = bpf_get_current_pid_tgid();
    // BUILD_TARGET_PID
    // if(pid != target_pid) {
    //     return 0;
    // }
    u64 cpu = args->cpu_id;
    u64 stat = args->state;
    bpf_trace_printk("cpu_id: %d    freq:%d", cpu, stat);
    freq_hist.increment(cpu, stat / 1000);
    return 0;
}



// # 注册tracepoint事件
// bpf.attach_tracepoint(tp="power:cpu_frequency", fn_name="TRACEPOINT_PROBE_power_cpu_frequency")

// # 打印直方图结果
// freq_hist = bpf.get_table("freq_hist")
// hist.print_log2_hist(freq_hist, "CPU Frequency (kHz)")
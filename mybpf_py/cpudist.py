from __future__ import print_function
from bcc import BPF
import comm_module
import os

def process_bpf_text(bpf_text):
    script_path = os.path.abspath(__file__)
    script_directory = os.path.dirname(script_path)
    script_directory = script_directory.replace('mybpf_py', 'mybpf_c')
    file_path = script_directory + "/cpudist.c"
    print(file_path)
    raw_text = "#define CPUDIST\n" + bpf_text
    # 打开文件
    with open(file_path, "r") as file:
        # 读取文件内容
        raw_text = raw_text + file.read()
    # other operation
    return raw_text

def attach_probe(bpf_object):
    comm_module.bpf_object.attach_kprobe(event_re=r'^finish_task_switch$|^finish_task_switch\.isra\.\d$',
                fn_name="cpu_sched_switch")

# def open_poll_buffer(bpf_object):
#     bpf_object["syscalls_result"].open_perf_buffer(print_syscalls_events)

# def print_syscalls_events(ctx, data, size):
#     event = comm_module.bpf_object["syscalls_result"].event(data)
#     if event.flag_latency == 0:
#         print("enter:")
#     else:
#         print("exit:")
#     print("NR: %-5d  TS:%-10d " % (event.syscall_nr, event.timestamp))
def process_data():
    dist = comm_module.bpf_object["dist"]
    target_dist = comm_module.bpf_object["target_dist"]
    def pid_to_comm(pid):
        try:
            comm = open("/proc/%d/comm" % pid, "r").read()
            return "%d %s" % (pid, comm)
        except IOError:
            return str(pid)

    target_dist.print_log2_hist("mesc", "pid", section_print_fn=pid_to_comm)
    dist.print_log2_hist("mesc", "")
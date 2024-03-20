from __future__ import print_function
from bcc import BPF
import os

import comm_module
def process_bpf_text(bpf_text):
    raw_text = "#define CONTEXT_SWITCH\n" + bpf_text
    script_path = os.path.abspath(__file__)
    script_directory = os.path.dirname(script_path)
    script_directory = script_directory.replace('mybpf_py', 'mybpf_c')
    file_path = script_directory + "/task_switch.c"
    # 打开文件
    with open(file_path, "r") as file:
        # 读取文件内容
        raw_text = raw_text + file.read()
    # other opearation
    return raw_text

def attach_probe(bpf_object):
    bpf_object.attach_kprobe(event="finish_task_switch", fn_name="record_switch")

    
def open_poll_buffer(bpf_object):
    bpf_object["switch_result"].open_perf_buffer(print_switch_events)
    bpf_object["runqueue_result"].open_perf_buffer(print_runq_event)

def print_switch_events(ctx, data, size):     # 打印进程切换内容
    event = comm_module.bpf_object["switch_result"].event(data)
    # print("prev-comm: %-16s  %-10d" % (event.prev_comm, event.duration))
    print("context-switch: prev-pid: %-5d  %-10d" % (event.prev_pid, event.duration))
    # time.sleep(1)
    # event = bpf_switch["switch_result"].event(data)
    # print("context-switch: %-10d %-16s %-6d %-16s %-6d" % (event.timestamp, event.prev_comm, event.prev_pid,
    #                                  event.curr_comm, event.curr_pid))
    # time.sleep(1)

def print_runq_event(ctx, data, size):
    event = comm_module.bpf_object["runqueue_result"].event(data)
    print("run queue: %d" % event.latency)

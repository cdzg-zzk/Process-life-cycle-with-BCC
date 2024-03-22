from __future__ import print_function
from bcc import BPF
import comm_module
from time import strftime
import os

def process_bpf_text(bpf_text):
    script_path = os.path.abspath(__file__)
    script_directory = os.path.dirname(script_path)
    script_directory = script_directory.replace('mybpf_py', 'mybpf_c')
    file_path = script_directory + "/oomkiller.c"
    print(file_path)
    raw_text = "#define OOMKILLER\n" + bpf_text
    # 打开文件
    with open(file_path, "r") as file:
        # 读取文件内容
        raw_text = raw_text + file.read()
    # other operation
    return raw_text

def attach_probe(bpf_object):
    pass



# loadavg:  前三个数字是1、5、15分钟内的平均进程数
#           第四个值的分子是正在运行的进程数，分母是进程总数
#           最后一个是最近运行的进程ID号。
loadavg = "/proc/loadavg"
def print_oomkiller_event(cpu, data, size):
    event = comm_module.bpf_object["events"].event(data)
    with open(loadavg) as stats:
        avgline = stats.read().rstrip()
    print(("%s Triggered by PID %d (\"%s\"), OOM kill of PID %d (\"%s\")"
        ", %d pages, loadavg: %s") % (strftime("%H:%M:%S"), event.fpid,
        event.fcomm.decode('utf-8', 'replace'), event.tpid,
        event.tcomm.decode('utf-8', 'replace'), event.pages, avgline))
    
def open_poll_buffer(bpf_object):
    bpf_object["oomkiller_event"].open_perf_buffer(print_oomkiller_event)


from __future__ import print_function
from bcc import BPF
import time
import signal
import sys
from datetime import datetime, timedelta
from bcc.syscall import syscall_name, syscalls
import re
import subprocess
import multiprocessing

import argparse

import comm_module

import exit_event as my_exit
import context_switch_event as my_cs
import syscall_event as my_syscall
import cpudist as my_cpudist
import cpu_freq as my_freq
import offcpu_time as my_offcpu
import softirqs as my_softirqs
import hardirqs as my_hardirqs
import cachestat as my_cache
import oomkiller as my_oomkiller
import page_fault as my_page_fault
import swapin as my_swapin
import sync as my_sync
import filer_latency as my_filelat
import readahead as my_readahead
import biostat as my_biostat
import signals as my_signal
import mutex as my_mutex
import mutex_held as my_mutex_held
import workq as my_workq



def exit_process():
    with open("/usr/share/bcc/Process-life-cycle-with-BCC/timeline.txt", 'w') as file:
        file.write('')
    with open("/usr/share/bcc/Process-life-cycle-with-BCC/count_event.txt", 'w') as file:
        file.write('')
    my_exit.process_data()
    print()
    print("exit monitor process...")
    my_cs.process_data()
    my_filelat.process_data()
    my_syscall.process_data()

    my_softirqs.process_data()
    my_hardirqs.process_data()
    my_page_fault.process_data()
    my_signal.process_data()
    with open("/usr/share/bcc/Process-life-cycle-with-BCC/sorted-tmp.txt", 'w') as file:
        file.write("start time: " + str(comm_module.start_process_time-comm_module.start_timestamp) + '\n')
        file.write("end time: " + str(comm_module.end_process_time-comm_module.start_timestamp) + '\n')
    exit()
def terminate_process(sentence):
    command = "kill -9 18001"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    print(sentence + ", terminate target process: ")
    print(command)
    print(result.stdout)
    time.sleep(1)
    exit_process()

def signal_handler(signal, frame):
    print()
    terminate_process("Recive Ctrl+C")


# arguments
examples = """examples:
    ./mybpf -p 181           # target process is 181
    ./mybpf -p 181 -d 10     # trace for 10 seconds only
"""
parser = argparse.ArgumentParser(
    description="Trace target process lifetime",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
# # parser.add_argument("-t", "--timestamp", action="store_true",
# #     help="include timestamp on output")
# # parser.add_argument("-x", "--failed", action="store_true",
# #     help="only show failed opens")
parser.add_argument("-p", "--pid",
    help="target process is 181")
parser.add_argument("-d", "--duration",
    help="trace finxed seconds only")
args = parser.parse_args()

if args.duration is None:
    args.duration = 99999
if args.pid is not None:
    comm_module.id = args.pid

duration = timedelta(seconds=int(args.duration))
# file_path = "/usr/share/bcc/examples/mybpf_c/task_switch.c"  # 文件路径
# # 打开文件
# with open(file_path, "r") as file:
#     # 读取文件内容
#     bpf_text = file.read()
    
# 开启某一module
bpf_text = ""
bpf_text = my_cs.process_bpf_text(bpf_text)
bpf_text = my_exit.process_bpf_text(bpf_text)
bpf_text = my_syscall.process_bpf_text(bpf_text)
# bpf_text = my_cpudist.process_bpf_text(bpf_text)
# bpf_text = my_freq.process_bpf_text(bpf_text)
# bpf_text = my_offcpu.process_bpf_text(bpf_text)
bpf_text = my_softirqs.process_bpf_text(bpf_text)
bpf_text = my_hardirqs.process_bpf_text(bpf_text)
# bpf_text = my_cache.process_bpf_text(bpf_text)
# bpf_text = my_oomkiller.process_bpf_text(bpf_text)
bpf_text = my_page_fault.process_bpf_text(bpf_text)
# bpf_text = my_sync.process_bpf_text(bpf_text)
bpf_text = my_filelat.process_bpf_text(bpf_text)
# bpf_text = my_readahead.process_bpf_text(bpf_text)
# bpf_text = my_biostat.process_bpf_text(bpf_text)
bpf_text = my_signal.process_bpf_text(bpf_text)
# bpf_text = my_mutex.process_bpf_text(bpf_text)
# bpf_text = my_mutex_held.process_bpf_text(bpf_text)
# bpf_text = my_workq.process_bpf_text(bpf_text)
# bpf_text = my_swapin.process_bpf_text(bpf_text)

# common replace operation

bpf_text = bpf_text.replace('BUILD_TARGET_PID',
                            'u32 target_pid = %s;' % comm_module.id)
bpf_text = bpf_text.replace('IDLE_FILTER', 'pid == 0')
if BPF.kernel_struct_has_field(b'task_struct', b'__state') == 1:
    bpf_text = bpf_text.replace('STATE_FIELD', '__state')
else:
    bpf_text = bpf_text.replace('STATE_FIELD', 'state')

comm_module.init_bpf_object(bpf_text)
comm_module.prefix_str = comm_module.prefix_str.format(comm_module.comm, comm_module.id)

my_cs.attach_probe(comm_module.bpf_object)
my_exit.attach_probe(comm_module.bpf_object)
my_syscall.attach_probe(comm_module.bpf_object)
# my_cpudist.attach_probe(comm_module.bpf_object)
# my_freq.attach_probe(comm_module.bpf_object)
# my_offcpu.attach_probe(comm_module.bpf_object)
my_softirqs.attach_probe(comm_module.bpf_object)
my_hardirqs.attach_probe(comm_module.bpf_object)
# my_cache.attach_probe(comm_module.bpf_object)
# my_oomkiller.attach_probe(comm_module.bpf_object)
my_page_fault.attach_probe(comm_module.bpf_object)
# my_swapin.attach_probe(comm_module.bpf_object)
# my_sync.attach_probe(comm_module.bpf_object)
my_filelat.attach_probe(comm_module.bpf_object)
# my_readahead.attach_probe(comm_module.bpf_object)
# my_biostat.attach_probe(comm_module.bpf_object)
my_signal.attach_probe(comm_module.bpf_object)
# my_mutex.attach_probe(comm_module.bpf_object)
# my_mutex_held.attach_probe(comm_module.bpf_object)
# my_workq.attach_probe(comm_module.bpf_object)
# open poll buffer 
signal.signal(signal.SIGINT, signal_handler)
# def print_exit_events(ctx, data, size):
#     event = comm_module.bpf_object["exit_result"].event(data)
#     age = (event.exit_time - event.start_time) / 1e9
#     print("TIME:%-16d TASK:%-16s PID:%-7d PPID:%-7d AGE:%-7.2f " %
#               (event.exit_time, event.task.decode(), event.pid, event.ppid, age), end="")
#     if event.sig_info == 0:
#         print("0" if event.exit_code == 0 else "code:%d" % event.exit_code)
#     else:
#         sig = event.sig_info & 0x7F
#         if sig:
#             print("signal %d (%s)" % (sig, comm_module.signum_to_signame(sig)), end="")
#         if event.sig_info & 0x80:
#             print(", core dumped ", end="")
#         print()
#     if(event.terminate == 1):
#         return
    # exit() 监测到target进程退出，直接退出程序，做善后处理工作
    
# comm_module.bpf_object["exit_result"].open_perf_buffer(print_exit_events)
# my_mutex.open_poll_buffer(comm_module.bpf_object)
# my_exit.open_poll_buffer(comm_module.bpf_object)
# my_oomkiller.open_poll_buffer(comm_module.bpf_object)
# my_swapin.open_poll_buffer(comm_module.bpf_object)
# my_sync.open_poll_buffer(comm_module.bpf_object)
# my_biostat.open_poll_buffer(comm_module.bpf_object)
# my_mutex_held.open_poll_buffer(comm_module.bpf_object)



start_time = datetime.now() 
comm_module.continuing = 1  
while comm_module.continuing == 1: 
    if datetime.now() - start_time >= duration:
        terminate_process("target process runs out of time")
    my_exit.process_data()
    # print("continuing: %d" % comm_module.continuing)

    # print("enter perf buffer poll")
    # comm_module.bpf_object.perf_buffer_poll(timeout=100)
    # print("exit perf buffer poll")

exit_process()







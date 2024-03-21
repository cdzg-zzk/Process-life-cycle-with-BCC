from __future__ import print_function
from bcc import BPF
import time
import signal
from datetime import datetime, timedelta
from bcc.syscall import syscall_name, syscalls
import re

import argparse

import comm_module

import exit_event as my_exit
import context_switch_event as my_cs
import syscall_event as my_syscall
import cpudist as my_cpudist
# # arguments
# examples = """examples:
#     ./mybpf -p 181           # target process is 181
#     ./mybpf -p 181 -d 10     # trace for 10 seconds only
#     ./mybpf -x        # only show failed opens
#     ./mybpf -p 181    # only trace PID 181
# """
# parser = argparse.ArgumentParser(
#     description="Trace target process liveline",
#     formatter_class=argparse.RawDescriptionHelpFormatter,
#     epilog=examples)
# # parser.add_argument("-t", "--timestamp", action="store_true",
# #     help="include timestamp on output")
# # parser.add_argument("-x", "--failed", action="store_true",
# #     help="only show failed opens")
# parser.add_argument("-p", "--pid",
#     help="target process is 181")
# parser.add_argument("-d", "--duration", action="store_true",
#     help="trace finxed seconds only")
# args = parser.parse_args()

# args.pid = 0
# args.duration = 5
duration = timedelta(seconds=int(3))
# file_path = "/usr/share/bcc/examples/mybpf_c/task_switch.c"  # 文件路径
# # 打开文件
# with open(file_path, "r") as file:
#     # 读取文件内容
#     bpf_text = file.read()
    
# 开启某一module
bpf_text = ""
bpf_text = my_cs.process_bpf_text(bpf_text)
# bpf_text = my_exit.process_bpf_text(bpf_text)
# bpf_text = my_syscall.process_bpf_text(bpf_text)
bpf_text = my_cpudist.process_bpf_text(bpf_text)

id = 0

# common replace operation
bpf_text = bpf_text.replace('BUILD_TARGET_PID',
                            'u32 target_pid = %s;' % id)
bpf_text = bpf_text.replace('IDLE_FILTER', 'pid == 0')
if BPF.kernel_struct_has_field(b'task_struct', b'__state') == 1:
    bpf_text = bpf_text.replace('STATE_FIELD', '__state')
else:
    bpf_text = bpf_text.replace('STATE_FIELD', 'state')


comm_module.init_bpf_object(bpf_text)

my_cs.attach_probe(comm_module.bpf_object)
# my_exit.attach_probe(comm_module.bpf_object)
# my_syscall.attach_probe(comm_module.bpf_object)
my_cpudist.attach_probe(comm_module.bpf_object)
# open poll buffer 
my_cs.open_poll_buffer(comm_module.bpf_object)
# my_exit.open_poll_buffer(comm_module.bpf_object)
# my_syscall.open_poll_buffer(comm_module.bpf_object)        


start_time = datetime.now()
while not duration or datetime.now() - start_time < duration:
    print("enter perf buffer poll")
    comm_module.bpf_object.perf_buffer_poll(timeout=1000)
    print("exit perf buffer poll")
    print("continue")
    time.sleep(1)




def exit_process():
    print("exit monitor process...")
    my_cpudist.process_data()
    # count_syscalls = bpf_switch.get_table("count_syscalls")
    # switch_out_invaluntary = bpf_switch.get_table("switch_out_invaluntary")
    # print(count_syscalls[0])
    # print(switch_out_invaluntary[0])
    # count_syscalls = bpf_switch.get_table("count_syscalls")
    # print("hello")
    # print(count_syscalls[0])
exit_process()




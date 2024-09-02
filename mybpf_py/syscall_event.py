from __future__ import print_function
from bcc import BPF
import comm_module
from bcc.syscall import syscall_name, syscalls

import sys

def process_bpf_text(bpf_text):
    raw_text = comm_module.read_file("syscalls", "SYSCALLS")
    bpf_text =  bpf_text + '\n' + raw_text
    return bpf_text

def attach_probe(bpf_object):
    print("noting to attach")

def syscallnr2name(syscall_nr):
    return syscall_name(syscall_nr).decode()

syscall_counts = {}
def count_syscall_nr(syscall_nr):
    if syscall_nr in syscall_counts:
        syscall_counts[syscall_nr] += 1
    else:
        syscall_counts[syscall_nr] = 1

def print_syscall_counts():
    print("%-s  %-15s  %s" % ("syscall_nr", "syscall", "counts"))
    for k, v in syscall_counts.items():
        print("%-10d  %-15s  %d" % (k, syscallnr2name(k), v))
def process_data():
    sys.stdout = open('/usr/share/bcc/Process-life-cycle-with-BCC/timeline.txt', 'a')
    end_queue = comm_module.bpf_object["end_queue"]
    start_queue = comm_module.bpf_object["start_queue"]
    for i,v in enumerate(start_queue.values()):
        count_syscall_nr(v.syscall_nr)
        print("TIME: %-12d %s:  EVENT: <SYSCALL>: SYSTEM CALL: %-10s %d enter" % (v.timestamp - comm_module.start_timestamp, 
                                                                            comm_module.prefix_str,
                                                                            syscallnr2name(v.syscall_nr), v.syscall_nr))
    for i,v in enumerate(end_queue.values()):
        print("TIME: %-12d %s:  EVENT: <SYSCALL>: SYSTEM CALL: %-10s %d exit DURATION: %d  RET:%d" % (v.timestamp - comm_module.start_timestamp, 
                                                                            comm_module.prefix_str,
                                                                            syscallnr2name(v.syscall_nr), v.syscall_nr,
                                                                            v.latency, v.ret))  
    sys.stdout = open('/usr/share/bcc/Process-life-cycle-with-BCC/count_event.txt', 'a')
    print_syscall_counts()
    sys.stdout = sys.__stdout__        


    # start_queue = comm_module.bpf_object["syscalls_start_queue"]
    # end_queue = comm_module.bpf_object["syscalls_end_queue"]


       


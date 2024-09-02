from __future__ import print_function
from bcc import BPF
import comm_module
from time import strftime
import sys

def process_bpf_text(bpf_text):
    raw_text = comm_module.read_file(file_name="page_fault", HONG="PAGE_FAULT")
    bpf_text = raw_text + '\n' + bpf_text
    return bpf_text


def attach_probe(bpf_object):
    bpf_object.attach_kretprobe(event="handle_mm_fault", fn_name="handle_mm_fault_enter")
    bpf_object.attach_kretprobe(event="handle_mm_fault", fn_name="handle_mm_fault_exit")

    
def process_data():
    sys.stdout = open('/usr/share/bcc/Process-life-cycle-with-BCC/timeline.txt', 'a')
    page_fault_queue = comm_module.bpf_object["page_fault_queue"]

    for i,v in enumerate(page_fault_queue.values()):
        print("TIME: %-12d %s:  EVENT: <PAGE FAULT>: LAT: %d  RETRY: %s  MAJOR: %s  RET: %d" % (v.timestamp - comm_module.start_timestamp, 
                                                                            comm_module.prefix_str,
                                                                            v.latency, "Y" if v.retry else "N",
                                                                            "Y" if v.major else "N", 
                                                                            v.ret))
    sys.stdout = sys.__stdout__



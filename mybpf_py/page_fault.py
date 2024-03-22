from __future__ import print_function
from bcc import BPF
import comm_module
from time import strftime
import os

def process_bpf_text(bpf_text):
    bpf_text = comm_module.read_file(bpf_text=bpf_text, file_name="page_fault", HONG="PAGE_FAULT")
    return bpf_text

def attach_probe(bpf_object):
    bpf_object.attach_kprobe(event="do_page_fault", fn_name="process")


    
def process_data():
    target_user_count = comm_module.bpf_object.get_table("target_page_fault_user_count")
    user_count = comm_module.bpf_object.get_table("page_fault_user_count")
    target_kernel_count = comm_module.bpf_object.get_table("target_page_fault_kernel_count")
    kernel_count = comm_module.bpf_object.get_table("page_fault_kernel_count")
    print("target process occurred user page fault %d times" % target_user_count[0].value)
    print("target process occurred kernel page fault %d times" % target_kernel_count[0].value)
    print("all processes occurred user page fault %d times" % user_count[0].value)
    print("all processes occurred kernel page fault %d times" % kernel_count[0].value)



from __future__ import print_function
from bcc import BPF
import comm_module

def process_bpf_text(bpf_text):
    raw_text = comm_module.read_file(file_name="workq", HONG="WORKQ")
    bpf_text += raw_text
    return bpf_text

def attach_probe(bpf_object):
    pass


def address_to_ksym(address):
    return BPF.ksym(address).decode()
def process_data():
    dist = comm_module.bpf_object["hist"]
    dist.print_log2_hist("mesc", "work queue func", section_print_fn=address_to_ksym)




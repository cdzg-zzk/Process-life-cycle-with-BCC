from __future__ import print_function
from sys import stderr
from bcc import BPF
import comm_module
import os
from bcc import BPF

def process_bpf_text(bpf_text):
    raw_text = comm_module.read_file(file_name="swapin", HONG="SWAPIN")
    bpf_text = raw_text + bpf_text
    return bpf_text

def attach_probe(bpf_object):
    pass

def open_poll_buffer(bpf_object):
    bpf_object["swapin_result"].open_perf_buffer(print_swapin_events)

def print_swapin_events(ctx, data, size):
    event = comm_module.bpf_object["swapin_result"].event(data)
    print("process: %s [%d] occurs swapin" % (event.comm, event.pid))



# check whether hash table batch ops is supported
htab_batch_ops = True if BPF.kernel_struct_has_field(b'bpf_map_ops',
        b'map_lookup_and_delete_batch') == 1 else False
def process_data():
    print("%-16s %-7s %s" % ("COMM", "PID", "COUNT"))
    counts = comm_module.bpf_object.get_table("swapin_counts")
    for k, v in sorted(counts.items_lookup_and_delete_batch()
                    if htab_batch_ops else counts.items(),
            key=lambda counts: counts[1].value):
        print("%-16s %-7d %d" % (k.comm, k.pid, v.value))
    # if not htab_batch_ops:
    #     counts.clear()
    # print()


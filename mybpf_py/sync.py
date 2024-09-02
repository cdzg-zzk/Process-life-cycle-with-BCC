from __future__ import print_function
from sys import stderr
from bcc import BPF
import comm_module


def process_bpf_text(bpf_text):
    raw_text = comm_module.read_file( file_name="sync", HONG="SYNC")
    bpf_text = raw_text + bpf_text
    return bpf_text

def attach_probe(bpf_object):
    sync_event = bpf_object.get_syscall_fnname("sync")
    bpf_object.attach_kprobe(event=sync_event,
                fn_name="syscall__sync")
    
def open_poll_buffer(bpf_object):
    bpf_object["sync_result"].open_perf_buffer(print_sync_events)


def print_sync_events(ctx, data, size):
    sync_event = comm_module.bpf_object.get_syscall_fnname("sync")
    print(sync_event)
    event = comm_module.bpf_object["sync_result"].event(data)
    print("%d target process occurs %s" % (event.ts, sync_event))
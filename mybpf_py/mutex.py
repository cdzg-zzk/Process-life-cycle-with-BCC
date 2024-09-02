from __future__ import print_function
from bcc import BPF
import comm_module
import os

def process_bpf_text(bpf_text):
    raw_text = comm_module.read_file(file_name="mutex", HONG="MUTEX")
    bpf_text += raw_text
    return bpf_text

def attach_probe(bpf_object):
    bpf_object.attach_kprobe(event="mutex_lock", fn_name="trace_mutex_lock")
    bpf_object.attach_kprobe(event="mutex_lock_interruptible", fn_name="trace_mutex_lock")
    bpf_object.attach_kretprobe(event="mutex_lock", fn_name="trace_mutex_lock_end")
    bpf_object.attach_kretprobe(event="mutex_lock_interruptible", fn_name="trace_mutex_lock_interruptible_end")

def open_poll_buffer(bpf_object):
    bpf_object["mutex_wait_result"].open_perf_buffer(print_mutex_wait_events)

def print_mutex_wait_events(ctx, data, size):
    event = comm_module.bpf_object["mutex_wait_result"].event(data)
    print("duration: %-5d %s" % (event.duration, BPF.ksym(event.lock)))

def address_to_ksym(address):
    return BPF.ksym(address).decode()
def process_data():
    dist = comm_module.bpf_object["lock_latency_ns"]
    dist.print_log2_hist("Time on lock(ns)", "lock", section_print_fn=address_to_ksym)
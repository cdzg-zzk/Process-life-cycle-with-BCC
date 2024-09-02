from __future__ import print_function
from bcc import BPF
import comm_module

def process_bpf_text(bpf_text):
    raw_text = comm_module.read_file(file_name="mutex_held", HONG="MUTEX_HELD")
    bpf_text += raw_text
    return bpf_text

def attach_probe(bpf_object):
    bpf_object.attach_kprobe(event="mutex_lock", fn_name="mutex_lock_enter")
    bpf_object.attach_kprobe(event="mutex_lock_interruptible", fn_name="mutex_lock_enter")
    bpf_object.attach_kprobe(event="mutex_trylock", fn_name="mutex_lock_enter")

    bpf_object.attach_kretprobe(event="mutex_lock", fn_name="mutex_lock_return")
    bpf_object.attach_kretprobe(event="mutex_lock_interruptible", fn_name="mutex_trylock_interruptible_return")
    bpf_object.attach_kretprobe(event="mutex_trylock", fn_name="mutex_trylock_interruptible_return")
    
    bpf_object.attach_kprobe(event="mutex_unlock", fn_name="mutex_exit")


def open_poll_buffer(bpf_object):
    bpf_object["mutex_held_result"].open_perf_buffer(print_mutex_wait_events)

def print_mutex_wait_events(ctx, data, size):
    event = comm_module.bpf_object["mutex_held_result"].event(data)
    print("TIME:%-16d duration: %-5d %s" % (event.ts, event.duration, BPF.ksym(event.lock)))


def address_to_ksym(address):
    return BPF.ksym(address).decode()
def process_data():
    dist = comm_module.bpf_object["held_time_ns"]
    dist.print_log2_hist("Time held lock(ns)", "lock", section_print_fn=address_to_ksym)




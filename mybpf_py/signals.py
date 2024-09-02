from __future__ import print_function
from bcc import BPF
import comm_module
from time import strftime
import sys
import signal

def process_bpf_text(bpf_text):
    raw_text = comm_module.read_file(file_name="signal", HONG="SIGNAL")
    bpf_text = raw_text + '\n' + bpf_text
    return bpf_text

def attach_probe(bpf_object):
    bpf_object.attach_kprobe(event="get_signal", fn_name="trace_get_signal")
    # bpf_object.attach_kretprobe(event="signal_setup_done", fn_name="trace_signal_setup_done_end")

def process_data():
    sys.stdout = open('/usr/share/bcc/Process-life-cycle-with-BCC/timeline.txt', 'a')
    signal_generate_queue = comm_module.bpf_object["signal_generate_queue"]
    signal_deliver_queue = comm_module.bpf_object["signal_deliver_queue"]
    new_signal_queue = comm_module.bpf_object["new_signal_queue"]
    
    for i,v in enumerate(signal_generate_queue.values()):
        signal_name = comm_module.signal_list[v.sig-1]
        print("TIME: %-12d %s:  EVENT: <SIGNAL>: SIG: %-3d  SIG_NAME: %-5s [FROM_PROC: %-4d %-15s] sent to [RECV_PRC:%d %-15s]  RES:%d  ERRNO:%d" % 
                                                                            (v.timestamp - comm_module.start_timestamp, 
                                                                            comm_module.prefix_str,
                                                                            v.sig, signal_name,
                                                                            v.from_pid, v.from_comm.decode(),
                                                                            v.to_pid, v.to_comm.decode(),
                                                                            v.res, v.errno))
    for i,v in enumerate(signal_deliver_queue.values()):
        signal_name = comm_module.signal_list[v.sig-1]
        print("TIME: %-12d %s:  EVENT: <SIGNAL>: SIG: %-3d  SIG_NAME: %-5s [PROC: %-4d %-15s] deliver signal ERRNO: %d:" % 
                                                                            (v.timestamp - comm_module.start_timestamp, 
                                                                            comm_module.prefix_str,
                                                                            v.sig, signal_name,
                                                                            v.pid, v.comm.decode(),
                                                                            v.errno))  
    for i,v in enumerate(new_signal_queue.values()):    
        print("TIME: %-12d %s:  EVENT: <SIGNAL>: DURATION: %d" % (v.timestamp - comm_module.start_timestamp,
                                                                    comm_module.prefix_str,
                                                                    v.duration))                           
    sys.stdout = sys.__stdout__        




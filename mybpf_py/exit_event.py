from __future__ import print_function
from bcc import BPF
import comm_module
import sys


def process_bpf_text(bpf_text):
    raw_text = comm_module.read_file(file_name="exit", HONG="EXIT")
    bpf_text = raw_text + '\n' + bpf_text
    return bpf_text


def attach_probe(bpf_object):
    pass


def process_data():
    exit_queue = comm_module.bpf_object["exit_queue"]
    for i,v in enumerate(exit_queue.values()):
        print("TIME: %-12d %s:  EVENT: <PROCESS EXIT>: PPID: %d  PID: %d  AGE: %d  START: %d  ENT: %d" % (v.exit_time - comm_module.start_timestamp, 
                                                                            comm_module.prefix_str,
                                                                            v.ppid, v.pid,
                                                                            v.exit_time-v.start_time, 
                                                                            v.start_time - comm_module.start_timestamp,
                                                                            v.exit_time - comm_module.start_timestamp), end="")
        if v.sig_info == 0:
            print(" EXIT CODE: %d" % v.exit_code)
        else:
            sig = v.sig_info & 0x7F
            if sig:
                print("signal %d (%s)" % (sig, comm_module.signal_list[sig-1]), end="")
            if v.sig_info & 0x80:
                print(", core dumped! ")

        # print("terminate: %d", v.terminate)
        if(v.terminate == 1):
            comm_module.continuing = 0
            comm_module.start_process_time = v.start_time
            comm_module.end_process_time = v.exit_time


# def print_exit_events(ctx, data, size):
#     event = comm_module.bpf_object["exit_result"].event(data)
#     age = (event.exit_time - event.start_time) / 1e9
#     print("TIME:%-16d TASK:%-16s PID:%-7d PPID:%-7d AGE:%-7.2f " %
#               (event.exit_time, event.task.decode(), event.pid, event.ppid, age), end="")
#     if event.sig_info == 0:
#         print("0" if event.exit_code == 0 else "code:%d" % event.exit_code)
#     else:
#         sig = event.sig_info & 0x7F
#         if sig:
#             print("signal %d (%s)" % (sig, comm_module.signum_to_signame(sig)), end="")
#         if event.sig_info & 0x80:
#             print(", core dumped ", end="")
#         print()
#     if(event.terminate == 1):
#         return
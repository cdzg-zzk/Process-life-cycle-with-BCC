from __future__ import print_function
from bcc import BPF
import comm_module
import os
import time
import sys
from bcc.utils import printb

def process_bpf_text(bpf_text):
    raw_text = comm_module.read_file(file_name="file_latency", HONG="FILE_LATENCY")
    bpf_text = raw_text + '\n' + bpf_text
    return bpf_text

def attach_probe(bpf_object):
    pass



    # try:
    #     bpf_object.attach_kprobe(event="__vfs_read", fn_name="trace_read_entry")
    #     bpf_object.attach_kretprobe(event="__vfs_read", fn_name="trace_read_return")
    # except Exception:
    #     print('Current kernel does not have __vfs_read, try vfs_read instead')
    #     bpf_object.attach_kprobe(event="vfs_read", fn_name="trace_read_entry")
    #     bpf_object.attach_kretprobe(event="vfs_read", fn_name="trace_read_return")
    # try:
    #     bpf_object.attach_kprobe(event="__vfs_write", fn_name="trace_write_entry")
    #     bpf_object.attach_kretprobe(event="__vfs_write", fn_name="trace_write_return")
    # except Exception:
    #     print('Current kernel does not have __vfs_write, try vfs_write instead')
    #     bpf_object.attach_kprobe(event="vfs_write", fn_name="trace_write_entry")
    #     bpf_object.attach_kretprobe(event="vfs_write", fn_name="trace_write_return")


# def open_poll_buffer(bpf_object):
#     bpf_object["events"].open_perf_buffer(print_event, page_cnt=64)
#     print("%-8s %-14s %-6s %1s %-7s %7s %s" % ("TIME(s)", "COMM", "TID", "D",
#         "BYTES", "LAT(ms)", "FILENAME"))

mode_s = {
    0: 'R',
    1: 'W',
}
file_type = {
    0: 'UNKNOW',
    1: 'FIFO',
    2: 'CHR',
    4: 'DIR',
    6: 'BLK',
    8: 'REG',
    10: 'LNK',
    12: 'SOCK',
    14: 'WHT',
}
def process_data():
    sys.stdout = open('/usr/share/bcc/Process-life-cycle-with-BCC/timeline.txt', 'a')
    rw_queue = comm_module.bpf_object["rw_queue"]
    open_queue = comm_module.bpf_object["open_queue"]
    close_queue = comm_module.bpf_object["close_queue"]
    for i,v in enumerate(rw_queue.values()):
        print("TIME: %-12d %s:  EVENT: <FILE SYSTEM>: TYPE: %s  FILE: %-10s" % (v.start_timestamp - comm_module.start_timestamp, 
                                                                            comm_module.prefix_str, mode_s[v.mode],
                                                                            v.filename.decode('utf-8','replace')))
        print("TIME: %-12d %s:  EVENT: <FILE SYSTEM>: TYPE: %s  FILE: %-10s  FD: %d  SIZE: %-4d  LATENCY: %d" % (v.timestamp - comm_module.start_timestamp, 
                                                                            comm_module.prefix_str, mode_s[v.mode],
                                                                            v.filename.decode('utf-8','replace'), v.fd, 
                                                                            v.ret, v.lat))
    for i,v in enumerate(open_queue.values()):
        print("TIME: %-12d %s:  EVENT: <FILE SYSTEM>: OPEN FILE  FILE: %-12s  TYPE: %-5s  FD: %d" % (v.timestamp - comm_module.start_timestamp, 
                                                                            comm_module.prefix_str,
                                                                            v.filename.decode(), file_type[v.type], v.fd))

    for i,v in enumerate(close_queue.values()):
        print("TIME: %-12d %s:  EVENT: <FILE SYSTEM>: CLOSE FILE  FILE: %-12s  FD: %d  AGE: %d" % (v.timestamp - comm_module.start_timestamp, 
                                                                            comm_module.prefix_str,
                                                                            v.filename.decode(), v.fd, v.age))
    sys.stdout = sys.__stdout__        
# start_ts = time.time()
# DNAME_INLINE_LEN = 32 

# def print_event(cpu, data, size):
#     event = comm_module.bpf_object["events"].event(data)

#     ms = float(event.delta_us) / 1000
#     name = event.name.decode('utf-8', 'replace')
#     if event.name_len > DNAME_INLINE_LEN:
#         name = name[:-3] + "..."

#     print("%-8.3f %-14.14s %-6s %1s %-7s %7.2f %s" % (
#         time.time() - start_ts, event.comm.decode('utf-8', 'replace'),
#         event.pid, mode_s[event.mode], event.sz, ms, name))
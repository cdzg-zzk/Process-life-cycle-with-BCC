from __future__ import print_function
from sys import stderr
from bcc import BPF
import comm_module
import os
from bcc import BPF




def process_bpf_text(bpf_text):
    raw_text = comm_module.read_file(file_name="biostat", HONG="BIOSTAT")
    if BPF.kernel_struct_has_field(b'request', b'rq_disk') == 1:
        raw_text = raw_text.replace('__RQ_DISK__', 'rq_disk')
    else:
        raw_text = raw_text.replace('__RQ_DISK__', 'q->disk')
    bpf_text = bpf_text + raw_text
    return bpf_text


# attach BPF probe
def attach_probe(bpf_object):
    if BPF.get_kprobe_functions(b'__blk_account_io_start'):
        bpf_object.attach_kprobe(event="__blk_account_io_start", fn_name="trace_pid_start")
    elif BPF.get_kprobe_functions(b'blk_account_io_start'):
        bpf_object.attach_kprobe(event="blk_account_io_start", fn_name="trace_pid_start")
    else:
        bpf_object.attach_tracepoint(tp="block:block_io_start", fn_name="trace_pid_start_tp")
    if BPF.get_kprobe_functions(b'blk_start_request'):
        bpf_object.attach_kprobe(event="blk_start_request", fn_name="trace_req_start")
    bpf_object.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")
    if BPF.get_kprobe_functions(b'__blk_account_io_done'):
        bpf_object.attach_kprobe(event="__blk_account_io_done", fn_name="trace_req_completion")
    elif BPF.get_kprobe_functions(b'blk_account_io_done'):
        bpf_object.attach_kprobe(event="blk_account_io_done", fn_name="trace_req_completion")
    else:
        bpf_object.attach_tracepoint(tp="block:block_io_done", fn_name="trace_req_completion_tp")


# cache disk major,minor -> diskname
diskstats = "/proc/diskstats"
disklookup = {}

def open_poll_buffer(bpf_object):
    bpf_object["bio_stat_events"].open_perf_buffer(print_bio_event, page_cnt=64)
    # header
    # print("%-11s %-14s %-7s %-9s %-1s %-20s %-7s" % ("TIME(s)", "COMM", "PID",
    #     "DISK", "T", "SECTOR", "BYTES"), end="")
    # print("%7s " % ("QUE(ms)"), end="")
    # print("%7s" % "LAT(ms)")

    with open(diskstats) as stats:
        for line in stats:
            a = line.split()
            disklookup[a[0] + "," + a[1]] = a[2]


rwflg = ""
start_ts = 0
delta = 0
def disk_print(d):
    major = d >> 20
    minor = d & ((1 << 20) - 1)

    disk = str(major) + "," + str(minor)
    if disk in disklookup:
        diskname = disklookup[disk]
    else:
        diskname = "<unknown>"
    return diskname

# process event
def print_bio_event(cpu, data, size):
    event = comm_module.bpf_object["bio_stat_events"].event(data)

    global start_ts
    if start_ts == 0:
        start_ts = event.ts

    if event.rwflag == 1:
        rwflg = "W"
    else:
        rwflg = "R"

    delta = float(event.ts) - start_ts
    disk_name = disk_print(event.dev)

    print("TIME:%-11.6f COMM:%-14.14s PID:%-7s DISK:%-9s TYPE%-1s SECTOR:%-20d SIZE:%-6s QUE:%7.2f LAT:%7.2f" % (
        delta / 1000000, event.name.decode('utf-8', 'replace'), event.pid,
        disk_name, rwflg, event.sector, event.len,
        (float(event.qdelta) / 1000000), (float(event.delta) / 1000000)))

    # print("QUE:%7.2f " % (float(event.qdelta) / 1000000), end="")
    # print("LAT:%7.2f" % (float(event.delta) / 1000000))

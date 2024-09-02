from __future__ import print_function
from sys import stderr
from bcc import BPF
import comm_module
import os
from bcc import BPF, PerfType, PerfHWConfig

def process_bpf_text(bpf_text):
    raw_text = "#define OFFCPU\n" + bpf_text
    script_path = os.path.abspath(__file__)
    script_directory = os.path.dirname(script_path)
    script_directory = script_directory.replace('mybpf_py', 'mybpf_c')
    file_path = script_directory + "/softirqs.c"
    # 打开文件
    with open(file_path, "r") as file:
        # 读取文件内容
        raw_text = raw_text + file.read()
    # other operation
    raw_text += bpf_text
    return raw_text

def attach_probe(bpf_object):
    sample_period = 50
    try:
        bpf_object.attach_perf_event(
            ev_type=PerfType.HARDWARE, ev_config=PerfHWConfig.CACHE_MISSES,
            fn_name="on_cache_miss", sample_period=sample_period)
        bpf_object.attach_perf_event(
            ev_type=PerfType.HARDWARE, ev_config=PerfHWConfig.CACHE_REFERENCES,
            fn_name="on_cache_ref", sample_period=sample_period)
    except Exception:
        print("Failed to attach to a hardware event. Is this a virtual machine?")
        return


def process_data():
    miss_count = {}
    for (k, v) in comm_module.bpf_object.get_table('miss_count').items():
        miss_count[(k.pid, k.cpu, k.name)] = v.value

    header_text = 'PID      '
    format_text = '{:<8d} '

    header_text += 'NAME             CPU     REFERENCE         MISS    HIT%'
    format_text += '{:<16s} {:<4d} {:>12d} {:>12d} {:>6.2f}%'

    print(header_text)
    tot_ref = 0
    tot_miss = 0
    for (k, v) in comm_module.bpf_object.get_table('ref_count').items():
        try:
            miss = miss_count[(k.pid, k.cpu, k.name)]
        except KeyError:
            miss = 0
        tot_ref += v.value
        tot_miss += miss
        # This happens on some PIDs due to missed counts caused by sampling
        hit = (v.value - miss) if (v.value >= miss) else 0

        print(format_text.format(
            k.pid, k.name.decode('utf-8', 'replace'), k.cpu, v.value, miss,
            (float(hit) / float(v.value)) * 100.0))
    print('Total References: {} Total Misses: {} Hit Rate: {:.2f}%'.format(
        tot_ref, tot_miss, (float(tot_ref - tot_miss) / float(tot_ref)) * 100.0))


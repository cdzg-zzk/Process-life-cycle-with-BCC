from __future__ import print_function
from bcc import BPF
import comm_module
import os

def process_bpf_text(bpf_text):
    raw_text = "#define EXIT_T\n" + bpf_text
    script_path = os.path.abspath(__file__)
    script_directory = os.path.dirname(script_path)
    script_directory = script_directory.replace('mybpf_py', 'mybpf_c')
    file_path = script_directory + "/exit.c"
    # 打开文件
    with open(file_path, "r") as file:
        # 读取文件内容
        raw_text = raw_text + file.read()
    # other operation
    return raw_text

def attach_probe(bpf_object):
    pass

def open_poll_buffer(bpf_object):
    bpf_object["exit_result"].open_perf_buffer(print_exit_events)

def print_exit_events(ctx, data, size):
    event = comm_module.bpf_object["exit_result"].event(data)
    age = (event.exit_time - event.start_time) / 1e9
    print("TASK:%-16s (PID:%-7d PPID:%-7d) [AGE:%-7.2f] " %
              (event.task.decode(), event.pid, event.ppid, age), end="")
    if event.sig_info == 0:
        print("0" if event.exit_code == 0 else "code:%d" % event.exit_code)
    else:
        sig = event.sig_info & 0x7F
        if sig:
            print("signal %d (%s)" % (sig, comm_module.signum_to_signame(sig)), end="")
        if event.sig_info & 0x80:
            print(", core dumped ", end="")
        print()
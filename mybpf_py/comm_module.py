from __future__ import print_function
from bcc import BPF

import time
import signal
from datetime import datetime, timedelta
from bcc.syscall import syscall_name, syscalls
import re
import os

def init_bpf_object(bpf_text):
    max_pid = int(open("/proc/sys/kernel/pid_max").read())
    global bpf_object
    bpf_object = BPF(text=bpf_text, cflags=["-DMAX_PID=%d" % max_pid])

def read_file(bpf_text, file_name, HONG):
    script_path = os.path.abspath(__file__)
    script_directory = os.path.dirname(script_path)
    script_directory = script_directory.replace('mybpf_py', 'mybpf_c')
    file_path = script_directory + "/" + file_name + ".c"
    print(file_path)
    raw_text = "#define " + HONG + "\n" + bpf_text
    # 打开文件
    with open(file_path, "r") as file:
        # 读取文件内容
        raw_text = raw_text + file.read()
    # other operation
    return raw_text
SIGNUM_TO_SIGNAME = dict((v, re.sub("^SIG", "", k))
    for k,v in signal.__dict__.items() if re.match("^SIG[A-Z]+$", k))
def signum_to_signame(signum):
    """Return the name of the signal corresponding to signum."""
    return SIGNUM_TO_SIGNAME.get(signum, "unknown")
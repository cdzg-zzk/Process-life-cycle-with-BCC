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


SIGNUM_TO_SIGNAME = dict((v, re.sub("^SIG", "", k))
    for k,v in signal.__dict__.items() if re.match("^SIG[A-Z]+$", k))
def signum_to_signame(signum):
    """Return the name of the signal corresponding to signum."""
    return SIGNUM_TO_SIGNAME.get(signum, "unknown")
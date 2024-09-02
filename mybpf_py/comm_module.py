from __future__ import print_function
from bcc import BPF

import time
import signal
from datetime import datetime, timedelta
from bcc.syscall import syscall_name, syscalls
import re
import os

process_state_mapping = {
    0: 'TASK_RUNNING',
    1: 'TASK_INTERRUPTIBLE',
    2: 'TASK_UNINTERRUPTIBLE',
    4: '__TASK_STOPPED',
    8: '__TASK_TRACED',
    # Used in tsk->exit_state:
    16: 'EXIT_DEAD',
    32: 'EXIT_ZOMBIE',
    48: 'EXIT_TRACE',
    128: 'TASK_DEAD',
    258: 'TASK_KILLABLE',
    1026: 'TASK_IDLE',
    2048: 'TASK_NEW',
}
signal_list = [
    "SIGHUP",
    "SIGINT",
    "SIGQUIT",
    "SIGILL",
    "SIGTRAP",
    "SIGABRT",
    "SIGBUS",
    "SIGFPE",
    "SIGKILL",
    "SIGUSR1",
    "SIGSEGV",
    "SIGUSR2",
    "SIGPIPE",
    "SIGALRM",
    "SIGTERM",
    "SIGSTKFLT",
    "SIGCHLD",
    "SIGCONT",
    "SIGSTOP",
    "SIGTSTP",
    "SIGTTIN",
    "SIGTTOU",
    "SIGURG",
    "SIGXCPU",
    "SIGXFSZ",
    "SIGVTALRM",
    "SIGPROF",
    "SIGWINCH",
    "SIGIO",
    "SIGPWR",
    "SIGSYS"
]
def init_bpf_object(bpf_text):
    max_pid = int(open("/proc/sys/kernel/pid_max").read())
    global bpf_object
    global start_timestamp
    start_timestamp = time.perf_counter_ns()
    bpf_object = BPF(text=bpf_text, cflags=["-DMAX_PID=%d" % max_pid])

# def read_file(bpf_text, file_name, HONG):
def read_file(file_name, HONG):
    script_path = os.path.abspath(__file__)
    script_directory = os.path.dirname(script_path)
    script_directory = script_directory.replace('mybpf_py', 'mybpf_c')
    file_path = script_directory + "/" + file_name + ".c"
    print(file_path)
    # raw_text = "#define " + HONG + "\n" + bpf_text
    raw_text = "#define " + HONG + "\n"
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


def pid_to_comm(pid):
    try:
        comm = open("/proc/%d/comm" % pid, "r").read()
        ret_str = "%d %s" % (pid, comm)
        return ret_str.rstrip("\n")
    except IOError:
        return str(pid)
    
global prefix_str
prefix_str = "COMM: {} PID: {}"

global comm
comm = ""
global id
id = -1

global continuing
continuing = 0

global end_process_time
end_process_time = 0

global start_process_time
start_process_time = 0

def Init_SIGINT(signal_handler):
    signal.signal(signal.SIGINT, signal_handler)
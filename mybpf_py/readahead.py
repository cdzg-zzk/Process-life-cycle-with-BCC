from __future__ import print_function
from sys import stderr
from bcc import BPF
import comm_module
from bcc import BPF
import ctypes as ct


def process_bpf_text(bpf_text):
    raw_text = comm_module.read_file(file_name="readahead", HONG="READAHEAD")
    ra_func = "do_page_cache_ra"
    bpf_text += raw_text.replace("RA_FUNC", ra_func)
    return bpf_text

def attach_probe(bpf_object):
    pass



# check whether hash table batch ops is supported
htab_batch_ops = True if BPF.kernel_struct_has_field(b'bpf_map_ops',
        b'map_lookup_and_delete_batch') == 1 else False
def process_data():
    print()
    print("Read-ahead unused pages: %d" % (comm_module.bpf_object["pages"][ct.c_ulong(0)].value))
    print("Histogram of read-ahead used page age (ms):")
    print("")
    comm_module.bpf_object["dist"].print_log2_hist("age (ms)")

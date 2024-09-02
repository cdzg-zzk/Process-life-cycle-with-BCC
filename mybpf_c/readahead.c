#include <uapi/linux/ptrace.h>
#include <linux/mm_types.h>
#include <linux/mm.h>

BPF_HASH(flag, u32, u8);            // used to track if we are in do_page_cache_readahead()
BPF_HASH(birth, struct page*, u64); // used to track timestamps of cache alloc'ed page
BPF_ARRAY(pages);                   // increment/decrement readahead pages
BPF_HISTOGRAM(dist);

KFUNC_PROBE(RA_FUNC)
{
    BUILD_TARGET_PID

    u32 pid = bpf_get_current_pid_tgid();
    // if(pid != target_pid){
    //     return 0;
    // }
    u8 one = 1;

    flag.update(&pid, &one);
    return 0;
}

KRETFUNC_PROBE(RA_FUNC)
{
    BUILD_TARGET_PID

    u32 pid = bpf_get_current_pid_tgid();
    // if(pid != target_pid){
    //     return 0;
    // }
    u8 zero = 0;

    flag.update(&pid, &zero);
    return 0;
}

KFUNC_PROBE(mark_page_accessed, struct page *arg0)
{
    u64 ts, delta;
    u32 zero = 0; // static key for accessing pages[0]
    u64 *bts = birth.lookup(&arg0);

    if (bts != NULL) {
        delta = bpf_ktime_get_ns() - *bts;
        dist.atomic_increment(bpf_log2l(delta/1000000));
        pages.atomic_increment(zero, -1);
        birth.delete(&arg0); // remove the entry from hashmap
    }
    return 0;
}


KRETFUNC_PROBE(__page_cache_alloc, gfp_t gfp, struct page *retval)
{
    u64 ts;
    u32 zero = 0; // static key for accessing pages[0]
    u32 pid = bpf_get_current_pid_tgid();
    u8 *f = flag.lookup(&pid);

    if (f != NULL && *f == 1) {
        ts = bpf_ktime_get_ns();
        birth.update(&retval, &ts);
        pages.atomic_increment(zero);
    }
    return 0;
}

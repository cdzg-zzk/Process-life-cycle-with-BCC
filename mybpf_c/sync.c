
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

struct sync_data_t {
    u64 ts;
};

BPF_PERF_OUTPUT(sync_result);

void syscall__sync(void *ctx) {
    struct sync_data_t data = {};
    data.ts = bpf_ktime_get_ns() / 1000;
    sync_result.perf_submit(ctx, &data, sizeof(data));
};
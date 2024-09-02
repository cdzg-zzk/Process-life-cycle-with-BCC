#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>
// biosnoop
// for saving the timestamp and __data_len of each request
struct start_req_t {
    u64 ts;
    u64 data_len;
};

struct bio_val_t {
    u64 ts;
    u32 pid;
    char name[TASK_COMM_LEN];
};

struct bio_tp_args {
    u64 __unused__;
    dev_t dev;
    sector_t sector;
    unsigned int nr_sector;
    unsigned int bytes;
    char rwbs[8];
    char comm[16];
    char cmd[];
};

struct bio_hash_key {
    dev_t dev;
    u32 rwflag;
    sector_t sector;
};

struct bio_stat_data_t {
    u32 pid;
    u32 dev;
    u64 rwflag;
    u64 delta;
    u64 qdelta;
    u64 sector;
    u64 len;
    u64 ts;
    char name[TASK_COMM_LEN];
};


BPF_HASH(req_start, struct bio_hash_key, struct start_req_t);
BPF_HASH(infobyreq, struct bio_hash_key, struct bio_val_t);
BPF_PERF_OUTPUT(bio_stat_events);

static dev_t ddevt(struct gendisk *disk) {
    return (disk->major  << 20) | disk->first_minor;
}

static int get_rwflag(u32 cmd_flags) {
#ifdef REQ_WRITE
    return !!(cmd_flags & REQ_WRITE);
#elif defined(REQ_OP_SHIFT)
    return !!((cmd_flags >> REQ_OP_SHIFT) == REQ_OP_WRITE);
#else
    return !!((cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);
#endif
}

#define RWBS_LEN	8

static int get_rwflag_tp(char *rwbs) {
    for (int i = 0; i < RWBS_LEN; i++) {
        if (rwbs[i] == 'W')
            return 1;
        if (rwbs[i] == '\0')
            return 0;
    }
    return 0;
}

// cache PID and comm by-req
static int __trace_pid_start(struct bio_hash_key key)
{
    struct bio_val_t val = {};
    u64 ts;

    if (bpf_get_current_comm(&val.name, sizeof(val.name)) == 0) {
        val.pid = bpf_get_current_pid_tgid() >> 32;
        val.ts = bpf_ktime_get_ns();
        infobyreq.update(&key, &val);
    }
    return 0;
}


int trace_pid_start(struct pt_regs *ctx, struct request *req)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct bio_hash_key key = {
        .dev = ddevt(req->__RQ_DISK__),
        .rwflag = get_rwflag(req->cmd_flags),
        .sector = req->__sector
    };

    return __trace_pid_start(key);
}

int trace_pid_start_tp(struct bio_tp_args *args)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct bio_hash_key key = {
        .dev = args->dev,
        .rwflag = get_rwflag_tp(args->rwbs),
        .sector = args->sector
    };

    return __trace_pid_start(key);
}

// time block I/O
int trace_req_start(struct pt_regs *ctx, struct request *req)
{
    BUILD_TARGET_PID
    u32 pid = bpf_get_current_pid_tgid();
    // if(pid != target_pid) {
    //     return 0;
    // }
    struct bio_hash_key key = {
        .dev = ddevt(req->__RQ_DISK__),
        .rwflag = get_rwflag(req->cmd_flags),
        .sector = req->__sector
    };

    struct start_req_t start_req = {
        .ts = bpf_ktime_get_ns(),
        .data_len = req->__data_len
    };
    req_start.update(&key, &start_req);
    return 0;
}

// output
static int __trace_req_completion(void *ctx, struct bio_hash_key key)
{
    struct start_req_t *startp;
    struct bio_val_t *valp;
    struct bio_stat_data_t data = {};
    //struct gendisk *rq_disk;
    u64 ts;

    // fetch timestamp and calculate delta
    startp = req_start.lookup(&key);
    if (startp == 0) {
        // missed tracing issue
        return 0;
    }
    ts = bpf_ktime_get_ns();
    //rq_disk = req->__RQ_DISK__;
    data.delta = ts - startp->ts;
    data.ts = ts / 1000;
    data.qdelta = 0;
    data.len = startp->data_len;

    valp = infobyreq.lookup(&key);
    if (valp == 0) {
        data.name[0] = '?';
        data.name[1] = 0;
    } else {
        data.qdelta = startp->ts - valp->ts;
        data.pid = valp->pid;
        data.sector = key.sector;
        data.dev = key.dev;
        bpf_probe_read_kernel(&data.name, sizeof(data.name), valp->name);
    }
    data.rwflag = key.rwflag;

    bio_stat_events.perf_submit(ctx, &data, sizeof(data));
    req_start.delete(&key);
    infobyreq.delete(&key);

    return 0;
}

int trace_req_completion(struct pt_regs *ctx, struct request *req)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct bio_hash_key key = {
        .dev = ddevt(req->__RQ_DISK__),
        .rwflag = get_rwflag(req->cmd_flags),
        .sector = req->__sector
    };

    return __trace_req_completion(ctx, key);
}

int trace_req_completion_tp(struct bio_tp_args *args)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct bio_hash_key key = {
        .dev = args->dev,
        .rwflag = get_rwflag_tp(args->rwbs),
        .sector = args->sector
    };

    return __trace_req_completion(args, key);
}
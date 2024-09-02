#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/dcache.h>
#include <uapi/linux/limits.h>


enum trace_fileop_mode {
    MODE_READ,
    MODE_WRITE
};
struct rw_event_data {
    enum trace_fileop_mode mode;
    int fd;
    u32 pid;
    u64 start_timestamp;
    u64 timestamp;
    u64 lat;
    long ret;
    char filename[DNAME_INLINE_LEN];
};
BPF_HASH(read_event, u32, struct rw_event_data);
BPF_QUEUE(rw_queue, struct rw_event_data, 1024);
TRACEPOINT_PROBE(syscalls, sys_enter_read)
{
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    struct file *file;
    // char filename[DNAME_INLINE_LEN];
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    BUILD_TARGET_PID
    if(target_pid != pid) {
        return 0;
    }
    u64 ts = bpf_ktime_get_ns();
    // Get the file pointer
    struct fdtable* fdtablep;
    struct file** fd;
    bpf_probe_read_kernel(&fdtablep, sizeof(fdtablep), &task->files->fdt);
    bpf_probe_read_kernel(&fd, sizeof(fd), &fdtablep->fd);
    bpf_probe_read_kernel(&file, sizeof(file), &fd[args->fd]);
    // bpf_probe_read_kernel(&file, sizeof(file), &task->files->fdt->fd[args->fd]);

    // Get the filename
    struct rw_event_data data = {};
    data.mode = MODE_READ;
    data.pid = pid;
    data.lat = ts;
    data.start_timestamp = ts;
    data.fd = args->fd;
    struct qstr qs= {};
    struct dentry* dtry;
    bpf_probe_read_kernel(&dtry, sizeof(dtry), &file->f_path.dentry);
    bpf_probe_read_kernel(&qs, sizeof(qs), &dtry->d_name);
    if(qs.len == 0) {
        return 0;
    }
    bpf_probe_read_kernel(&data.filename, sizeof(data.filename), qs.name);
    read_event.update(&pid, &data);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_read)
{
    u64 ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    BUILD_TARGET_PID
    if(target_pid != pid) {
        return 0;
    }
    long ret = args->ret;
    if(ret < 0) {
        return 0;
    }
    struct rw_event_data *datap = read_event.lookup(&pid);
    if(!datap) {
        return 0;
    }
    datap->timestamp = ts;
    datap->ret = args->ret;
    datap->lat = ts - datap->lat;
    rw_queue.push(datap, BPF_EXIST);
    return 0;
}



BPF_HASH(write_event, u32, struct rw_event_data);
TRACEPOINT_PROBE(syscalls, sys_enter_write)
{
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    struct file *file;
    // char filename[DNAME_INLINE_LEN];
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    BUILD_TARGET_PID
    if(target_pid != pid) {
        return 0;
    }
    u64 ts = bpf_ktime_get_ns();
    // Get the file pointer
    struct fdtable* fdtablep;
    struct file** fd;
    bpf_probe_read_kernel(&fdtablep, sizeof(fdtablep), &task->files->fdt);
    bpf_probe_read_kernel(&fd, sizeof(fd), &fdtablep->fd);
    bpf_probe_read_kernel(&file, sizeof(file), &fd[args->fd]);
    // bpf_probe_read_kernel(&file, sizeof(file), &task->files->fdt->fd[args->fd]);

    // Get the filename
    struct rw_event_data data = {};
    data.mode = MODE_WRITE;
    data.pid = pid;
    data.start_timestamp = ts;
    data.lat = ts;
    data.fd = args->fd;
    struct qstr qs= {};
    struct dentry* dtry;
    bpf_probe_read_kernel(&dtry, sizeof(dtry), &file->f_path.dentry);
    bpf_probe_read_kernel(&qs, sizeof(qs), &dtry->d_name);
    if(qs.len == 0) {
        return 0;
    }
    bpf_probe_read_kernel(&data.filename, sizeof(data.filename), qs.name);
    write_event.update(&pid, &data);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_write)
{
    u64 ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    BUILD_TARGET_PID
    if(target_pid != pid) {
        return 0;
    }
    long ret = args->ret;
    if(ret < 0) {
        return 0;
    }
    struct rw_event_data *datap = write_event.lookup(&pid);
    if(!datap) {
        return 0;
    }
    datap->timestamp = ts;
    datap->ret = args->ret;
    datap->lat = ts - datap->lat;
    rw_queue.push(datap, BPF_EXIST);
    return 0;
}




struct open_data_t {
    u64 timestamp;
    // u32 pid;
    int fd;
    int type;
    // char comm[TASK_COMM_LEN];
    char filename[NAME_MAX];
    int flags; // EXTENDED_STRUCT_MEMBER
};

BPF_QUEUE(open_queue, struct open_data_t, 1024);
struct file_key {
    u32 pid;
    int fd;
};
BPF_HASH(start_file, struct file_key, u64);
// BPF_PERCPU_HASH(node, struct inode);
static int body(const char __user *filename, int flags, int ret) {
    
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part

    BUILD_TARGET_PID
    if(pid != target_pid) {
        return 0;
    }
    struct open_data_t data = {};
    // bpf_get_current_comm(&data.comm, sizeof(data.comm));

    u64 ts = bpf_ktime_get_ns();

    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)filename);
    data.timestamp    = ts;
    // data.pid   = bpf_get_current_pid_tgid();
    data.flags = flags; // EXTENDED_STRUCT_MEMBER
    data.fd   = ret;

    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    struct file *file;
    struct fdtable* fdtablep;
    struct file** fd;
    struct files_struct* files;
    bpf_probe_read_kernel(&files, sizeof(files), &task->files);
    bpf_probe_read_kernel(&fdtablep, sizeof(fdtablep), &files->fdt);
    bpf_probe_read_kernel(&fd, sizeof(fd), &fdtablep->fd);
    bpf_probe_read_kernel(&file, sizeof(file), &fd[ret]);

    int mode;
    struct inode* nodep;
    bpf_probe_read_kernel(&nodep, sizeof(nodep), &file->f_inode);
    bpf_probe_read_kernel(&mode, sizeof(mode), &nodep->i_mode);
    mode = (mode >> 12) & 15;
    data.type = mode;
    open_queue.push(&data, BPF_EXIST);
    struct file_key key = {};
    key.pid = pid;
    key.fd = ret;
    start_file.update(&key, &ts);
    return 0;
}

#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER) && !defined(__s390x__)
KRETFUNC_PROBE(__x64_sys_open, struct pt_regs *regs, int ret)
{
    const char __user *filename = (char *)PT_REGS_PARM1(regs);
    int flags = PT_REGS_PARM2(regs);
    return body(filename, flags, ret);
}
#else
KRETFUNC_PROBE(__x64_sys_open, const char __user *filename, int flags, int ret)
{
    return body(filename, flags, ret);
}
#endif

#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER) && !defined(__s390x__)
KRETFUNC_PROBE(__x64_sys_openat, struct pt_regs *regs, int ret)
{
    int dfd = PT_REGS_PARM1(regs);
    const char __user *filename = (char *)PT_REGS_PARM2(regs);
    int flags = PT_REGS_PARM3(regs);
    return body(filename, flags, ret);
}
#else
KRETFUNC_PROBE(__x64_sys_openat, int dfd, const char __user *filename, int flags, int ret)
{
    return body(filename, flags, ret);
}
#endif


#include <uapi/linux/openat2.h>
#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER) && !defined(__s390x__)
KRETFUNC_PROBE(__x64_sys_openat2, struct pt_regs *regs, int ret)
{
    int dfd = PT_REGS_PARM1(regs);
    const char __user *filename = (char *)PT_REGS_PARM2(regs);
    struct open_how __user how;
    int flags;

    bpf_probe_read_user(&how, sizeof(struct open_how), (struct open_how*)PT_REGS_PARM3(regs));
    flags = how.flags;
    return body(filename, flags, ret);
}
#else
KRETFUNC_PROBE(__x64_sys_openat2, int dfd, const char __user *filename, struct open_how __user *how, int ret)
{
    int flags = how->flags;
    return body(filename, flags, ret);
}
#endif





struct close_data_t{
    int fd;
    int age;
    u64 timestamp;
    char filename[NAME_MAX];
};
BPF_QUEUE(close_queue, struct close_data_t, 1024);

KFUNC_PROBE(__x64_sys_close, struct pt_regs *regs)
{
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    struct file *file;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    BUILD_TARGET_PID
    if(target_pid != pid) {
        return 0;
    }
    int fd = PT_REGS_PARM1(regs);
    u64 ts = bpf_ktime_get_ns();
    // Get the file pointer
    struct fdtable* fdtablep;
    struct file** fdpptr;
    struct files_struct* files;
    bpf_probe_read_kernel(&files, sizeof(files), &task->files);
    bpf_probe_read_kernel(&fdtablep, sizeof(fdtablep), &files->fdt);
    bpf_probe_read_kernel(&fdpptr, sizeof(fdpptr), &fdtablep->fd);
    bpf_probe_read_kernel(&file, sizeof(file), &fdpptr[fd]);
    // bpf_probe_read_kernel(&file, sizeof(file), &task->files->fdt->fd[args->fd]);

    // Get the filename
    struct qstr qs= {};
    struct dentry* dtry;
    bpf_probe_read_kernel(&dtry, sizeof(dtry), &file->f_path.dentry);
    bpf_probe_read_kernel(&qs, sizeof(qs), &dtry->d_name);    

    struct close_data_t data = {};
    data.timestamp = ts;
    data.fd = fd;
    bpf_probe_read_kernel(&data.filename, sizeof(data.filename), qs.name);
    bpf_trace_printk("filename: %s", data.filename);
    struct file_key key = {};
    key.pid = pid;
    key.fd = fd;
    u64* tsp = start_file.lookup(&key);
    if(tsp == NULL) {
        return 0;
    }
    start_file.delete(&key);
    data.age = ts - *tsp;
    close_queue.push(&data, BPF_EXIST);

    return 0;
}
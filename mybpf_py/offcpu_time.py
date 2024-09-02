from __future__ import print_function
from sys import stderr
from bcc import BPF
import comm_module
import os
import errno

def process_bpf_text(bpf_text):
    raw_text = comm_module.read_file("offcpu_time", "OFFCPU")
    # other operation
    kernel_stack_get = "stack_traces.get_stackid(ctx, 0)"
    user_stack_get = "stack_traces.get_stackid(ctx, BPF_F_USER_STACK)"
    raw_text = raw_text.replace('USER_STACK_GET', user_stack_get)
    raw_text = raw_text.replace('KERNEL_STACK_GET', kernel_stack_get)
    bpf_text = raw_text + bpf_text
    return bpf_text

def attach_probe(bpf_object):
    bpf_object.attach_kprobe(event_re=r'^finish_task_switch$|^finish_task_switch\.isra\.\d$',
                fn_name="oncpu")


def stack_id_err(stack_id):
    # -EFAULT in get_stackid normally means the stack-trace is not available,
    # Such as getting kernel stack trace in userspace code
    return (stack_id < 0) and (stack_id != -errno.EFAULT)

def process_data():
    show_offset = False
    missing_stacks = 0
    has_enomem = False
    counts = comm_module.bpf_object.get_table("counts")
    stack_traces = comm_module.bpf_object.get_table("stack_traces")
    for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
        # handle get_stackid errors
        if stack_id_err(k.kernel_stack_id):
            missing_stacks += 1
            has_enomem = has_enomem or k.kernel_stack_id == -errno.ENOMEM
        if stack_id_err(k.user_stack_id):
            missing_stacks += 1
            has_enomem = has_enomem or k.user_stack_id == -errno.ENOMEM

        # user stacks will be symbolized by tgid, not pid, to avoid the overhead
        # of one symbol resolver per thread
        user_stack = [] if k.user_stack_id < 0 else \
            stack_traces.walk(k.user_stack_id)
        kernel_stack = [] if k.kernel_stack_id < 0 else \
            stack_traces.walk(k.kernel_stack_id)

        if stack_id_err(k.kernel_stack_id):
            print("    [Missed Kernel Stack]")
        else:
            for addr in kernel_stack:
                print("    %s" % comm_module.bpf_object.ksym(addr, show_offset=show_offset).decode('utf-8', 'replace'))

        if k.user_stack_id >= 0 and k.kernel_stack_id >= 0:
            print("    --")
        if stack_id_err(k.user_stack_id):
            print("    [Missed User Stack]")
        else:
            for addr in user_stack:
                print("    %s" % comm_module.bpf_object.sym(addr, k.tgid, show_offset=show_offset).decode('utf-8', 'replace'))
        print("    %-16s %s (%d)" % ("-", k.name.decode('utf-8', 'replace'), k.pid))
        print("        %d\n" % v.value)

    if missing_stacks > 0:
        enomem_str = "" if not has_enomem else \
            " Consider increasing --stack-storage-size."
        print("WARNING: %d stack traces lost and could not be displayed.%s" %
            (missing_stacks, enomem_str),
            file=stderr)












# # set thread filter
# thread_context = ""
# if args.tgid is not None:
#     thread_context = "PID %d" % args.tgid
#     thread_filter = 'tgid == %d' % args.tgid
# elif args.pid is not None:
#     thread_context = "TID %d" % args.pid
#     thread_filter = 'pid == %d' % args.pid
# elif args.user_threads_only:
#     thread_context = "user threads"
#     thread_filter = '!(prev->flags & PF_KTHREAD)'
# elif args.kernel_threads_only:
#     thread_context = "kernel threads"
#     thread_filter = 'prev->flags & PF_KTHREAD'
# else:
#     thread_context = "all threads"
#     thread_filter = '1'
# if args.state == 0:
#     state_filter = 'prev->STATE_FIELD == 0'
# elif args.state:
#     # these states are sometimes bitmask checked
#     state_filter = 'prev->STATE_FIELD & %d' % args.state
# else:
#     state_filter = '1'
# bpf_text = bpf_text.replace('THREAD_FILTER', thread_filter)
# bpf_text = bpf_text.replace('STATE_FILTER', state_filter)
# if BPF.kernel_struct_has_field(b'task_struct', b'__state') == 1:
#     bpf_text = bpf_text.replace('STATE_FIELD', '__state')
# else:
#     bpf_text = bpf_text.replace('STATE_FIELD', 'state')

# # set stack storage size
# bpf_text = bpf_text.replace('STACK_STORAGE_SIZE', str(args.stack_storage_size))
# bpf_text = bpf_text.replace('MINBLOCK_US_VALUE', str(args.min_block_time))
# bpf_text = bpf_text.replace('MAXBLOCK_US_VALUE', str(args.max_block_time))

# # handle stack args

# stack_context = ""
# if args.user_stacks_only:
#     stack_context = "user"
#     kernel_stack_get = "-1"
# elif args.kernel_stacks_only:
#     stack_context = "kernel"
#     user_stack_get = "-1"
# else:
#     stack_context = "user + kernel"


# need_delimiter = args.delimited and not (args.kernel_stacks_only or
#                                          args.user_stacks_only)

# # check for an edge case; the code below will handle this case correctly
# # but ultimately nothing will be displayed
# if args.kernel_threads_only and args.user_stacks_only:
#     print("ERROR: Displaying user stacks for kernel threads " +
#           "doesn't make sense.", file=stderr)
#     exit(2)


# # header
# if not folded:
#     print("Tracing off-CPU time (us) of %s by %s stack" %
#         (thread_context, stack_context), end="")
#     if duration < 99999999:
#         print(" for %d secs." % duration)
#     else:
#         print("... Hit Ctrl-C to end.")


# def print_warn_event(cpu, data, size):
#     event = b["warn_events"].event(data)
#     # See https://github.com/iovisor/bcc/pull/3227 for those wondering how can this happen.
#     print("WARN: Skipped an event with negative duration: pid:%d, tgid:%d, off-cpu:%d, on-cpu:%d"
#           % (event.pid, event.tgid, event.t_start, event.t_end),
#           file=stderr)


# if not folded:
#     print()

# show_offset = False
# if args.offset:
#     show_offset = True


#     if folded:
#         # print folded stack output
#         user_stack = list(user_stack)
#         kernel_stack = list(kernel_stack)
#         line = [k.name.decode('utf-8', 'replace')]
#         # if we failed to get the stack is, such as due to no space (-ENOMEM) or
#         # hash collision (-EEXIST), we still print a placeholder for consistency
#         if not args.kernel_stacks_only:
#             if stack_id_err(k.user_stack_id):
#                 line.append("[Missed User Stack]")
#             else:
#                 line.extend([b.sym(addr, k.tgid).decode('utf-8', 'replace')
#                     for addr in reversed(user_stack)])
#         if not args.user_stacks_only:
#             line.extend(["-"] if (need_delimiter and k.kernel_stack_id >= 0 and k.user_stack_id >= 0) else [])
#             if stack_id_err(k.kernel_stack_id):
#                 line.append("[Missed Kernel Stack]")
#             else:
#                 line.extend([b.ksym(addr).decode('utf-8', 'replace')
#                     for addr in reversed(kernel_stack)])
#         print("%s %d" % (";".join(line), v.value))
#     else:
#         # print default multi-line stack output
#         if not args.user_stacks_only:
#             if stack_id_err(k.kernel_stack_id):
#                 print("    [Missed Kernel Stack]")
#             else:
#                 for addr in kernel_stack:
#                     print("    %s" % b.ksym(addr, show_offset=show_offset).decode('utf-8', 'replace'))
#         if not args.kernel_stacks_only:
#             if need_delimiter and k.user_stack_id >= 0 and k.kernel_stack_id >= 0:
#                 print("    --")
#             if stack_id_err(k.user_stack_id):
#                 print("    [Missed User Stack]")
#             else:
#                 for addr in user_stack:
#                     print("    %s" % b.sym(addr, k.tgid, show_offset=show_offset).decode('utf-8', 'replace'))
#         print("    %-16s %s (%d)" % ("-", k.name.decode('utf-8', 'replace'), k.pid))
#         print("        %d\n" % v.value)

# if missing_stacks > 0:
#     enomem_str = "" if not has_enomem else \
#         " Consider increasing --stack-storage-size."
#     print("WARNING: %d stack traces lost and could not be displayed.%s" %
#         (missing_stacks, enomem_str),
#         file=stderr)

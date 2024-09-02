from __future__ import print_function
from bcc import BPF
import sys
from enum import Enum

import comm_module
def process_bpf_text(bpf_text):
    raw_text = comm_module.read_file("task_switch", "CONTEXT_SWITCH")
    bpf_text = bpf_text + '\n' + raw_text
    return bpf_text

def attach_probe(bpf_object):
    bpf_object.attach_kprobe(event="finish_task_switch", fn_name="record_switch")
    bpf_object.attach_kretprobe(event="finish_task_switch", fn_name="record_switch_end")
    bpf_object.attach_kprobe(event="ttwu_do_wakeup", fn_name="trace_ttwu_do_wakeup")
    bpf_object.attach_kprobe(event="wake_up_new_task", fn_name="trace_wake_up_new_task")
    bpf_object.attach_kprobe(event="resched_curr", fn_name="trace_resched_curr")
    bpf_object.attach_kprobe(event="scheduler_tick", fn_name="trace_scheduler_tick")
    bpf_object.attach_kretprobe(event="scheduler_tick", fn_name="trace_scheduler_tick_end")
    bpf_object.attach_kretprobe(event="prepare_to_wait_event", fn_name="trace_prepare_to_wait_event_end")
    bpf_object.attach_kprobe(event="finish_wait", fn_name="trace_finish_wait")
    bpf_object.attach_kprobe(event="__wake_up_common", fn_name="trace_wake_up_common")
    
# def open_poll_buffer(bpf_object):
#     bpf_object["switch_result"].open_perf_buffer(print_switch_events)
#     bpf_object["runqueue_result"].open_perf_buffer(print_runq_event)

# def print_switch_events(ctx, data, size):     # 打印进程切换内容
#     event = comm_module.bpf_object["switch_result"].event(data)
#     # print("prev-comm: %-16s  %-10d" % (event.prev_comm, event.duration))
#     print("context-switch: prev-pid: %-5d  %-10d" % (event.prev_pid, event.duration))
#     # time.sleep(1)
#     # event = bpf_switch["switch_result"].event(data)
#     # print("context-switch: %-10d %-16s %-6d %-16s %-6d" % (event.timestamp, event.prev_comm, event.prev_pid,
#     #                                  event.curr_comm, event.curr_pid))
#     # time.sleep(1)

# def print_runq_event(ctx, data, size):
#     event = comm_module.bpf_object["runqueue_result"].event(data)
#     print("run queue: %d" % event.latency)
class ScheduleType(Enum):
    NONE = 0
    SCHEDULE = 1
    PREEMPT_IRQ = 2
    TIMEOUT = 3

def sched_method(need_sched, sched_entry_type):
    method = ""
    if need_sched == 0 and sched_entry_type == ScheduleType.SCHEDULE.value:
        method = "Normal Schedule"
    elif need_sched == 1 and sched_entry_type == ScheduleType.TIMEOUT.value:
        method = "TIMEOUT"
    elif need_sched == 1 and sched_entry_type == ScheduleType.SCHEDULE.value:
        method = "IRQ -> UserSpace"
    elif need_sched == 1 and sched_entry_type == ScheduleType.PREEMPT_IRQ.value:
        method = "IRQ -> Kernel"
    elif need_sched == 1 and sched_entry_type == ScheduleType.NONE.value:
        method = "In Kernel"
    elif need_sched == 0 and sched_entry_type == ScheduleType.NONE.value:
        method = "Normal Schedule"
    else:
        method = "Something Goes Wrong" + str(need_sched) + "  " + str(sched_entry_type)
    return method


def process_data():
    sys.stdout = open('/usr/share/bcc/Process-life-cycle-with-BCC/timeline.txt', 'a')
    
    switch_in_queue = comm_module.bpf_object["switch_in_queue"]
    switch_out_queue = comm_module.bpf_object["switch_out_queue"]
    runqueue_queue = comm_module.bpf_object["runqueue_queue"]
    waitqueue_queue = comm_module.bpf_object["waitqueue_queue"]
    cs_cost_queue = comm_module.bpf_object["cs_cost_queue"]
    # res_queue = comm_module.bpf_object["res_queue"]
    # for i,v in enumerate(res_queue.values()):
    #     print("TIME: %-12d %s:  res: %d" % (v.timestamp - comm_module.start_timestamp, v.res))

   
    for i,v in enumerate(runqueue_queue.values()):
        print("TIME: %-12d %s:  EVENT: <RUN QUEUE LAT>: LAT: %d" % (v.timestamp - comm_module.start_timestamp,
                                                                    comm_module.prefix_str, v.latency))

    for i,v in enumerate(waitqueue_queue.values()):
        process_state = comm_module.process_state_mapping.get(v.state)
        print("TIME: %-12d %s:  EVENT: <WAIT QUEUE LAT>: LAT: %d  WAIT STATE: %s  PID: %d" % (v.timestamp - comm_module.start_timestamp,
                                                                    comm_module.prefix_str, v.latency,
                                                                    process_state, v.pid))
        
    for i,v in enumerate(cs_cost_queue.values()):
        print("TIME: %-12d %s:  EVENT: <CONTEXT SWITCH COST>: COST: %d" % (v.timestamp - comm_module.start_timestamp,
                                                                    comm_module.prefix_str, v.cost))

    # switch_queue = comm_module.bpf_object["switch_queue"]
    for i,v in enumerate(switch_out_queue.values()):
        process_state = comm_module.process_state_mapping.get(v.state)
        if process_state is None:
            # print("v.state: %d" % v.state)
            print(v.state)
            process_state = "<unknow state>"
        print("TIME: %-12d %s:  EVENT: <TASK SWITCH-OUT>: [TARGET_PROC: %-5d %-15s] ==> [PREV_PROC: %-5d %-15s]  PREV STATE: %s  DURATION: %d  METHOD: %s" % (v.timestamp - comm_module.start_timestamp, 
                                                                                                                                comm_module.prefix_str,
                                                                                                                                int(comm_module.id), comm_module.comm,
                                                                                                                                v.next_pid, v.next_comm.decode(),
                                                                                                                                process_state, v.duration, 
                                                                                                                                sched_method(v.need_sched, v.entry))) 
    for i,v in enumerate(switch_in_queue.values()):
        process_state = comm_module.process_state_mapping.get(v.state)
        if process_state is None:
            # print("v.state: %d" % v.state)
            print(v.state)
            process_state = "<unknow state>"
        print("TIME: %-12d %s:  EVENT: <TASK SWITCH-IN>: [PREV_PROC: %-5d %-15s] ==> [TARGET_PROC: %-5d %-15s]  PREV STATE: %s  METHOD: %s" % (v.timestamp - comm_module.start_timestamp, 
                                                                                                                                comm_module.prefix_str,
                                                                                                                                v.prev_pid, v.prev_comm.decode(),
                                                                                                                                int(comm_module.id), comm_module.comm,
                                                                                                                                process_state,
                                                                                                                                sched_method(v.need_sched, v.entry)))
    sys.stdout = sys.__stdout__



#define TASK_RUNNING			0x00000000
#define TASK_INTERRUPTIBLE		0x00000001
#define TASK_UNINTERRUPTIBLE		0x00000002
#define __TASK_STOPPED			0x00000004
#define __TASK_TRACED			0x00000008
#/* Used in tsk->exit_state: */
#define EXIT_DEAD			0x00000010
#define EXIT_ZOMBIE			0x00000020
#define EXIT_TRACE			(EXIT_ZOMBIE | EXIT_DEAD)

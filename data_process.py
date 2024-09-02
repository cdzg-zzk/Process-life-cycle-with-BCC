import re

SYSCALL_pattern = r'SYSTEM CALL:\s*([^\d\s]*)'

def getSYSCALL(line):
    syscall = re.search(SYSCALL_pattern, line)
    if syscall is None:
        print("get syscall" + line)
        exit()
    return syscall.group(1)

pair = ("None", 0, -1)
delete_lines = []
def PrevTextProcess(text):
    line_index = 1
    for line in text:
        line_index += 1
        pattern = r'<(.*?)>'
        event = re.search(pattern, line)
        if event is None:
            print("something wrong in prev text process ", line)
            exit()
        event = event.group(1)
        if event != "SYSCALL":
            continue
        syscall = getSYSCALL(line)
        if line.find("enter"):
            if pair[0] != "None":
                delete_lines.append(pair[2])
            pair[0] = syscall
            pair[1] = 1
            pair[2] = line_index
            continue
        elif line.find("exit"):
            if pair[0] == "None" or pair[0] != syscall:
                delete_lines.append(line_index)
                continue
            pair[0] = "None"
            pair[1] = 0
            pair[2] = -1               
    if pair[0] != "None":
        delete_lines.append(pair[2])

txt_lines = open("D:\Coding\Python\z4.txt").readlines()
PrevTextProcess(txt_lines[2:])
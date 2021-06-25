def trace(task_id, command=None):
    ip = requests.get('https://api.ipify.org').text

    if command==None:
        response = {
                'task_id': task_id,
                "user_output": ip,
                'completed': True
            }
            
        responses.append(response)

    else:

        path = ""

        print("PATH = " + str(command))

        if command == False:
            path = ip
        else:
            path += command + ";" + ip

        response = {
                'task_id': task_id,
                "user_output": path,
                'completed': True
            }
            
        responses.append(response)

def shell(task_id, cmd):
    
    global responses

    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    stdout, stderr = p.communicate()

    resp = ""
    if isinstance(stdout, bytes):
        resp = stdout.decode()
    elif isinstance(stderr, bytes):
        resp = stderr.decode()
    else:
        resp = "Error"


    response = {
            'task_id': task_id,
            "user_output": resp,
            'completed': True
        }
    
    responses.append(response) 

    print("\t- Shell Done")

    return
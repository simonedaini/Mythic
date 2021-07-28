def shell(task_id, cmd):
    
    global responses

    p = Popen(cmd.split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
    output = p.communicate()

    response = {
            'task_id': task_id,
            "user_output": str(output),
            'completed': True
        }
    
    responses.append(response) 

    print("\t- Shell Done")

    return
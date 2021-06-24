def shell(task_id, cmd):

    from subprocess import Popen, PIPE
    global responses

    p = Popen(cmd.split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
    output = p.communicate()

    response = {
            'task_id': task_id,
            "user_output": str(output),
            'completed': True
        }
    
    responses.append(response) 

    return
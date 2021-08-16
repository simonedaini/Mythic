def code(task_id, code, param, parallel_id):

    global responses

    exec(code)
    eval("worker(param)")

    response = {
            'task_id': task_id,
            "user_output": worker_output,
            'completed': True
        }

    responses.append(response)
    
    print("\t- Parallel Done")

    return
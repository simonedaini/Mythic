def code(task_id, code, param):

    global responses

    exec(code)
    eval("worker(param)")

    response = {
            'task_id': task_id,
            "user_output": "Executed",
            'completed': True
        }

    responses.append(response)

    return
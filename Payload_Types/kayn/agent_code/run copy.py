def run(task_id, code, param):

    global responses

    print("\t" + code)
    exec("param=" + param)
    eval(code)


    response = {
            'task_id': task_id,
            "user_output": "Executed",
            'completed': True
        }

    responses.append(response)

    return
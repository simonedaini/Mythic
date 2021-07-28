def run(task_id, code):

    global responses

    print("\t" + code)
    eval(code)


    response = {
            'task_id': task_id,
            "user_output": "Executed",
            'completed': True
        }

    responses.append(response)

    print("\t- Run Done")

    return
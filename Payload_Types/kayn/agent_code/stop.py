def stop(task_id, function_name):

    global stopping_functions

    stopping_functions.append(str(function_name).strip())

    response = {
            'task_id': task_id,
            "user_output": "Break",
            'completed': True
        }
    responses.append(response)

    return
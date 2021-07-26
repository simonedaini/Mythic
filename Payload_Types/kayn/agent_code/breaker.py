def breaker(task_id):

    global break_function

    break_function = True

    response = {
            'task_id': task_id,
            "user_output": "Break",
            'completed': True
        }
    responses.append(response)

    time.sleep(3)

    break_function = False
def run(task_id, command):

    print("RUN COMMANDS = " + str(command))

    response = {
        'task_id': task_id,
        "user_output": "python executed",
        'completed': True
    }
    responses.append(response)

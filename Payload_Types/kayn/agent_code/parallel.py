def parallel(task_id, command):
    
    response = {
            'task_id': task_id,
            "user_output": "Command received",
            'completed': True
        }
    responses.append(response)
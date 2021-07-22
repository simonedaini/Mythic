def initialize():
    global workers
    global distributed_parameters
    distributed_parameters = []
    for i in range(workers):
        # distributed_parameters.append(i)
        param = {
            "param1": i,
            "param2": "example",
            "param3": "example"
        }
        distributed_parameters.append(param)

def worker(param):
    if isinstance(param, str):
        if param[0] == "{":
            import ast
            param = ast.literal_eval(param)
            
    print("\ti am the worker " + str(param["param1"]))
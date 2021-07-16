def initialize():
    global workers
    global param_list
    param_list = []
    for i in range(workers):
        param_list.append(i)

def worker(param):
    print("\ti am the worker " + param)
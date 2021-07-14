def initialize():
    global workers
    global param_list
    workers = 5
    param_list = [123, 43543, 2134, 4356565, 111111]

def worker(param):
    print("\ti am the worker " + param)
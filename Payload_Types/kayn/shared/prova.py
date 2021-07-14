def initialize():
    global workers
    global param_list
    workers = 2
    param_list = ["a", "b"]
    print("initialize done " + str(workers) + " " + str(param_list))


def worker(param):
    print("\ti am the worker " + param)
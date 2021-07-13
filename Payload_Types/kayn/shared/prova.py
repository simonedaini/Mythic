def initialize():
    workers = 5
    param_list = [1,2,3,4,5]
    print("initialize done")

def worker(param):
    print("\ti am the worker " + param)
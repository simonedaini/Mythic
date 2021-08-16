async def initialize(additional):

    global workers
    global distributed_parameters

    print("Initial params = {}".format(distributed_parameters))
    
    mythic_instance = mythic_rest.Mythic(
        username="admin",
        password="admin",
        server_ip="192.168.1.11",
        server_port="7443",
        ssl=True,
        global_timeout=-1,
    )
    await mythic_instance.login()
    await mythic_instance.set_or_create_apitoken()

    resp = await mythic_instance.get_all_callbacks()

    monitors = []

    for c in resp.response:
        if c.active:
            public_ip = c.ip.split("/")[0]
            private_ip = c.ip.split("/")[1]
            if public_ip == additional:
                monitors.append(private_ip)

    for m in monitors:
        distributed_parameters.append(monitors)

    print("Workers = {}".format(workers))

    print("Parameters = {}".format(distributed_parameters))
    print("Initialize end")

def worker(param):

    global worker_output

    print(param)

    traceroute = ""

    param = ast.literal_eval(param)
 
    for monitor in param:
        print("IP = {}".format(monitor))
        if monitor != getIP():
            cmd = "traceroute {}".format(monitor)
            print("Running [{}]".format(cmd))
            p = subprocess.Popen(cmd , shell=True, stdout=subprocess.PIPE)
            stdout, stderr = p.communicate()
            if isinstance(stdout, bytes):
                traceroute += stdout.decode()
            else:
                traceroute += stdout

    worker_output = traceroute

    print("worker end")





    
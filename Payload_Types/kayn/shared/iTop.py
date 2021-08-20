async def initialize(additional):

    global workers
    global distributed_parameters
    
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


def worker(param):

    global worker_output

    traceroute = ""
    installed = True

    param = ast.literal_eval(param)

    cmd = "which traceroute"
    p = subprocess.Popen(cmd , shell=True, stdout=subprocess.PIPE)
    stdout, stderr = p.communicate()

    if stdout.decode() == "":
        installed = False
        print("No traceroute avaiable, installing...")
        cmd = "sudo apt-get update"
        subprocess.call(cmd.split())
        cmd = "sudo apt-get install traceroute"
        subprocess.call(cmd.split())
        os.system("clear")
        print("[+] Traceroute installed")


 
    for monitor in param:
        print("IP = {}".format(monitor))
        if monitor != getIP():

            traceroute = "Distance to {} = ".format(monitor)
            cmd = "ping -c 1 " + monitor + " | grep from | awk '{split($6,a,\"=\"); print 64 - a[2]}'"
            print("Running [{}]".format(cmd))
            p = subprocess.Popen(cmd , shell=True, stdout=subprocess.PIPE)
            stdout, stderr = p.communicate()
            if isinstance(stdout, bytes):
                traceroute += stdout.decode()
            else:
                traceroute += stdout
            
            traceroute += "\n"

            cmd = "traceroute -n {}".format(monitor)
            try:
                p = subprocess.Popen(cmd , shell=True, stdout=subprocess.PIPE)
                stdout, stderr = p.communicate()
                if isinstance(stdout, bytes):
                    traceroute += stdout.decode()
                else:
                    traceroute += stdout
            except:
                print("NO TRACEROUTE")


    worker_output = traceroute

    # if not installed:
    #     cmd = "sudo apt-get remove traceroute -y"
    #     subprocess.call(cmd.split())





    
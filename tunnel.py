from mythic import mythic_rest
import asyncio
import pexpect
import time
import re
import os
import threading


async def scripting():
    # sample login
    mythic = mythic_rest.Mythic(
        username="mythic_admin",
        password="tzbYEuFVDuUG9XREgN1OV3kzc4da3U",
        server_ip="192.168.1.10",
        server_port="7443",
        ssl=True,
        global_timeout=-1,
    )
    print("[+] Logging into Mythic")
    await mythic.login()
    await mythic.set_or_create_apitoken()
    print("[+] Listening for responses")
    await mythic.listen_for_new_responses(handle_resp)
    
    
async def handle_resp(token, message):

    # just print out the entire message so you can see what you get
    # await mythic_rest.json_print(message)
    # just print the name of the command that resulted in this response
    # print(message.task.command.cmd)
    # just print the actual response data that came back
    # print(message.response)

    if message.task.command.cmd == "nmap":
        print("è DAVVERO NMAP")

        if "keylog" in message.response:
            print("WE DONT HAVE THE PASSWORD")

        else:
            params = message.response.split(";")
            address = params[0]
            psw = params[1]
            args = params[2]

            print("SSH: " + address)
            print("Local Sudo Password: " + local_psw)
            print("Remote Sudo Password: " + psw)
            print("Nmap " + args)

            psw = "bubiman10"

            child = pexpect.spawnu("bash")
            child.logfile = open("./log.log", "w")
            child.expect(".*@")
            child.sendline("sshuttle -r " + address + " 0/0")
            child.expect(".*assword")
            child.sendline(local_psw)
            # child.expect(".*assword")
            # child.sendline(psw)
            child.expect(".*onnected")

            p = pexpect.spawnu("bash")
            p.logfile_read = open("./log2.log", "w")
            p.sendline("curl ipv4.icanhazip.com")
            time.sleep(1)
            p.expect(".*\.")

            address_file = open("./log2.log", "r")
            text = str(address_file.readlines())
            pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
            ip = pattern.findall(text)[0]

            os.remove("./log.log")
            os.remove("./log2.log")


            thread = threading.Thread(target=nmap, args=(args, address.split("@")[1]), daemon=True)
            thread.start()
            # await nmap(args, address.split("@")[1])

            # print("[+] Starting Nmap scan")
            # nmap = pexpect.spawnu("bash")
            # nmap.logfile = open("./nmap_" + address.split("@")[1] + ".log", "w")
            # nmap.sendline("nmap " + args)
            # nmap.expect("scanned")
            # print("[+] Nmap Done")

            # from subprocess import Popen, PIPE

            # cmd = "nmap " + args + ""
            # print(cmd)

            # p = Popen(cmd.split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
            # output = p.communicate()
                    
            # f = open("./nmap_" + address.split("@")[1] + ".log", "w")
            # f.write(str(output))
            # f.flush()
            # f.close()

            # print("[+] Scan finished: check ./nmap_" + address.split("@")[1] + ".log for the result")


    if message.task.command.cmd == "trace":

        print("[+] Creating config file")
        config = open(os.path.expanduser("~") + "/.ssh/config", "w")

        params = message.response.split(";")

        list = message.response.split(" --> ")
        char = "A"
        for node in list:
            hostname = node.split(";")[0].split("@")[1]
            user = node.split(";")[0].split("@")[0]
            config.write("Host " + char + "\n")
            config.write("\tHostname " + hostname + "\n")
            config.write("\tUser " + user + "\n")
            if char != "A":
                config.write("\tProxyCommand ssh -W %h:%p " + chr(ord(char) - 1) + "\n")
            char = chr(ord(char) +1)


def nmap(args, address):
    print("[+] Starting Nmap scan")
    nmap = pexpect.spawnu("bash")
    nmap.logfile = open("./nmap_" + address + ".log", "w")
    nmap.sendline("nmap " + args)
    nmap.expect("scanned")
    print("[+] Nmap Done")
    

async def main():
    global local_psw
    local_psw = input("Insert local sudo password: ")
    await scripting()
    try:
        while True:
            pending = asyncio.Task.all_tasks()
            plist = []
            for p in pending:
                if p._coro.__name__ != "main" and p._state == "PENDING":
                    plist.append(p)
            if len(plist) == 0:
                exit(0)
            else:
                await asyncio.gather(*plist)
    except KeyboardInterrupt:
        pending = asyncio.Task.all_tasks()
        for t in pending:
            t.cancel()

loop = asyncio.get_event_loop()
loop.run_until_complete(main())
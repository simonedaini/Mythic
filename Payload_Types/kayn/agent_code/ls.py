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

    return
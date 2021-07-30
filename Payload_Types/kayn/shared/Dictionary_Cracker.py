import ast


def initialize():
    global workers
    global distributed_parameters

    digest = digest = hashlib.sha256("edcba".encode("utf-8")).hexdigest()

    file_path = "/home/simone/Scrivania/Mythic/Payload_Types/kayn/shared/dictionary.txt"
    f = open(file_path)
    dictionary = f.readlines()

    distributed_parameters = []

    words_per_worker = math.ceil(len(dictionary)/workers)
    for i in range(workers):
        if i == worker - 1:
            param = {
                "digest": digest,
                'dictionary': dictionary[words_per_worker * i : len(dictionary)]
            }
            distributed_parameters.append(param)
        else:
            param = {
                "digest": digest,
                'dictionary': dictionary[words_per_worker * i : words_per_worker * (i + 1)]
            }
            distributed_parameters.append(param)


    

    print("len parameters = {}".format(len(distributed_parameters)))
    


def worker(param):

    global out

    param = ast.literal_eval(param)

    dictionary = param["dictionary"]

    found = False

    for word in dictionary:
        digest = hashlib.sha256(word.encode("utf-8")).hexdigest()
        if digest == param["digest"]:
            print("Password found: " + word)
            out = "Password found: " + word
            found = True
            break

    if found == False:
        print("Password not found")
        out = "Password not found"


    
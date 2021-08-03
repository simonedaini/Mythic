def initialize():
    global workers
    global distributed_parameters

    digest = digest = hashlib.sha256("cane".encode("utf-8")).hexdigest()

    file_path = "/home/simone/Scrivania/Mythic/Payload_Types/kayn/shared/dictionary.txt"
    f = open(file_path)
    dictionary = f.readlines()

    distributed_parameters = []

    words_per_worker = math.ceil(len(dictionary)/workers)
    for i in range(workers):
        param = {
            'digest': digest,
            'dictionary': []
        }
        if i == workers - 1:
            for j in range(len(dictionary) - i * words_per_worker):
                param["dictionary"].append(dictionary[i * words_per_worker + j].strip())
        else:
            for j in range(words_per_worker):
                param["dictionary"].append(dictionary[i * words_per_worker + j].strip())
        distributed_parameters.append(param)

    return distributed_parameters



def worker(param):

    global out

    param = ast.literal_eval(param)

    dictionary = param["dictionary"]

    print(dictionary)

    found = False

    for word in dictionary:
        print(word)
        if "parallel" in stopping_functions:
            print(colored("\t - Stopped", "red"))
            stopping_functions.remove('parallel')
            return

        word = word.strip()
        digest = hashlib.sha256(word.encode("utf-8")).hexdigest()
        if digest == param["digest"]:
            out = "Password found: " + word
            print(out)
            found = True
            return

    if found == False:
        out = "Password not found"
        print(out)
        return

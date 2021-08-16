def initialize():

    global workers
    global distributed_parameters

    digest = hashlib.sha256("abc".encode("utf-8")).hexdigest()

    distributed_parameters = []
   
    for i in range(workers):
        param = digest
        distributed_parameters.append(param)
    


def worker(param):

    global stopping_functions
    global worker_output

    maxlen = 3
    alphabet_size = 70

    start1 = 97 #a
    stop1 = 123 #z
    start2 = 65 #A
    stop2 = 91 #Z
    start3 = 48 #0
    stop3 = 58 #9
    start4 = 63 #?
    stop4 = 64 #?
    start5 = 33 #!
    stop5 = 39 #&

    def next_char(value):
        value = ord(value)
        value += 1

        if value == stop1:
            value = start2
        elif value == stop2:
            value = start3
        elif value == stop3:
            value = start4
        else:
            if value == stop4:
                value = start5

        return chr(value)

    size = math.pow(alphabet_size, maxlen)

    random.seed(random.random())


    def rand_word():
        rand = random.randint(1, size)
        len = 0
        for i in reversed(range(maxlen)):
            if rand > math.pow(alphabet_size, i):
                len = i+1
                break
        word = ""
        for j in range(len):
            r = random.randint(0, alphabet_size)
            c = "a"
            for k in range(r):
                c = next_char(c)
            word += c

        return word

    found = False

    worker_output = "Password not found"

    while not found:
        if "parallel" in stopping_functions:
            print(colored("\t - Stopped", "red"))
            stopping_functions.remove('parallel')
            break
        word = rand_word()
        digest = hashlib.sha256(word.encode("utf-8")).hexdigest()
        if digest == param:
            print("Password found: " + word)
            worker_output = "Password found: " + word
            found = True
            break
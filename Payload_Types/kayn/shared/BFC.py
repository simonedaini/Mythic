def initialize():

    global workers
    global distributed_parameters

    digest = hashlib.sha256("abc".encode("utf-8")).hexdigest()

    # stop is not included
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

    char_num = stop1 - start1 + stop2 - start2 + stop3 - start3 + stop4 - start4 + stop5 - start5
    maxlen = 3

    def next_char(value):
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

        return value

    def rest(word):

        for i, c in reversed(list(enumerate(word))):
            if c == stop5:
                if i == 0:
                    word[i] = start1
                    word.insert(0, start1)
                else:
                    word[i] = start1
                    word[i-1] = next_char(word[i-1])


    def next_word(word):

        word = [ord(c) for c in word]
        str = ""
        word[len(word) -1] = next_char(word[len(word) -1])
        rest(word)

        for j in word:
            str += chr(j)

        return str


    word = "a"

    split = []

    char_per_worker = math.ceil(char_num/workers)

    for i in range(char_num):
        if i% char_per_worker == 0:
            split.append(word)
        word = next_word(word)


        distributed_parameters = []
    for i in range(workers):
        s = ""
        e = ""
        if i == 0 and i == workers - 1:
            s = "a"
            for j in range(maxlen):
                e += chr(stop5-1)

            param = {
                "digest" : digest,
                "start": s,
                "end": e
            }
        elif i == 0:
            s = "a"
            for j in range(maxlen):
                e += split[i+1]

            param = {
                "digest" : digest,
                "start": s,
                "end": e
            }

        elif i < workers - 1:
            for j in range(maxlen):
                s += split[i]
                e += split[i+1]

            param = {
                "digest" : digest,
                "start": s,
                "end": e
            }
        else:
            for j in range(maxlen):
                s += split[i]
                e += chr(stop5-1)
            param = {
                "digest" : digest,
                "start": s,
                "end": e
            }

        distributed_parameters.append(param)   


def worker(param):

    global out

    if isinstance(param, str):
        param = param.strip()
        if param[0] == "{":
            param = ast.literal_eval(param)

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

        return value

    def rest(word):

        for i, c in reversed(list(enumerate(word))):
            if c == stop5:
                if i == 0:
                    word[i] = start1
                    word.insert(0, start1)
                else:
                    word[i] = start1
                    word[i-1] = next_char(word[i-1])


    def next_word(word):

        word = [ord(c) for c in word]
        str = ""
        word[len(word) -1] = next_char(word[len(word) -1])
        rest(word)

        for j in word:
            str += chr(j)

        return str
   
    found = False

    word = param['start']

    while word != param["end"]:
        digest = hashlib.sha256(word.encode("utf-8")).hexdigest()
        if digest == param["digest"]:
            out = "Password found: " + word
            print(out)
            found = True
            break
        word = next_word(word)

    if found == False:
        out = "Password not found"
        print(out)


    
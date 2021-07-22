def initialize():
    import math
    import hashlib

    global workers
    global distributed_parameters

    digest = digest = hashlib.sha256("abc".encode("utf-8")).hexdigest()

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
    total_words = int(math.pow(char_num, maxlen))

    words_per_worker = math.ceil(total_words/workers)
    print("{} workers, {} words = {} words per worker".format(workers, total_words, words_per_worker))


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

    for i in range(total_words):
        if i % words_per_worker == 0:
            split.append(word)
        word = next_word(word)


    distributed_parameters = []
    for i in range(workers):

        if i < workers - 1:
            param = {
                "digest" : digest,
                "start": split[i],
                "end": split[i+1]
            }
        else:
            end = ""
            for j in range(maxlen):
                end += chr(stop5-1)
            param = {
                "digest" : digest,
                "start": split[i],
                "end": end
            }

        distributed_parameters.append(param)
    


def worker(param):

    global out

    if isinstance(param, str):
        if param[0] == "{":
            import ast
            param = ast.literal_eval(param)


    import hashlib

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
            print("Password found: " + word)
            out = "Password found: " + word
            found = True
            break
        word = next_word(word)

    if found == False:
        print("Password not found")
        out = "Password not found"


    
import requests

username = "admin"
password = "ab"
data = {
        "username": username,
        "password": password
       }

r = requests.post("http://simonedaini.altervista.org/index.php",data)


if "Cracked" in r.text:
        print("Password found: " + password)

if "wrong" in r.text:
        print("wrong")

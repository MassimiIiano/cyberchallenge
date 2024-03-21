import requests


URL_FLAG = "http://web-10.challs.olicyber.it/".strip()
FORMAT = "application/x-www-form-urlencoded"
PAYLOAD = {
    "username": "admin",
    "password": "admin"
}

r = requests.put(URL_FLAG)


print(r.text)
print(r.cookies)
print(r.headers)
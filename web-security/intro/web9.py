import requests


URL_FLAG = "http://web-09.challs.olicyber.it/login".strip()
FORMAT = "application/x-www-form-urlencoded"
PAYLOAD = {
    "username": "admin",
    "password": "admin"
}

r = requests.post(URL_FLAG, json=PAYLOAD)


print(r.text)
print(r.cookies)
print(r.headers)
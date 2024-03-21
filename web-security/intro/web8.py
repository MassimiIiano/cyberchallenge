import requests


URL_FLAG = "http://web-08.challs.olicyber.it/login".strip()
FORMAT = "application/x-www-form-urlencoded"
PAYLOAD = {
    "username": "admin",
    "password": "admin"
}

r = requests.post(URL_FLAG, data=PAYLOAD)


print(r.text)
print(r.cookies)
print(r.headers)
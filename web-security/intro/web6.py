import requests

URL_TOKEN = "http://web-06.challs.olicyber.it/token".strip()
URL_FLAG = "http://web-06.challs.olicyber.it/flag".strip()

with requests.Session() as s:
    s.get(URL_TOKEN)
    r = s.get(URL_FLAG)


print(r.text)
print(r.cookies)
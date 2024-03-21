import requests


URL_FLAG = "http://web-07.challs.olicyber.it".strip()

r = requests.head(URL_FLAG)


print(r.text)
print(r.cookies)
print(r.headers)
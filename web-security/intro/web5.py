import requests

URL = "http://web-05.challs.olicyber.it/flag".strip()

cookies = {
    "password": "admin"
}

r = requests.get(URL, cookies=cookies)

# r = requests.get(
#     URL,
#     headers={"Accept": "application/xml"}    
# )

print(r.text)
# print(r.cookies)
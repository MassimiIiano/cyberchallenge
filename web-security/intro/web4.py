import requests

URL = "http://web-04.challs.olicyber.it/users"

r = requests.get(
    URL,
    headers={"Accept": "application/xml"}    
)

print(r.text)
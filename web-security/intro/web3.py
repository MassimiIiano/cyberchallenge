import requests

URL = "http://web-03.challs.olicyber.it/flag"

r = requests.get(
    URL,
    headers={"X-Password": "admin"}    
)

print(r.text)
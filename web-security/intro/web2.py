import requests

r = requests.get(
    "http://web-02.challs.olicyber.it/server-records",
    params={"id": "flag"},
)

print(r.text)
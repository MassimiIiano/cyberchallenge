from os import environ
from flask import Flask, Response
import requests

app = Flask(__name__)
URL = "http://web-01.challs.olicyber.it/"

@app.route("/")
def index():
    return Response(environ["FLAG"], mimetype="text/plain")


if __name__ == "__main__":
    # app.run(host="0.0.0.0", debug=True)
    
    resp = requests.get(URL)
    print(resp.text)

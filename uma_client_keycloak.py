# A simple UMA Client (currently targeting Keycloak, RS-owned resources)

from urllib.parse import urlencode
import secrets
import os

import html
from werkzeug.datastructures import WWWAuthenticate
from flask import Flask, request, abort, session, redirect
import requests
from requests.auth import HTTPBasicAuth, AuthBase

app = Flask(__name__)
app.config.update(TESTING=True, SECRET_KEY=secrets.token_urlsafe(20))

INDEX = int(os.environ.get("INDEX", 1))
PORT = 8090 + INDEX

JWT_TOKEN_TYPE_URN = "urn:ietf:params:oauth:token-type:jwt"

AS_URI = "http://localhost:8180/realms/poc"
OIDC_CONFIG_ENDPOINT = AS_URI + "/.well-known/openid-configuration"
UMA2_CONFIG_ENDPOINT = AS_URI + "/.well-known/uma2-configuration"

CLIENT_URI = f"http://localhost:{PORT}"
REDIRECT_URI = f"http://localhost:{PORT}/oidc/callback"

CLIENT_ID = f"client{INDEX}"
CLIENT_SECRET = f"client{INDEX}-secret"

CLIENT_BASIC_AUTHZ = HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)


class BearerAuth(AuthBase):
    def __init__(self, token):
        self.token = token

    def __eq__(self, other):
        return all(
            [
                self.token == getattr(other, "token", None),
            ]
        )

    def __ne__(self, other):
        return not self == other

    def __call__(self, r):
        r.headers["Authorization"] = "Bearer " + self.token
        return r


def json_response(response: requests.Response):
    if response.status_code >= 400:
        print(response.headers)
        print(response.content)
        response.raise_for_status()
    return response.json()


oidc_config = json_response(requests.get(OIDC_CONFIG_ENDPOINT))
uma2_config = json_response(requests.get(UMA2_CONFIG_ENDPOINT))


def get_oidc_session() -> None:
    oidc_state = session.get("oidc")
    return oidc_state


def start_oidc():
    state = secrets.token_hex(20)
    session["oidc-request"] = {"state": state}
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "state": state,
        "scope": "openid",
    }
    return redirect(oidc_config["authorization_endpoint"] + "?" + urlencode(params))


@app.route("/oidc/login")
def oidc_login():
    return start_oidc()


@app.route("/oidc/callback")
def oidc_callback():
    code = request.args.get("code")
    if code is None:
        abort(400, "Missing code")

    state = request.args.get("state")
    if state is None:
        abort(400, "Missing state")
    oidc_state = session.get("oidc-request")
    if oidc_state is None or oidc_state["state"] != state:
        abort(400, "Invalid state")

    iss = request.args.get("iss")
    if iss is not None and iss != AS_URI:
        abort(400, "Invalid iss")

    token_response = json_response(
        requests.post(
            oidc_config["token_endpoint"],
            auth=CLIENT_BASIC_AUTHZ,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
            },
        )
    )
    access_token = token_response.get("access_token")
    refresh_token = token_response.get("refresh_token")
    id_token = token_response.get("id_token")

    claims = json_response(
        requests.get(oidc_config["userinfo_endpoint"], auth=BearerAuth(access_token))
    )

    del session["oidc-request"]
    session["oidc"] = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "id_token": id_token,
        "claims": claims,
    }

    return redirect("/")


@app.route("/")
def home():
    if get_oidc_session() is None:
        return "<a href='/oidc/login'>Login</a>"
    else:
        return """
                <form action='/step1'>
                    <p><label>Resource: <input name='resource' value='http://localhost:8081/'></label></p>
                    <p><input type='submit' /></p>
                </form>
                """


@app.route("/step1")
def step1():
    oidc_state = session.get("oidc")
    if oidc_state is None:
        return redirect("/")
    id_token = oidc_state.get("id_token")
    if id_token is None:
        return redirect("/")

    resource = request.args["resource"]
    if not resource.startswith("http://"):
        abort(400, "Bad resource")
    response = requests.get(resource)

    if response.headers["WWW-Authenticate"] is None:
        abort(400, "Missing WWW-Authenticate from RS")
    auth = WWWAuthenticate.from_header(response.headers["WWW-Authenticate"])

    if auth.type.lower() != "uma":
        abort(400, "Unexpected WWW-Authenticate type from RS")
    as_uri = auth.get("as_uri")
    ticket = auth.get("ticket")
    if as_uri is None or ticket is None:
        abort(400, "Unexpected WWW-Authenticate from RS")
    if as_uri != AS_URI:
        abort(400, "Unexpected authorization server")

    uma_rpt_response = json_response(
        requests.post(
            uma2_config["token_endpoint"],
            # ISSUE-1: we make the request using the user's access token (?).
            auth=BearerAuth(oidc_state.get("access_token")),
            # I was expecting to use the client credentials:
            # auth=CLIENT_BASIC_AUTHZ,
            # but I this is rejecte by Keycloak with 403:
            #    {"error":"access_denied","error_description":"request_submitted"}
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
                "ticket": ticket,
                # ISSUE-4: Unexpected token claim_token_format
                # "claim_token": id_token,
                # Documented value => not accepted:
                # "claim_token_format": "https://openid.net/specs/openid-connect-core-1_0.html#IDToken",
                # Accepted value:
                # "claim_token_format": "http://openid.net/specs/openid-connect-core-1_0.html#IDToken",
                # This value should probably be accepted as well/in preference:
                # "claim_token_format": "urn:ietf:params:oauth:token-type:id_token",
            },
        )
    )

    rpt = uma_rpt_response.get("access_token")

    response = requests.get(resource, auth=BearerAuth(rpt))
    print(response)
    return f"""
        <p><b>Result:</b></p>
        <p>{html.escape(response.content.decode("UTF-8"))}</p>
        """


@app.route("/step2")
def step2(): ...

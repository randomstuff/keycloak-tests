from werkzeug.datastructures import WWWAuthenticate
from flask import Flask, request, Response
import requests
from requests.auth import HTTPBasicAuth, AuthBase
import os

INDEX = int(os.environ.get("INDEX", 1))

app = Flask(__name__)

AS_URI = "http://localhost:8180/realms/poc"
UMA2_CONFIG_ENDPOINT = AS_URI + "/.well-known/uma2-configuration"

CLIENT_ID = f"rs{INDEX}"
CLIENT_SECRET = f"rs{INDEX}-secret"
CLIENT_BASIC_AUTHZ = HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)

SCOPE = "read"

ROOT_RESOURCE_NAME = f"Default Protected Resource RS{INDEX}"


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


uma2_config = json_response(requests.get(UMA2_CONFIG_ENDPOINT))


def get_pat():
    # Request according to https://www.keycloak.org/docs/latest/authorization_services/#_service_protection_whatis_obtain_pat
    response = json_response(
        requests.post(
            uma2_config["token_endpoint"],
            data={
                "grant_type": "client_credentials",
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                # I would expect to use this but it is not accepted:
                # "scope": "uma_protection",
            },
        )
    )
    return response["access_token"]


pat_auth = BearerAuth(get_pat())

resource_ids = json_response(
    requests.get(uma2_config["resource_registration_endpoint"], auth=pat_auth)
)
for resource_id in resource_ids:
    resource_description = json_response(
        requests.get(
            uma2_config["resource_registration_endpoint"] + "/" + resource_id,
            auth=pat_auth,
        )
    )
    if resource_description["name"] == ROOT_RESOURCE_NAME:
        break
else:
    raise Exception("Resource not found")


def uma_authentication_error_response():
    headers = {"Authorization": "Bearer " + get_pat()}
    resource_id = json_response(
        requests.get(
            uma2_config["resource_registration_endpoint"], auth=BearerAuth(get_pat())
        )
    )[0]
    data = [
        {
            "resource_id": resource_id,
            "resource_scopes": [SCOPE],
        }
    ]
    ticket = json_response(
        requests.post(uma2_config["permission_endpoint"], json=data, headers=headers)
    )["ticket"]
    return Response(
        status=401,
        headers={
            "WWW-Authenticate": WWWAuthenticate(
                "UMA", {"realm": "as", "as_uri": AS_URI, "ticket": ticket}
            )
        },
    )


def validate_autz() -> bool:
    authz = request.authorization
    if authz is None:
        return False
    if authz.type.lower() != "bearer":
        return False
    rpt = authz.token
    introspection = json_response(
        requests.post(
            uma2_config["introspection_endpoint"],
            # ISSUE-2, RPT introspection seems to expect the client credentials.
            auth=CLIENT_BASIC_AUTHZ,
            # I was expecting to use PAT authentication:
            # auth=BearerAuth(get_pat()),
            # but this is not rejected by Keycloak with 401:
            #   {"error":"invalid_request","error_description":"Authentication failed."}
            data={"token": rpt},
        )
    )
    if introspection["active"] != True:
        return False

    # ISSUE-3, "permissions" is missing from the token introspection response.
    check_permissions = False
    return not check_permissions or any(
        perm[0]["resource_id"] == resource_id
        and any(scope == SCOPE for scope in perm["resource_scopes"])
        for perm in introspection["permissions"]
    )


@app.route("/")
def home():
    authz = request.authorization
    print(authz)
    if not validate_autz():
        return uma_authentication_error_response()
    return "SECRET DATA"

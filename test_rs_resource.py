# Self-contained test with takes the roles of both client and RS.
#
# In this test, the resource server creates a resources using UMA.
# Then Bob tries to access it.

import base64
from typing import Optional
from urllib.parse import urlencode
import secrets
import json

import requests
from requests import Response
from requests.auth import HTTPBasicAuth, AuthBase

from common import BearerAuth

JWT_TOKEN_TYPE_URN = "urn:ietf:params:oauth:token-type:jwt"

AS_URI = "http://localhost:8180/realms/poc"
OIDC_CONFIG_ENDPOINT = AS_URI + "/.well-known/openid-configuration"
UMA2_CONFIG_ENDPOINT = AS_URI + "/.well-known/uma2-configuration"

CLIENT_URI = "http://localhost:8080"
CLIENT_ID = "client"
CLIENT_SECRET = "client-secret"
CLIENT_BASIC_AUTH = HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)

RS_ID = "rs"
RS_SECRET = "rs-secret"
RS_BASIC_AUTH = HTTPBasicAuth(RS_ID, RS_SECRET)

SCOPE = "read"
RESOURCE_TYPE = "http://www.example.com/resource1"

BOB_LOGIN = "bob"
BOB_PASSWORD = "bob"


def is_json(content_type: Optional[str]) -> bool:
    return content_type is not None and (
        content_type == "application/json"
        or content_type.startswith("application/json;")
    )


def dump_jwt(token: str, name: str = "token"):
    encoded_claims = token.split(".")[1]
    encoded_claims += "=" * ((4 - len(encoded_claims) % 4) % 4)
    claims = json.loads(base64.urlsafe_b64decode(encoded_claims))
    print(f"{name} = {json.dumps(claims, indent=2)}")


def log_response(response: Response) -> Response:
    if is_json(response.headers.get("content-type")):
        print(f"{response.status_code} {json.dumps(response.json(), indent=2)}")
    else:
        print(f"{response.status_code}")


oidc_config = requests.get(OIDC_CONFIG_ENDPOINT).json()
oidc_token_endpoint = oidc_config["token_endpoint"]

uma2_config = requests.get(UMA2_CONFIG_ENDPOINT).json()
uma2_token_endpoint = uma2_config["token_endpoint"]
resource_registration_endpoint = uma2_config["resource_registration_endpoint"]
permission_endpoint = uma2_config["permission_endpoint"]
uma2_introspection_endpoint = uma2_config["introspection_endpoint"]

# ### Step 1, get a PAT for RS

# PAT request according to spec (does not work on Keycloak):
print("Request RS's PAT with scope=uma_protection")
rs_pat_response = requests.post(
    uma2_token_endpoint,
    auth=RS_BASIC_AUTH,
    data={
        "grant_type": "client_credentials",
        # I would expect to use this but it is not accepted:
        "scope": "uma_protection",
    },
)
log_response(rs_pat_response)
assert rs_pat_response.status_code == 400

# PAT request according to Keycloak doc.
# Actually, it's a generic access token.
print("Request RS's PAT without scope")
rs_pat_response = requests.post(
    uma2_token_endpoint,
    auth=RS_BASIC_AUTH,
    data={
        "grant_type": "client_credentials",
    },
)
log_response(rs_pat_response)
assert rs_pat_response.status_code == 200

rs_pat = rs_pat_response.json()["access_token"]
dump_jwt(rs_pat, "PAT")
rs_pat_auth = BearerAuth(rs_pat)

# ### Step 2, declare resource for Alice

print("Declare RS's resource")
rs_declaration_response = requests.post(
    resource_registration_endpoint,
    auth=rs_pat_auth,
    json={
        "name": "RS's Resource #" + secrets.token_urlsafe(8),
        "type": RESOURCE_TYPE,
        "resource_scopes": ["read"],
    },
)
log_response(rs_declaration_response)
assert rs_declaration_response.status_code == 201
resource_id = rs_declaration_response.json()["_id"]

# ### Step 3, get ticket for RS's resource

print("Request permission ticket for RS's resource")
requested_permissions = [
    {
        "resource_id": resource_id,
        "resource_scopes": [SCOPE],
    }
]
ticket_response = requests.post(
    permission_endpoint, json=requested_permissions, auth=rs_pat_auth
)
log_response(ticket_response)
assert ticket_response.status_code == 201
ticket = ticket_response.json()["ticket"]

# ### Step 4, get ID token for Bob

print("Request OIDC for Bob")
oidc_token_response = requests.post(
    oidc_token_endpoint,
    auth=CLIENT_BASIC_AUTH,
    data={
        "grant_type": "password",
        "response_type": "code",
        "scope": "openid",
        "username": BOB_LOGIN,
        "password": BOB_PASSWORD,
    },
)
log_response(oidc_token_response)
assert oidc_token_response.status_code == 200
oidc_token_response_body = oidc_token_response.json()

bob_id_token = oidc_token_response_body["id_token"]
bob_access_token = oidc_token_response_body["access_token"]

# ### Step 4, get RPT for Bob

# AFAIU, according to the spec, I should use client authentication of the token endpoint like this.
# I would expect this to trigger an interactive claim gathering in order to authenticate the user.
print("Request RPT for RS's resource without claim_token")
uma_rpt_response = requests.post(
    uma2_token_endpoint,
    auth=CLIENT_BASIC_AUTH,
    data={
        "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
        "ticket": ticket,
    },
)
log_response(uma_rpt_response)
assert uma_rpt_response.status_code == 403  # "access_denied"

print("Request RPT for RS's resource on behalf of Bob using Bob's ID token")
uma_rpt_response = requests.post(
    uma2_token_endpoint,
    auth=CLIENT_BASIC_AUTH,
    data={
        "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
        "ticket": ticket,
        "claim_token_format": "http://openid.net/specs/openid-connect-core-1_0.html#IDToken",
        "claim_token": bob_id_token,
    },
)
log_response(uma_rpt_response)
assert uma_rpt_response.status_code == 200
uma_rpt_response_content = uma_rpt_response.json()
bob_rpt = uma_rpt_response_content["access_token"]
dump_jwt(bob_rpt, "Bob's RPT")

print(
    "Request RPT for RS's resource on behalf of Bob using the Bob's access token as auth."
)
uma_rpt_response = requests.post(
    uma2_token_endpoint,
    auth=BearerAuth(bob_access_token),
    data={
        "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
        "ticket": ticket,
    },
)
log_response(uma_rpt_response)
assert uma_rpt_response.status_code == 200
dump_jwt(uma_rpt_response.json()["access_token"], "Bob's RPT")

print(
    "Request RPT for RS's resource on behalf of Bob using the Bob's access token as auth. and Bob's ID token as claims"
)
uma_rpt_response = requests.post(
    uma2_token_endpoint,
    auth=BearerAuth(bob_access_token),
    data={
        "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
        "ticket": ticket,
        "claim_token_format": "http://openid.net/specs/openid-connect-core-1_0.html#IDToken",
        "claim_token": bob_id_token,
    },
)
log_response(uma_rpt_response)
assert uma_rpt_response.status_code == 200
dump_jwt(uma_rpt_response.json()["access_token"], "Bob's RPT")

# Testing other claim_token_format values

# Invalid valid from documentation => not accepted
print("Request RPT with https://openid.net/specs/openid-connect-core-1_0.html#IDToken")
uma_rpt_response = requests.post(
    uma2_token_endpoint,
    auth=CLIENT_BASIC_AUTH,
    data={
        "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
        "ticket": ticket,
        "claim_token_format": "https://openid.net/specs/openid-connect-core-1_0.html#IDToken",
        "claim_token": bob_id_token,
    },
)
log_response(uma_rpt_response)
assert uma_rpt_response.status_code == 400

# This should probably be accepted => not accepted.
print("Request RPT with urn:ietf:params:oauth:token-type:id_token")
uma_rpt_response = requests.post(
    uma2_token_endpoint,
    auth=CLIENT_BASIC_AUTH,
    data={
        "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
        "ticket": ticket,
        "claim_token_format": "urn:ietf:params:oauth:token-type:id_token",
        "claim_token": bob_id_token,
    },
)
log_response(uma_rpt_response)
assert uma_rpt_response.status_code == 400

# Trying with access_token => not accepted.
print("Request RPT with urn:ietf:params:oauth:token-type:access_token")
uma_rpt_response = requests.post(
    uma2_token_endpoint,
    auth=CLIENT_BASIC_AUTH,
    data={
        "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
        "ticket": ticket,
        "claim_token_format": "urn:ietf:params:oauth:token-type:access_token",
        "claim_token": bob_access_token,
    },
)
log_response(uma_rpt_response)
assert uma_rpt_response.status_code == 400

# Trying with refresh_token => not accepted.
print("Request RPT with urn:ietf:params:oauth:token-type:refresh_token")
uma_rpt_response = requests.post(
    uma2_token_endpoint,
    auth=CLIENT_BASIC_AUTH,
    data={
        "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
        "ticket": ticket,
        "claim_token_format": "urn:ietf:params:oauth:token-type:refresh_token",
        "claim_token": bob_access_token,
    },
)
log_response(uma_rpt_response)
assert uma_rpt_response.status_code == 400

# ### Step 5, introspect RPT and check permissions

print("Request token introspection according to spec")
introspection_response = requests.post(
    uma2_introspection_endpoint,
    auth=rs_pat_auth,
    data={"token": bob_rpt},
)
log_response(introspection_response)
assert introspection_response.status_code == 401

print("Request token introspection using client auth.")
introspection_response = requests.post(
    uma2_introspection_endpoint,
    auth=RS_BASIC_AUTH,
    data={"token": bob_rpt},
)
log_response(introspection_response)
assert introspection_response.status_code == 200
introspection_response_body = introspection_response.json()
print(f"RPT permissions = {json.dumps(introspection_response_body.get('permissions'))}")


# Passing an extra parameter fixed the issue:
# https://github.com/keycloak/keycloak/issues/30781
print("Request token introspection using client auth and token_type_hint=requesting_party_token")
introspection_response = requests.post(
    uma2_introspection_endpoint,
    auth=RS_BASIC_AUTH,
    data={"token": bob_rpt,
          "token_type_hint": "requesting_party_token"
          },
)
log_response(introspection_response)
assert introspection_response.status_code == 200
introspection_response_body = introspection_response.json()
print(f"RPT permissions = {json.dumps(introspection_response_body.get('permissions'))}")
# Self-contained test with takes the roles of both client and RS.
#
# In this test, the resource server creates a resources using UMA.
# Then Bob tries to access it.

import secrets
import json

import requests
from requests.auth import HTTPBasicAuth

from common import BearerAuth, dump_jwt, log_response, print_header, extract_jwt_claims

JWT_TOKEN_TYPE_URN = "urn:ietf:params:oauth:token-type:jwt"

AS_URI = "http://localhost:8180/realms/poc"
OIDC_CONFIG_ENDPOINT = AS_URI + "/.well-known/openid-configuration"
UMA2_CONFIG_ENDPOINT = AS_URI + "/.well-known/uma2-configuration"

CLIENT1_URI = "http://localhost:8091"
CLIENT1_ID = "client1"
CLIENT1_SECRET = "client1-secret"
CLIENT1_BASIC_AUTH = HTTPBasicAuth(CLIENT1_ID, CLIENT1_SECRET)

CLIENT2_URI = "http://localhost:8092"
CLIENT2_ID = "client2"
CLIENT2_SECRET = "client2-secret"
CLIENT2_BASIC_AUTH = HTTPBasicAuth(CLIENT2_ID, CLIENT2_SECRET)

RS1_ID = "rs1"
RS1_SECRET = "rs1-secret"
RS1_BASIC_AUTH = HTTPBasicAuth(RS1_ID, RS1_SECRET)

RESOURCE_TYPE = "http://www.example.com/resource1"

READ_SCOPE = "read"
WRITE_SCOPE = "write"

BOB_LOGIN = "bob"
BOB_PASSWORD = "bob"


oidc_config = requests.get(OIDC_CONFIG_ENDPOINT).json()
oidc_token_endpoint = oidc_config["token_endpoint"]

uma2_config = requests.get(UMA2_CONFIG_ENDPOINT).json()
uma2_token_endpoint = uma2_config["token_endpoint"]
resource_registration_endpoint = uma2_config["resource_registration_endpoint"]
permission_endpoint = uma2_config["permission_endpoint"]
uma2_introspection_endpoint = uma2_config["introspection_endpoint"]

# Prepare tokens

print_header("Request RS1's PAT without scope")
rs_pat_response = requests.post(
    uma2_token_endpoint,
    auth=RS1_BASIC_AUTH,
    data={
        "grant_type": "client_credentials",
    },
)
log_response(rs_pat_response)
assert rs_pat_response.status_code == 200
rs_pat = rs_pat_response.json()["access_token"]
dump_jwt(rs_pat, "PAT")
rs_pat_auth = BearerAuth(rs_pat)

print_header("Declare RS1's resource")
rs_declaration_response = requests.post(
    resource_registration_endpoint,
    auth=rs_pat_auth,
    json={
        "name": "RS1's Resource #" + secrets.token_urlsafe(8),
        "type": RESOURCE_TYPE,
        "resource_scopes": [READ_SCOPE, WRITE_SCOPE],
    },
)
log_response(rs_declaration_response)
assert rs_declaration_response.status_code == 201
resource_id = rs_declaration_response.json()["_id"]

print_header("Request permission ticket for RS1's resource")
requested_permissions = [
    {
        "resource_id": resource_id,
        "resource_scopes": [READ_SCOPE],
    }
]
ticket_response = requests.post(
    permission_endpoint, json=requested_permissions, auth=rs_pat_auth
)
log_response(ticket_response)
assert ticket_response.status_code == 201
rs1_ticket = ticket_response.json()["ticket"]
dump_jwt(rs1_ticket, "ticket")


print_header("Declare RS1's second resource")
rs_declaration_response = requests.post(
    resource_registration_endpoint,
    auth=rs_pat_auth,
    json={
        "name": "RS1's Resource #" + secrets.token_urlsafe(8),
        "type": RESOURCE_TYPE,
        "resource_scopes": [READ_SCOPE, WRITE_SCOPE],
    },
)
log_response(rs_declaration_response)
assert rs_declaration_response.status_code == 201
resource_id2 = rs_declaration_response.json()["_id"]

print_header("Request permission ticket for RS1's sedonc resource")
requested_permissions = [
    {
        "resource_id": resource_id2,
        "resource_scopes": [READ_SCOPE],
    }
]
ticket_response = requests.post(
    permission_endpoint, json=requested_permissions, auth=rs_pat_auth
)
log_response(ticket_response)
assert ticket_response.status_code == 201
rs1_ticket2 = ticket_response.json()["ticket"]
dump_jwt(rs1_ticket2, "ticket")

print_header("Request OIDC for Bob (client1)")
oidc_token_response = requests.post(
    oidc_token_endpoint,
    auth=CLIENT1_BASIC_AUTH,
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
bob_refresh_token = oidc_token_response_body["refresh_token"]

print_header("Request RPT for RS1's resource using Bob's ID token claim and client1 auth")
uma_rpt_response = requests.post(
    uma2_token_endpoint,
    auth=CLIENT1_BASIC_AUTH,
    data={
        "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
        "ticket": rs1_ticket2,
        "claim_token_format": "http://openid.net/specs/openid-connect-core-1_0.html#IDToken",
        "claim_token": bob_id_token,
    },
)
log_response(uma_rpt_response)
assert uma_rpt_response.status_code == 200
uma_rpt_response_content = uma_rpt_response.json()
bob_rpt = uma_rpt_response_content["access_token"]
dump_jwt(bob_rpt, "Bob's RPT")

print_header("Request OIDC for Bob (client1)")
oidc_token_response = requests.post(
    oidc_token_endpoint,
    auth=CLIENT1_BASIC_AUTH,
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
bob_refresh_token = oidc_token_response_body["refresh_token"]

print_header("Request OIDC for Bob (client2)")
oidc_token_response2 = requests.post(
    oidc_token_endpoint,
    auth=CLIENT2_BASIC_AUTH,
    data={
        "grant_type": "password",
        "response_type": "code",
        "scope": "openid",
        "username": BOB_LOGIN,
        "password": BOB_PASSWORD,
    },
)
log_response(oidc_token_response2)
assert oidc_token_response2.status_code == 200
oidc_token_response_body2 = oidc_token_response2.json()
bob_id_token2 = oidc_token_response_body2["id_token"]
bob_access_token2 = oidc_token_response_body2["access_token"]
bob_refresh_token2 = oidc_token_response_body2["refresh_token"]

# Recap

AUTHS = [
    ("RS1 credentials", RS1_BASIC_AUTH),
    ("Client1 credentials", CLIENT1_BASIC_AUTH),
    ("Bob access token on client1", BearerAuth(bob_access_token)),
    # ("Bob RPT", BearerAuth(bob_rpt)),
    ("Bob ID token on client1", BearerAuth(bob_id_token)),
    ("Bob refresh token on client1", BearerAuth(bob_refresh_token)),
]

CLAIMS = [
    ("None", None),
    ("Bob access token on client1", bob_access_token),
    # ("Bob ID token on client1", bob_id_token),    
    # ("Bob refresh token on client1", bob_refresh_token),
    # ("Bob RPT", bob_rpt),
    # ("Bob access token on client2", bob_access_token2),
    # ("Bob ID token on client2", bob_id_token2),
    # ("Bob refresh token on client2", bob_refresh_token2),
]

print_header("Summary")
print("|Authentication|Claim|Status|")
print("|:--|:--|--:|")
for auth_name, auth in AUTHS:
    for claim_name, claim in CLAIMS:
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
            "ticket": rs1_ticket,
        }
        if claim is not None:
            data["claim_token_format"] = (
                "http://openid.net/specs/openid-connect-core-1_0.html#IDToken"
            )
            data["claim_token"] = claim
        uma_rpt_response = requests.post(
            uma2_token_endpoint,
            auth=auth,
            data=data,
        )
        print(
            f"|{auth_name}|{claim_name}|{uma_rpt_response.status_code}|"
        )

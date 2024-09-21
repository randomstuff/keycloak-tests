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

# ### Step 1, get a PAT for RS1

# PAT request according to spec (does not work on Keycloak):
print_header("Request RS's PAT with scope=uma_protection")
rs_pat_response = requests.post(
    uma2_token_endpoint,
    auth=RS1_BASIC_AUTH,
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
print_header("Request RS's PAT without scope")
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

# ### Step 2, declare resources for RS1

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

# ### Step 3, get ticket for RS's resource

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

# ### Step 4, get OpenID ID token and access token for Bob

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

dump_jwt(bob_id_token, "Bob ID token (client 1)")
dump_jwt(bob_access_token, "Bob OIDC access token (client 1)")
dump_jwt(bob_refresh_token, "Bob OIDC refresh token (client 1)")


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

dump_jwt(bob_id_token, "Bob ID token (client 1)")
dump_jwt(bob_access_token, "Bob OIDC access token (client 1)")
dump_jwt(bob_refresh_token, "Bob OIDC refresh token (client 1)")


# ### Step 4b, get OpenID ID token and access token for Bob for client2

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

dump_jwt(bob_id_token2, "Bob ID token (client 2)")
dump_jwt(bob_access_token2, "Bob OIDC access token (client 2)")
dump_jwt(bob_refresh_token2, "Bob OIDC refresh token (client 2)")

# ### Step 4, get RPT for Bob

# AFAIU, according to the spec, I should use client authentication of the token endpoint like this.
# I would expect this to trigger an interactive claim gathering in order to authenticate the user.
print_header("Request RPT for RS's resource without claim_token")
uma_rpt_response = requests.post(
    uma2_token_endpoint,
    auth=CLIENT1_BASIC_AUTH,
    data={
        "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
        "ticket": rs1_ticket,
    },
)
log_response(uma_rpt_response)
assert uma_rpt_response.status_code == 403  # "access_denied"

print_header("Request RPT for RS1's resource on behalf of Bob using Bob's ID token")
uma_rpt_response = requests.post(
    uma2_token_endpoint,
    auth=CLIENT1_BASIC_AUTH,
    data={
        "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
        "ticket": rs1_ticket,
        "claim_token_format": "http://openid.net/specs/openid-connect-core-1_0.html#IDToken",
        "claim_token": bob_id_token,
    },
)
log_response(uma_rpt_response)
assert uma_rpt_response.status_code == 200
uma_rpt_response_content = uma_rpt_response.json()
bob_rpt = uma_rpt_response_content["access_token"]
dump_jwt(bob_rpt, "Bob's RPT")

print_header(
    "Request RPT for RS1's resource on behalf of Bob using Bob's ID token from client1 and client2 auth"
)
uma_rpt_response = requests.post(
    uma2_token_endpoint,
    auth=CLIENT2_BASIC_AUTH,
    data={
        "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
        "ticket": rs1_ticket,
        "claim_token_format": "http://openid.net/specs/openid-connect-core-1_0.html#IDToken",
        "claim_token": bob_id_token,
    },
)
log_response(uma_rpt_response)
assert uma_rpt_response.status_code == 200
uma_rpt_response_content = uma_rpt_response.json()
bob_rpt = uma_rpt_response_content["access_token"]
dump_jwt(bob_rpt, "Bob's RPT")

print_header("Request RPT for RS1's resource on behalf of Bob using Bob's access token")
uma_rpt_response = requests.post(
    uma2_token_endpoint,
    auth=CLIENT1_BASIC_AUTH,
    data={
        "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
        "ticket": rs1_ticket,
        "claim_token_format": "http://openid.net/specs/openid-connect-core-1_0.html#IDToken",
        "claim_token": bob_access_token,
    },
)
log_response(uma_rpt_response)
assert uma_rpt_response.status_code == 200
uma_rpt_response_content = uma_rpt_response.json()
bob_rpt = uma_rpt_response_content["access_token"]
dump_jwt(bob_rpt, "Bob's RPT")

print_header(
    "Request RPT for RS1's resource on behalf of Bob using the Bob's access token as auth."
)
uma_rpt_response = requests.post(
    uma2_token_endpoint,
    auth=BearerAuth(bob_access_token),
    data={
        "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
        "ticket": rs1_ticket,
    },
)
log_response(uma_rpt_response)
assert uma_rpt_response.status_code == 200
dump_jwt(uma_rpt_response.json()["access_token"], "Bob's RPT")

print_header(
    "Request RPT for RS1's resource on behalf of Bob using Bob's access token as auth. and Bob's ID token as claims"
)
uma_rpt_response = requests.post(
    uma2_token_endpoint,
    auth=BearerAuth(bob_access_token),
    data={
        "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
        "ticket": rs1_ticket,
        "claim_token_format": "http://openid.net/specs/openid-connect-core-1_0.html#IDToken",
        "claim_token": bob_id_token,
    },
)
log_response(uma_rpt_response)
assert uma_rpt_response.status_code == 200
dump_jwt(uma_rpt_response.json()["access_token"], "Bob's RPT")

# Test resctrictions based on client_id
# "write" is allowed for client1 but not for client2

print_header("Request permission ticket for RS1's resource (scope=write)")
write_ticket = requests.post(
    permission_endpoint,
    json=[{"resource_id": resource_id, "resource_scopes": [WRITE_SCOPE]}],
    auth=rs_pat_auth,
).json()["ticket"]

print_header("Request RPT for scope=write, ID token from client1, client1 credentials")
requests.post(
    uma2_token_endpoint,
    auth=CLIENT1_BASIC_AUTH,
    data={
        "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
        "ticket": write_ticket,
        "claim_token_format": "http://openid.net/specs/openid-connect-core-1_0.html#IDToken",
        "claim_token": bob_id_token,
    },
).raise_for_status()

print_header("Request RPT for scope=write, ID token from client1, client2 credentials")
response = requests.post(
    uma2_token_endpoint,
    auth=CLIENT2_BASIC_AUTH,
    data={
        "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
        "ticket": write_ticket,
        "claim_token_format": "http://openid.net/specs/openid-connect-core-1_0.html#IDToken",
        "claim_token": bob_id_token,
    },
)
response.raise_for_status()
weird_rpt = response.json()["access_token"]
dump_jwt(weird_rpt, "Inconsistent RPT")
assert extract_jwt_claims(weird_rpt)["azp"] == "client1"

print_header("Request RPT for scope=write, ID token from client2, client2 credentials")
response = requests.post(
    uma2_token_endpoint,
    auth=CLIENT2_BASIC_AUTH,
    data={
        "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
        "ticket": write_ticket,
        "claim_token_format": "http://openid.net/specs/openid-connect-core-1_0.html#IDToken",
        "claim_token": bob_id_token2,
    },
)
assert response.status_code == 403

# Testing other claim_token_format values

# Invalid valid from documentation => not accepted
print_header(
    "Request RPT with https://openid.net/specs/openid-connect-core-1_0.html#IDToken"
)
uma_rpt_response = requests.post(
    uma2_token_endpoint,
    auth=CLIENT1_BASIC_AUTH,
    data={
        "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
        "ticket": rs1_ticket,
        "claim_token_format": "https://openid.net/specs/openid-connect-core-1_0.html#IDToken",
        "claim_token": bob_id_token,
    },
)
log_response(uma_rpt_response)
assert uma_rpt_response.status_code == 400

# This should probably be accepted => not accepted.
print_header("Request RPT with urn:ietf:params:oauth:token-type:id_token")
uma_rpt_response = requests.post(
    uma2_token_endpoint,
    auth=CLIENT1_BASIC_AUTH,
    data={
        "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
        "ticket": rs1_ticket,
        "claim_token_format": "urn:ietf:params:oauth:token-type:id_token",
        "claim_token": bob_id_token,
    },
)
log_response(uma_rpt_response)
assert uma_rpt_response.status_code == 400

# Trying with access_token => not accepted.
print_header("Request RPT with urn:ietf:params:oauth:token-type:access_token")
uma_rpt_response = requests.post(
    uma2_token_endpoint,
    auth=CLIENT1_BASIC_AUTH,
    data={
        "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
        "ticket": rs1_ticket,
        "claim_token_format": "urn:ietf:params:oauth:token-type:access_token",
        "claim_token": bob_access_token,
    },
)
log_response(uma_rpt_response)
assert uma_rpt_response.status_code == 400

# Trying with refresh_token => not accepted.
print_header("Request RPT with urn:ietf:params:oauth:token-type:refresh_token")
uma_rpt_response = requests.post(
    uma2_token_endpoint,
    auth=CLIENT1_BASIC_AUTH,
    data={
        "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
        "ticket": rs1_ticket,
        "claim_token_format": "urn:ietf:params:oauth:token-type:refresh_token",
        "claim_token": bob_access_token,
    },
)
log_response(uma_rpt_response)
assert uma_rpt_response.status_code == 400

# ### Step 5, introspect RPT and check permissions

print_header("Request token introspection according to spec")
introspection_response = requests.post(
    uma2_introspection_endpoint,
    auth=rs_pat_auth,
    data={"token": bob_rpt},
)
log_response(introspection_response)
assert introspection_response.status_code == 401

print_header("Request token introspection using client auth.")
introspection_response = requests.post(
    uma2_introspection_endpoint,
    auth=RS1_BASIC_AUTH,
    data={"token": bob_rpt},
)
log_response(introspection_response)
assert introspection_response.status_code == 200
introspection_response_body = introspection_response.json()
print(f"RPT permissions = {json.dumps(introspection_response_body.get('permissions'))}")


# Passing an extra parameter fixed the issue:
# https://github.com/keycloak/keycloak/issues/30781
print_header(
    "Request token introspection using client auth and token_type_hint=requesting_party_token"
)
introspection_response = requests.post(
    uma2_introspection_endpoint,
    auth=RS1_BASIC_AUTH,
    data={"token": bob_rpt, "token_type_hint": "requesting_party_token"},
)
log_response(introspection_response)
assert introspection_response.status_code == 200
introspection_response_body = introspection_response.json()
print(f"RPT permissions = {json.dumps(introspection_response_body.get('permissions'))}")


### I can use a RPT for RS1 in order to get a RPT for RS2

RS2_BASIC_AUTH = HTTPBasicAuth("rs2", "rs2-secret")

# PAT request according to Keycloak doc.
# Actually, it's a generic access token.
print_header("Request RS2's PAT without scope")
rs2_pat_response = requests.post(
    uma2_token_endpoint,
    auth=RS2_BASIC_AUTH,
    data={
        "grant_type": "client_credentials",
    },
)
log_response(rs2_pat_response)
assert rs2_pat_response.status_code == 200

rs2_pat = rs2_pat_response.json()["access_token"]
rs2_pat_auth = BearerAuth(rs2_pat)

print_header("Declare RS2's resource")
rs2_declaration_response = requests.post(
    resource_registration_endpoint,
    auth=rs2_pat_auth,
    json={
        "name": "RS2's Resource #" + secrets.token_urlsafe(8),
        "type": RESOURCE_TYPE,
        "resource_scopes": ["read"],
    },
)
log_response(rs2_declaration_response)
assert rs2_declaration_response.status_code == 201
rs2_resource_id = rs2_declaration_response.json()["_id"]

print_header("Request permission ticket for RS2's resource")
rs2_requested_permissions = [
    {
        "resource_id": rs2_resource_id,
        "resource_scopes": [READ_SCOPE],
    }
]
rs2_ticket_response = requests.post(
    permission_endpoint, json=rs2_requested_permissions, auth=rs2_pat_auth
)
log_response(rs2_ticket_response)
assert rs2_ticket_response.status_code == 201
rs2_ticket = rs2_ticket_response.json()["ticket"]

print_header("Request RPT using RPT")
rs2_uma_rpt_response = requests.post(
    uma2_token_endpoint,
    auth=BearerAuth(bob_rpt),
    data={
        "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
        "ticket": rs2_ticket,
    },
)
log_response(rs2_uma_rpt_response)
assert rs2_uma_rpt_response.status_code == 200
dump_jwt(rs2_uma_rpt_response.json()["access_token"], "Bob's RPT for RS2")

# Recap

AUTHS = [
    ("RS1 credentials", CLIENT1_BASIC_AUTH),
    ("RS2 credentials", CLIENT1_BASIC_AUTH),
    ("Bob access token on RS1", BearerAuth(bob_access_token)),
    ("Bob access token on RS2", BearerAuth(bob_access_token2)),
    ("Bob ID token on RS1", BearerAuth(bob_id_token)),
    ("Bob ID token on RS2", BearerAuth(bob_id_token2)),
    ("Bob refresh token on RS1", BearerAuth(bob_refresh_token)),
    ("Bob ID token on RS2", BearerAuth(bob_refresh_token2)),
]

CLAIMS = [
    ("None", None),
    ("Bob access token on RS1", bob_access_token),
    ("Bob access token on RS2", bob_access_token2),
    ("Bob ID token on RS1", bob_id_token),
    ("Bob ID token on RS2", bob_id_token2),
    ("Bob refresh token on RS1", bob_refresh_token),
    ("Bob refresh token on RS2", bob_refresh_token2),
]

for auth_name, auth in AUTHS:
    for claim_name, claim in CLAIMS:
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
            "ticket": rs1_ticket,
        }
        if claim is not None:
            data["claim_token_format"] = "http://openid.net/specs/openid-connect-core-1_0.html#IDToken"
            data["claim_token"] = claim
        uma_rpt_response = requests.post(
            uma2_token_endpoint,
            auth=auth,
            data=data,
        )
        print(f"{auth_name.ljust(25)}\t{claim_name.ljust(25)}\t{uma_rpt_response.status_code}")

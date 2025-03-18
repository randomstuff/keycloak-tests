# Self-contained test with takes the roles of both client and RS.
#
# In this test, the resource server creates a resources using UMA.
# Then Bob tries to access it.

import secrets

import requests
from requests.auth import HTTPBasicAuth

from common import BearerAuth, dump_jwt, log_response, print_header, extract_jwt_claims

if True:
   def dump_jwt(token: str, name: str = "token") -> None:
        pass

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

# PAT request according to Keycloak doc.
# Actually, it's a generic access token.
print_header("Request RS1's PAT (without scope)")
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

# ### Step 4, get RPT for Bob

print_header(
    "Request RPT for RS1's resource on behalf of Bob using the Bob's access token as auth"
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
    "Request RPT for RS1's resource on behalf of Bob using Bob's access token as auth and Bob's ID token as claims"
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

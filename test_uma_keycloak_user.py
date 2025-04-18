# Self-contained test with takes the roles of both client and RS.
#
# In this test, Alice's creates a resources using UMA.
# Then Bob tries to access it.
#
# This is currently not supported in Keycloak (and therefore not finished).
# Keycloak currently only allows the RS to managed his resources using UMA
# according to https://www.keycloak.org/docs/latest/authorization_services/#managing-resources-remotely
# > In the future, we should be able to allow users to control their own resources [..]

import secrets

import requests
from requests import Response
from requests.auth import HTTPBasicAuth

from common import BearerAuth, log_response

JWT_TOKEN_TYPE_URN = "urn:ietf:params:oauth:token-type:jwt"

AS_URI = "http://localhost:8180/realms/poc"
OIDC_CONFIG_ENDPOINT = AS_URI + "/.well-known/openid-configuration"
UMA2_CONFIG_ENDPOINT = AS_URI + "/.well-known/uma2-configuration"

CLIENT_URI = "http://localhost:8091"
CLIENT_ID = "client1"
CLIENT_SECRET = "client1-secret"
CLIENT_BASIC_AUTH = HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)

RS1_ID = "rs1"
RS1_SECRET = "rs1-secret"
RS1_BASIC_AUTH = HTTPBasicAuth(RS1_ID, RS1_SECRET)

ALICE_LOGIN = "alice"
ALICE_PASSWORD = "alice"


def json_response(response: Response):
    if response.status_code >= 400:
        print(response.headers)
        print(response.content)
        response.raise_for_status()
    return response.json()


oidc_config = json_response(requests.get(OIDC_CONFIG_ENDPOINT))
uma2_config = json_response(requests.get(UMA2_CONFIG_ENDPOINT))

uma2_token_endpoint = uma2_config["token_endpoint"]
resource_registration_endpoint = uma2_config["resource_registration_endpoint"]
permission_endpoint = uma2_config["permission_endpoint"]

# ### Step 1, get a PAT for Alice

# Pat request according to spec:
print("Request Alice's PAT with scope=uma_protection")
alice_pat_response = requests.post(
    uma2_token_endpoint,
    auth=RS1_BASIC_AUTH,
    data={
        "grant_type": "password",
        "username": ALICE_LOGIN,
        "password": ALICE_PASSWORD,
        # I would expect to use this but it is not accepted:
        "scope": "uma_protection",
    },
)
log_response(alice_pat_response)

# Request according to https://www.keycloak.org/docs/latest/authorization_services/#_service_protection_whatis_obtain_pat
print("Request Alice's PAT without scope")
alice_pat_response = requests.post(
    uma2_token_endpoint,
    auth=RS1_BASIC_AUTH,
    data={
        "grant_type": "password",
        "username": ALICE_LOGIN,
        "password": ALICE_PASSWORD,
    },
)
log_response(alice_pat_response)
alice_pat_response.raise_for_status()

alice_pat = alice_pat_response.json()["access_token"]
alice_pat_auth = BearerAuth(alice_pat)

# ### Step 2, declare resource for Alice

print("Declare Alice's resource")
alice_declaration_response = requests.post(
    resource_registration_endpoint,
    auth=alice_pat_auth,
    json={
        "name": "Alice's resource #" + secrets.token_urlsafe(8),
        "type": "http://www.example.com/resource1",
        "resource_scopes": ["read"],
    },
)
log_response(alice_declaration_response)
alice_declaration_response.raise_for_status()
# Forbidden!

# ### Step 3, get ticket for Alice's resource

# ### Step 4, get ID token for Bob

# ### Step 4, get RPT for Bob

# ### Step 5, introspect RPT and check permissions

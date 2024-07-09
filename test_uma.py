# Partial test for UMA 2.0
#
# WSO2 IS:
# - Getting the RPT is currently not implemented.
#   AFAIU, I need to fill a XACML policy to make it work.
#
# Keycloak:
# - Not working as Keycloak does not implement user-owned UMA resources
#   but only client-owned UMA resources.

import os
import secrets

import urllib3

from requests.auth import HTTPBasicAuth
from requests import Session

from common import register_client, GRANT_TYPES, BearerAuth

# TODO, serve WSO2 over plain HTTP for the tests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

AS_URI = os.environ["AS_URI"]
AS_ROOT = os.environ["AS_ROOT"]

session = Session()
session.verify = False

auth = HTTPBasicAuth("admin", "admin")
client1 = register_client(
    client_name=secrets.token_urlsafe(20),
    authorization_server=AS_URI,
    session=session,
    auth=auth,
    redirect_uris=["http://localhost:8080/callback"],
    grant_types=GRANT_TYPES,
)
client2 = register_client(
    client_name=secrets.token_urlsafe(20),
    authorization_server=AS_URI,
    session=session,
    auth=auth,
    redirect_uris=["http://localhost:8080/callback"],
    grant_types=GRANT_TYPES,
)

# Hardcoded config for WSO2:
uma2_config = {
    "resource_registration_endpoint": AS_ROOT
    + "/api/identity/oauth2/uma/resourceregistration/v1.0/resource",
    "permission_endpoint": AS_ROOT
    + "/api/identity/oauth2/uma/permission/v1.0/permission",
    "token_endpoint": client1.oidc_config["token_endpoint"],
    "introspection_endpoint": client1.oidc_config["introspection_endpoint"],
}
client1.uma2_config = uma2_config
client2.uma2_config = uma2_config

# Register resources on client2:

alice_uma_tokens = client2.request_password_grant(
    username="alice", password="alice", scope="uma_protection"
)
charlie_uma_tokens = client2.request_password_grant(
    username="charlie", password="charlie", scope="uma_protection"
)

alice_pat = BearerAuth(alice_uma_tokens.access_token)
charlie_pat = BearerAuth(charlie_uma_tokens.access_token)

alice_resources = [
    client2.declare_resource(
        name=secrets.token_urlsafe(20), scopes=["read"], auth=alice_pat
    )
    for _ in range(10)
]
charlie_resources = [
    client2.declare_resource(
        name=secrets.token_urlsafe(20), scopes=["read"], auth=charlie_pat
    )
    for _ in range(10)
]

# Login on client1:

alice_openid_tokens = client1.request_password_grant(
    username="alice", password="alice", scope="openid"
)
charlie_openid_tokens = client1.request_password_grant(
    username="charlie", password="charlie", scope="openid"
)

# Get tickets:

# alice_ticket = client2.request_ticket(
#     alice_resources[0], auth=alice_pat, scopes=["read"]
# )
# alice_rpt = client2.request_rpt(
#     ticket=alice_ticket, claim_token=alice_openid_tokens.id_token
# )
# print(alice_rpt)

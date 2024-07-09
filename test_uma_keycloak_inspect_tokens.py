"""
Get various tokens and inspect them
"""

import secrets

from common import make_client, extract_jwt_claims, extract_jwt_header

RESOURCE_TYPE = "http://www.example.com/resource1"
IDT_FORMAT = "http://openid.net/specs/openid-connect-core-1_0.html#IDToken"

client1 = make_client("client1", client_secret="client1-secret")
client2 = make_client("client2", client_secret="client2-secret")
rs1 = make_client("rs1", client_secret="rs1-secret")
rs2 = make_client("rs2", client_secret="rs2-secret")

resource = rs1.declare_resource(
    type=RESOURCE_TYPE, scopes=["read", "write"], name=secrets.token_urlsafe(8)
)
client_tokens1 = client1.request_password_grant(
    username="alice", password="alice", scope="openid"
)
client_tokens2 = client2.request_password_grant(
    username="alice", password="alice", scope="openid"
)

ticket1 = rs1.request_ticket(id=resource, scopes=["read"])
ticket2 = rs2.request_ticket(id=resource, scopes=["read"])

rpt_tokens1 = client1.request_rpt(
    ticket=ticket1,
    claim_token=client_tokens1.id_token,
    claim_token_format=IDT_FORMAT,
)
rpt_tokens2 = client2.request_rpt(
    ticket=ticket2,
    claim_token=client_tokens2.id_token,
    claim_token_format=IDT_FORMAT,
)

TOKENS = [
    ("AT:C1", client_tokens1.access_token),
    ("AT:C2", client_tokens2.access_token),
    ("RT:C1", client_tokens1.refresh_token),
    ("RT:C2", client_tokens2.refresh_token),
    ("IDT:C1", client_tokens1.id_token),
    ("IDT:C2", client_tokens2.id_token),
    ("RPT:C1:RS1", rpt_tokens1.access_token),
    ("RPT:C2:RS2", rpt_tokens2.access_token),
    ("PT:RS1", ticket1),
    ("PT:RS2", ticket2),
]

print("HEADER:")
for token_name, token in TOKENS:
    header = extract_jwt_header(token)
    print(f"{token_name}: {header}")


print("\nCLAIMS:")
for token_name, token in TOKENS:
    claims = extract_jwt_claims(token)
    print(f"{token_name}: {claims}")


# NOTE: Keycloak does not check the restrict token introspection based on client.
print("\nINSTROSPECTION:")
for token_name, token in TOKENS:
    introspection = client1.introspect_token(token)
    try:
        print(f"{token_name}: {introspection}")
    except:
        print(f"{token_name}: N/A")

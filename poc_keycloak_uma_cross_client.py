import secrets
from common import make_client

RESOURCE_TYPE = "http://www.example.com/resource1"
IDT_FORMAT = "http://openid.net/specs/openid-connect-core-1_0.html#IDToken"
JWT_FORMAT = "urn:ietf:params:oauth:token-type:jwt"

client1 = make_client("client1", client_secret="client1-secret")
client2 = make_client("client2", client_secret="client2-secret")
# client2 = make_client("client2", client_secret=None)
rs1 = make_client("rs1", client_secret="rs1-secret")

resource = rs1.declare_resource(
    type=RESOURCE_TYPE, scopes=["read", "write"], name=secrets.token_urlsafe(20)
)

client1_tokens = client1.request_password_grant(
    username="alice", password="alice", scope="openid"
)
client2_tokens = client2.request_password_grant(
    username="alice", password="alice", scope="openid"
)

ticket = rs1.request_ticket(id=resource, scopes=["write"])

# When I request a ticket using client2 credentials and client2 OIDC access_token,
try:
    client2.request_rpt(
        ticket=ticket,
        claim_token=client2_tokens.id_token,
        claim_token_format=IDT_FORMAT,
    )
    raise Exception("unreachable")
except:
    # it fails because client2 is not allowed to request "write" scope.
    pass

# When I request a ticket using client2 credentials and client1 OIDC access_token,
rpt_tokens = client2.request_rpt(
    ticket=ticket,
    claim_token=client1_tokens.id_token,
    claim_token_format=IDT_FORMAT,
    audience="client1",
)
# I get a RPT bound to client1 even though client2 is not allowed to request the "write" scope.
introspection = rs1.introspect_uma_token(rpt_tokens.access_token)
print(introspection)
assert introspection["active"] == True
assert introspection["azp"] == client1.client_id

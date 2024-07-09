import secrets

from requests import HTTPError

from common import make_client, extract_jwt_claims, extract_jwt_header

RESOURCE_TYPE = "http://www.example.com/resource1"
IDT_FORMAT = "http://openid.net/specs/openid-connect-core-1_0.html#IDToken"

client1 = make_client("client1", client_secret="client1-secret")
client2 = make_client("client2", client_secret="client2-secret")
rs1 = make_client("rs1", client_secret="rs1-secret")
rs2 = make_client("rs2", client_secret="rs1-secret")

resource = rs1.declare_resource(
    type=RESOURCE_TYPE, scopes=["read", "write"], name=secrets.token_urlsafe(8)
)
client_tokens = client1.request_password_grant(
    username="alice", password="alice", scope="openid"
)
ticket = rs1.request_ticket(id=resource, scopes=["write"])

rpt_tokens = client1.request_rpt(
    ticket=ticket,
    claim_token=client_tokens.id_token,
    claim_token_format=IDT_FORMAT,
)

TOKENS = [
    ("id_token", client_tokens.id_token),
    ("refresh_token", client_tokens.refresh_token),
    ("access_token", client_tokens.access_token),
    ("ticket", ticket),
    ("rpt", rpt_tokens.access_token),
    ("rpt:refresh_token", rpt_tokens.refresh_token),
]

# It's always the same answer anyway:
# CLIENTS = [client1, client2, rs1, rs2]
CLIENTS = [client1]

print(f"TOKEN CLIENT RESULT AZP AUD TYP DURATION SCOPE")
for token_name, token in TOKENS:
    for client in CLIENTS:
        res = "N/A"
        aud = "N/A"
        typ = "N/A"
        scope = "N/A"
        duration = "N/A"
        azp = "N/A"
        try:
            introspection = client.introspect_uma_token(token)
            res = introspection["active"]
            claims = extract_jwt_claims(token)
            header = extract_jwt_header(token)
            azp = introspection.get("azp", "N/A")
            aud = introspection.get("aud", "N/A")
            typ = introspection.get("typ", "N/A")
            scope = introspection.get("scope", "N/A").replace(" ", ",")
            try:
                duration = introspection.get("exp") - introspection.get("iat")
            except:
                pass
        except HTTPError as e:
            res = e.response.status_code
            pass
        print(
            f"{token_name} {client.client_id} {res} {azp} {aud} {typ} {duration} {scope}"
        )

import json
import base64
from typing import Optional, Any, List
from dataclasses import dataclass
import secrets

import jwt

import requests
from requests import Response, Session
from requests.auth import AuthBase, HTTPBasicAuth

from jwt.jwks_client import PyJWKClient


SYMMETRIC_ALGS = ["HS256"]
ASYMMETRIC_ALGS = ["RS256"]


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


def extract_jwt_claims(token: str):
    """
    Extract claims from JWT.

    This does not check the signature or anything!
    """
    encoded_claims = token.split(".")[1]
    encoded_claims += "=" * ((4 - len(encoded_claims) % 4) % 4)
    claims = json.loads(base64.urlsafe_b64decode(encoded_claims))
    return claims


def extract_jwt_header(token: str):
    """
    Extract claims from JWT.

    This does not check the signature or anything!
    """
    encoded_claims = token.split(".")[0]
    encoded_claims += "=" * ((4 - len(encoded_claims) % 4) % 4)
    claims = json.loads(base64.urlsafe_b64decode(encoded_claims))
    return claims


def dump_jwt(token: str, name: str = "token") -> None:
    claims = extract_jwt_claims(token)
    print(f"{name} = {json.dumps(claims, indent=2)}")


def is_json(content_type: Optional[str]) -> bool:
    return content_type is not None and (
        content_type == "application/json"
        or content_type.startswith("application/json;")
    )


def log_response(response: Response):
    if is_json(response.headers.get("content-type")):
        print(f"{response.status_code} {json.dumps(response.json(), indent=2)}")
    else:
        print(f"{response.status_code}")


def print_header(message: str):
    print(f"\n\n\x1B[32m{message}\x1B[0m")


@dataclass
class TokenResult:
    access_token: Optional[str]
    refresh_token: Optional[str]
    id_token: Optional[str]
    scope: Optional[str]

    @staticmethod
    def create(data: dict[str, Any]) -> "TokenResult":
        return TokenResult(
            access_token=data.get("access_token"),
            refresh_token=data.get("refresh_token"),
            id_token=data.get("id_token"),
            scope=data.get("scope"),
        )


class OauthClient:
    authorization_server: str
    client_id: str
    client_secret: str
    auth: Optional[AuthBase]

    oidc_config_endpoint: str
    uma2_config_endpoint: str

    oidc_config: dict[str, Any]
    uma2_config: Optional[dict[str, Any]]

    session: Session

    jwk_client: PyJWKClient

    def __init__(
        self,
        authorization_server: str,
        client_id: str,
        client_secret: str,
        session: Optional[Session] = None,
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        if client_secret is not None:
            self.auth = HTTPBasicAuth(client_id, client_secret)
        else:
            self.auth = None

        self.session = session if session is not None else Session()

        self.authorization_server = authorization_server
        self.oidc_config_endpoint = (
            authorization_server + "/.well-known/openid-configuration"
        )
        self.uma2_config_endpoint = (
            authorization_server + "/.well-known/uma2-configuration"
        )

        self.oidc_config = session.get(self.oidc_config_endpoint).json()
        try:
            self.uma2_config = session.get(self.uma2_config_endpoint).json()
        except:
            self.uma2_config = None

        self.jwk_client = PyJWKClient(self.oidc_config["jwks_uri"])

    def request_access_token(self, scope: Optional[str] = None) -> TokenResult:
        data = {"grant_type": "client_credentials"}
        if scope is not None:
            data["scope"] = scope
        if self.auth is None:
            data["client_id"] = self.client_id
        response = self.session.post(
            self.uma2_config["token_endpoint"],
            auth=self.auth,
            data=data,
        )
        response.raise_for_status()
        return TokenResult.create(response.json())

    def declare_resource(
        self,
        scopes: List[str],
        name: Optional[str] = None,
        description: Optional[str] = None,
        type: Optional[str] = None,
        auth: Optional[AuthBase] = None,
    ) -> str:
        data = {"resource_scopes": scopes}
        if name is not None:
            data["name"] = name
        if type is not None:
            data["type"] = type
        if description is not None:
            data["description"] = description
        if auth is None:
            auth = BearerAuth(self.request_access_token().access_token)
        response = self.session.post(
            self.uma2_config["resource_registration_endpoint"],
            auth=auth,
            json=data,
        )
        response.raise_for_status()
        return response.json()["_id"]

    def request_ticket(
        self, id: str, scopes: List[str], auth: Optional[AuthBase] = None
    ):
        if auth is None:
            auth = BearerAuth(self.request_access_token().access_token)
        response = self.session.post(
            self.uma2_config["permission_endpoint"],
            auth=auth,
            json=[
                {
                    "resource_id": id,
                    "resource_scopes": scopes,
                }
            ],
        )
        response.raise_for_status()
        return response.json()["ticket"]

    def request_password_grant(
        self, username: str, password: str, scope: Optional[str] = None
    ):
        """
        Password-credentials grant.

        This is deprecated but is still quite useful for automated tests.
        """
        data = {
            "grant_type": "password",
            "response_type": "code",
            "username": username,
            "password": password,
        }
        if scope is not None:
            data["scope"] = scope
        if self.auth is None:
            data["client_id"] = self.client_id
        response = self.session.post(
            self.oidc_config["token_endpoint"], auth=self.auth, data=data
        )
        response.raise_for_status()
        return TokenResult.create(response.json())

    def request_rpt(
        self,
        ticket: Optional[str] = None,
        auth: Optional[AuthBase] = None,
        claim_token: Optional[str] = None,
        claim_token_format: Optional[str] = None,
        rpt: Optional[str] = None,
        # Some keycloak-specific parameters:
        subject_token: Optional[str] = None,
        audience: Optional[str] = None,
    ) -> TokenResult:
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
        }
        if ticket is not None:
            data["ticket"] = ticket
        if rpt is not None:
            data["rpt"] = rpt
        if claim_token is not None:
            data["claim_token"] = claim_token
        if claim_token_format is not None:
            data["claim_token_format"] = claim_token_format
        if subject_token is not None:
            data["subject_token"] = subject_token
        if audience is not None:
            data["audience"] = audience
        if auth is None and self.auth is None:
            data["client_id"] = self.client_id
        response = self.session.post(
            self.uma2_config["token_endpoint"],
            auth=auth if auth is not None else self.auth,
            data=data,
        )
        response.raise_for_status()
        return TokenResult.create(response.json())

    def introspect_token(self, token: str, type: Optional[str] = None) -> dict:
        data = {"token": token}
        if type is not None:
            data["token_type_hint"] = type
        if self.auth is None:
            data["client_id"] = self.client_id
        response = self.session.post(
            self.oidc_config["introspection_endpoint"],
            auth=self.auth,
            data=data,
        )
        response.raise_for_status()
        return response.json()

    def introspect_uma_token(self, token: str, type: Optional[str] = None) -> dict:
        data = {"token": token}
        if type is not None:
            data["token_type_hint"] = type
        if self.auth is None:
            data["client_id"] = self.client_id
        response = self.session.post(
            self.uma2_config["introspection_endpoint"],
            # NOTE, the standard requires using the PAT but currently only works using client credentials
            auth=self.auth,
            # auth=BearerAuth(self.request_access_token().access_token),
            data=data,
        )
        response.raise_for_status()
        return response.json()

    def decode_jwt(self, token: str):
        header = extract_jwt_header(token)
        alg = header.get("alg")
        kid = header.get("kid")

        if alg in SYMMETRIC_ALGS:
            return jwt.decode(token, self.client_secret, algorithms=SYMMETRIC_ALGS)
        elif alg in ASYMMETRIC_ALGS:
            key = self.jwk_client.get_signing_key(kid)
            return jwt.decode(token, key.key, algorithms=ASYMMETRIC_ALGS)
        else:
            raise Exception("Unexpected alg")

    def get_authorization_server_jwks(self) -> dict:
        response = self.session.get(self.oidc_config["jwks_uri"])
        response.raise_for_status()
        return response.json()


def register_client(
    authorization_server: str,
    redirect_uris: Optional[List[str]],
    client_name: Optional[str] = None,
    session: Optional[Session] = None,
    auth: Optional[AuthBase] = None,
    grant_types: Optional[List[str]] = None,
) -> OauthClient:
    if session is None:
        session = Session()

    response = session.get(authorization_server + "/.well-known/openid-configuration")
    response.raise_for_status()
    openid_config = response.json()

    registration_endpoint = openid_config["registration_endpoint"]

    req = {}
    if client_name is not None:
        req["client_name"] = client_name
    if redirect_uris is not None:
        req["redirect_uris"] = redirect_uris
    if grant_types is not None:
        req["grant_types"] = grant_types
    response = session.post(
        registration_endpoint,
        auth=auth,
        json=req,
    )
    response.raise_for_status()
    res = response.json()
    return OauthClient(
        authorization_server=authorization_server,
        client_id=res["client_id"],
        client_secret=res["client_secret"],
        session=session,
    )


UMA_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:uma-ticket"

STANDARD_GRANT_TYPES = [
    "authorization_code",
    "implicit",
    "password",
    "client_credentials",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:saml2-bearer",
]

GRANT_TYPES = STANDARD_GRANT_TYPES + [UMA_GRANT_TYPE]


AS_URI = "http://localhost:8180/realms/poc"


def make_client(client_id: str, client_secret: Optional[str] = None) -> OauthClient:
    return OauthClient(
        authorization_server=AS_URI,
        client_id=client_id,
        client_secret=client_secret,
    )


def parse_bearer(value: str) -> Optional[str]:
    tokens = value.split(" ")
    if len(tokens) == 2 and tokens[0].lower() == "bearer":
        return tokens[1]
    else:
        return None

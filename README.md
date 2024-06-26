Minimal applications for testing UMA on Keycloak.

Warning: This software is not intended to be secure.
For example,

* it is vulnerable to CSRF;
* it does not use PKCE;
* it uses hardcoded credentials (and bad),
* etc.

## Execution

### Running the test

`test_rs_resource.py` is a standalone program
which tests several UMA-related exchanges
with a KeyCloak instance.

~~~sh
./poc run keycloak
~~~

~~~sh
python3 ./test_rs_resource.py
~~~

### Running the environment

We can execute an execution environment with a KeyCloak instance, a client application and a resource server.

~~~sh
./poc run keycloak
~~~

~~~sh
./poc run client
~~~

~~~sh
./poc run rs
~~~

~~~sh
./poc browse
~~~

## Environment

### Components

* Keycloak (OAuth/UMA authorization server, OpenID Provider)
* `client.py`, client application (web based)
* `rs.py`, Target/true resource server

| Application | URL                   | client_id | client_secret
|-------------|-----------------------|-----------|----
| Keycloak    |http://localhost:81080 |           |
| Client      |http://localhost:81081 | client    | client-secret
| RS          |http://localhost:81082 | rs        | rs-secret

### Users

|Realm  | Login | Password
|-------|-------|---------
|admin  | admin | admin
|test   | alice | alice
|test   | bob   | bob

### Protected resources

| Application | Ressource name          | Scope
|-------------|-------------------------|--------
| Client      | Root Protected Resource | access


## Unexpected behaviors

#### ISSUE-1, RPT Request authentication

The [UMA RPT Request](https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html#uma-grant-type)
uses the RqP's OIDC AT instead of the client credentials.
Using the client credentials gives a 403:

~~~json
{"error":"access_denied","error_description":"request_submitted"}
~~~

For the following request:

~~~json
[
    {
        "resource_id": "...",
        "resource_scopes": ["read"],
    }
]
~~~

### ISSUE-2, RPT introspection authentication

Keycloak does not accept the PAT as authentication for the UMA introspection API. This fails with a 401:

~~~json
{"error":"invalid_request","error_description":"Authentication failed."}
~~~

The UMA spec says:

> Introspect the RPT at the authorization server using the OAuth token introspection endpoint (defined in [RFC7662]
> and this section) **that is part of the protection API**

and

> Use of these endpoints assumes that the resource server has acquired OAuth client credentials from the authorization server by static or dynamic means, and has a valid PAT. Note: Although the resource identifiers that appear in permission and token introspection request messages could sufficiently identify the resource owner, the PAT is still required because it represents the resource owner's authorization to use the protection API, as noted in Section 1.3.

### ISSUE-3, Missing permissions in RPT introspection

The UMA introspection of the RPT does not provide the "permissions" field.

RPT content:

~~~json
{
  "exp": 1719361310,
  "iat": 1719361010,
  "auth_time": 1719359420,
  "jti": "2cd18b23-1c7d-4fc0-9eb2-7b12ebff5a4d",
  "iss": "http://localhost:8180/realms/poc",
  "aud": "rs",
  "sub": "d7093c2b-895e-413a-884c-3525f04ce0cd",
  "typ": "Bearer",
  "azp": "client",
  "sid": "0b41b4f6-76f3-44fc-9498-a3d3a26ecc41",
  "acr": "1",
  "allowed-origins": [
    "http://localhost:8081"
  ],
  "realm_access": {
    "roles": [
      "user"
    ]
  },
  "authorization": {
    "permissions": [
      {
        "scopes": [
          "read"
        ],
        "rsid": "0ce7280a-63ac-455f-aa26-f50b81a41ba9",
        "rsname": "Protected Resource"
      }
    ]
  },
  "scope": "email profile",
  "email_verified": false,
  "name": "Alice Liddel",
  "preferred_username": "alice",
  "given_name": "Alice",
  "family_name": "Liddel",
  "email": "alice@example.com"
}
~~~

Introspection response:

~~~json
{
  "exp": 1719361310,
  "iat": 1719361010,
  "auth_time": 1719359420,
  "jti": "2cd18b23-1c7d-4fc0-9eb2-7b12ebff5a4d",
  "iss": "http://localhost:8180/realms/poc",
  "aud": "rs",
  "sub": "d7093c2b-895e-413a-884c-3525f04ce0cd",
  "typ": "Bearer",
  "azp": "client",
  "sid": "0b41b4f6-76f3-44fc-9498-a3d3a26ecc41",
  "acr": "0",
  "allowed-origins": [
    "http://localhost:8080"
  ],
  "realm_access": {
    "roles": [
      "user"
    ]
  },
  "scope": "email profile",
  "email_verified": false,
  "name": "Alice Liddel",
  "preferred_username": "alice",
  "given_name": "Alice",
  "family_name": "Liddel",
  "email": "alice@example.com",
  "client_id": "client",
  "username": "alice",
  "token_type": "Bearer",
  "active": true
}
~~~

#### ISSUE-4, Document ID token claim_token_format is not recognized

`claim_token_format=https://openid.net/specs/openid-connect-core-1_0.html#IDToken`
(which is the documented value for ID token) is not recognized.
`http://openid.net/specs/openid-connect-core-1_0.html#IDToken`
if the value recognized by Keycloak.

`urn:ietf:params:oauth:token-type:id_token` should probably be recognized
as it seems to be more standard.


## References:

* [KeyCloak 25.0 Authorization Services Guide](https://www.keycloak.org/docs/25.0.0/authorization_services/)
* [User-Managed Access (UMA) 2.0 Grant for OAuth 2.0 Authorization](https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html)
* [Federated Authorization for User-Managed Access (UMA) 2.0](https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html)

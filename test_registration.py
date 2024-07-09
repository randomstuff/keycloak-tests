# Test client registration.
#
# Currently working for WSO2 IS.
# - Supports client registration using admin credentials.

import os
import secrets

import urllib3

from requests.auth import HTTPBasicAuth
from requests import Session

from common import register_client, GRANT_TYPES

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

AS_URI = os.environ["AS_URI"]

session = Session()
session.verify = False

auth = HTTPBasicAuth("admin", "admin")
client = register_client(
    client_name=secrets.token_urlsafe(20),
    authorization_server=AS_URI,
    session=session,
    auth=auth,
    redirect_uris=["http://localhost:8080/callback"],
    grant_types=GRANT_TYPES,
)
print(client.client_id)
print(client.client_secret)

# Tests for OAuth

Very simple code used to the test OAuth protocols and implementations
(including OpenID Connect, UMA).

For more details see the doc/ directory.

## Scope

Topics:

* mostly security
* and conformance as well

Protocols:

* OAuth
* OIDC
* UMA

Authorization servers:

* Keycloak (main focus for now)
* WSO2 IS (very limited)

## Warning

This software is not intended to be secure but to have the quickest path to check some behaviors
in several OAuth/OpenID Connect/UMA implementations.

For example,

* it is vulnerable to CSRF;
* it uses the password grant;
* it does not use PKCE;
* it uses hardcoded (and bad) credentials,
* etc.

## References

OAuth 2.x:

* [OAuth 2.x specifications](https://oauth.net/2/)
* [OAuth at IETF Data Tracker](https://datatracker.ietf.org/wg/oauth/documents/)

OpenID:

* [OpenID specifications](https://openid.net/developers/specs/)

UMA 2.0:

* [User-Managed Access (UMA) 2.0 Grant for OAuth 2.0 Authorization](https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html)
* [Federated Authorization for User-Managed Access (UMA) 2.0](https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html)
* [User-Managed Access (UMA) 2.0 Grant for OAuth 2.0 Authorization](https://datatracker.ietf.org/doc/html/draft-maler-oauth-umagrant-00), IETF draft
* [Federated Authorization for User-Managed Access (UMA) 2.0](https://datatracker.ietf.org/doc/html/draft-maler-oauth-umafedauthz-00), IETF draft

UMA 1.0:

* [UMA 1.0 Core](https://docs.kantarainitiative.org/uma/rec-uma-core-v1_0.html)
* [UMA 1.0 / OAuth 2.0 Resource Set Registration](https://docs.kantarainitiative.org/uma/rec-oauth-resource-reg-v1_0_1.html)

UMA and healthcare:

* [Health Relationship Trust Profile for User-Managed Access 2.0](https://openid.net/specs/openid-heart-uma2-1_0.html)
* [Health Relationship Trust Profile for Fast Healthcare Interoperability Resources (FHIR) UMA 2 Resources](https://openid.net/specs/openid-heart-fhir-uma2-1_0.html)
* [Patient-Centric Data Sharing with UMA](https://kantara.atlassian.net/wiki/spaces/uma/pages/172687365/Patient-Centric+Data+Sharing+with+UMA)

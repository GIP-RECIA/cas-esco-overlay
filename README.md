ESCO CAS Overlay
================

This is an overlay for CAS 5.2.0 featuring LDAP authentication and
OpenID Connect customized with JWT access and refresh token.

Configuration
-------------

Copy `config.example` directory to `config` and set following properties:

- `etc/cas/config/cas.properties`
    - `cas.authn.ldap[0].bindCredential`: Password of LDAP system account.

- JWKS can be generated (keystore.jwks) with [mkjwk.org](https://mkjwk.org/).
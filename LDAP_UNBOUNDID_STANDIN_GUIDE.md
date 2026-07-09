# UnboundID LDAPS stand-in — a turnkey LDAP server for TLS/mTLS testing

The LDAP TLS test scenarios (SNI, hostname verification, mutual TLS, the protocol floor) run against
**any** LDAPS instance — self-hosted, OpenLDAP, UnboundID, Active Directory, etc. If you already have
one, point the scenarios at it and skip this guide.

If you **don't** have a directory handy, this repo ships a self-contained stand-in: an in-memory
**UnboundID** LDAPS directory (`./gradlew ldapMtlsServer`) that performs a **real bind** and, with
client auth on, **requires and verifies a client cert** — LDAPS + mTLS in one small process.
**Authentication only** — no group/role resolution (test that against a real directory).

It reuses the OpenSearch install's **own demo PKI** already in `$OPENSEARCH_HOME/config/`
("Example Com Inc."): `esnode` (server cert, SAN includes `localhost`), `root-ca.pem` (trust anchor),
`kirk` (client cert) — all chaining to one root. The stand-in is pointed at this PKI (below), so
OpenSearch reuses the certs already in `config/` and **copies nothing**.

The stand-in itself runs on a **non-FIPS JVM** (JKS keystores) — fine, it's the *server*; OpenSearch is
the FIPS side under test.

## Build the keystore + truststore

Build them from the install's demo PEMs (once), so the stand-in speaks the **same PKI** OpenSearch
already trusts from `config/`:

```bash
CFG="$OPENSEARCH_HOME/config"; S=/tmp/ldap-standin        # any scratch dir
mkdir -p "$S"

# Server keystore (node identity) from the esnode cert + key.
openssl pkcs12 -export -in "$CFG/esnode.pem" -inkey "$CFG/esnode-key.pem" \
  -name node-0 -out "$S/esnode.p12" -passout pass:changeit
keytool -importkeystore -noprompt -srcstoretype PKCS12 -srcstorepass changeit -deststorepass changeit \
  -srckeystore "$S/esnode.p12" -destkeystore "$S/esnode-keystore.jks"

# Truststore (to verify client certs) from the root CA.
keytool -importcert -noprompt -alias root-ca -file "$CFG/root-ca.pem" \
  -keystore "$S/install-truststore.jks" -storepass changeit
```

## Start it

```bash
./gradlew ldapMtlsServer \
  -Dserver.keystore="$S/esnode-keystore.jks" -Dserver.keystore.password=changeit \
  -Dtruststore="$S/install-truststore.jks"  -Dtruststore.password=changeit
# → Local LDAPS mTLS stand-in listening on localhost:8636  (client cert REQUIRED, base o=TEST, LDIF=…/local-mtls.ldif)
```

`esnode`'s SAN covers `localhost`/`127.0.0.1`/`::1`, so `verify_hostnames: true` passes. Overridable
`-D` properties (all optional): `ldaps.port` (default `8636`), `server.keystore`,
`server.keystore.password`, `truststore`, `truststore.password`, `ldif`, `need.client.auth` (default
`true`).

> **Always pass the `-D` stores.** With no `-D`, the runner falls back to its built-in repo demo
> keystores (`src/test/resources/ldap/`, a *different* CA with the same DN), which won't trust the
> install's `config/` certs — the handshake then fails confusingly.

## Quick TLS self-check (no OpenSearch)

From `$OPENSEARCH_HOME/config/`:

```bash
# Client cert presented → full handshake, chain verifies.
echo | openssl s_client -connect localhost:8636 -cert kirk.pem -key kirk-key.pem -CAfile root-ca.pem 2>/dev/null \
  | grep -E "subject=|Verify return"
# → subject=… CN=node-0.example.com   /   Verify return code: 0 (ok)

# No client cert → mTLS enforced. Hold the connection open with `sleep 1` (not `echo`/`</dev/null`):
# TLS 1.3 sends `certificate_required` *after* the handshake, so a client that closes on stdin EOF
# exits before reading it. The alert is on stderr, hence `2>&1`.
sleep 1 | openssl s_client -connect localhost:8636 -CAfile root-ca.pem 2>&1 | grep -i "certificate required"
# → …tlsv13 alert certificate required… (SSL alert 116)   (mTLS enforced)
```

## The directory (DIT)

The LDIF (`src/test/resources/ldap/local-mtls.ldif`) defines a minimal `o=TEST` tree — a service
account to bind as and one end user to authenticate:

```text
o=TEST
└── ou=people
    ├── cn=opensearch-bind   (uid=opensearch-bind, userPassword=bindpassword)   ← bind_dn
    └── cn=Test User         (uid=testuser,        userPassword=testpassword)   ← the login under test
```

## Files

- Runner: `src/test/java/org/opensearch/security/auth/ldap/srv/LocalLdapMtlsServer.java`
- DIT: `src/test/resources/ldap/local-mtls.ldif`
- Gradle task: `ldapMtlsServer` (`build.gradle`)

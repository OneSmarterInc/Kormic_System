# Ammar branch: HQ authentication fixes

These changes are local and tested with disposable PostgreSQL. No production
organization, YubiKey configuration, or private-key handoff has been performed.

## Administrator key

Set `MESHKOR_ADMIN_PUBKEY_SHA256` to the lowercase SHA-256 hex digest of the
approved EC public key encoded as DER SubjectPublicKeyInfo. This is NOT the
hash of a PEM file or a certificate. Export only the public key from the YubiKey.
For a PEM public-key export, compute the pin with:

```bash
openssl pkey -pubin -in admin-public.pem -outform DER | openssl dgst -sha256
```

Configure the digest via the service environment. Non-development startup rejects
missing pins; malformed pins are rejected in all modes. Development with no pin
cannot authenticate a Super-Admin. A matching key must still prove possession
by signing the server challenge using ECDSA/SHA-256. Challenges expire after 60
seconds and are consumed on the first authentication attempt, including failures.
Sessions and challenges remain process-local, as before.

The existing production restriction on SoftwareKeyCustody remains in place;
these fixes do not replace it with a production custody provider.

## Organization isolation

Revoke, unblock, wake and download lock the twin's ownership row, then check the
session before any mutation or payload read. Non-Super-Admins must be ORG_ADMIN
with a nonempty matching organization. Cross-organization requests return 403;
unknown AINs return 404. Database transactions commit before registry mutation.
The existing in-memory registry is not a distributed transaction with PostgreSQL.

## Organization keys

HQ no longer accepts a global environment API key or the legacy shared key.
Create each organization through `/api/v1/auth/signup`; its `mk_live_` key is
returned only in the signup response and stored as a hash. Login does not return
it again. Retain it in the client's secret store, never a repository or log.
Existing valid database-backed organization keys continue to work. Existing
clients using the removed fallback must be provisioned through signup and have
their existing AIN ownership reviewed before migration; this patch does not
silently reassign production data. Password hashing, session expiry and HTTPS
are separate follow-up work, not addressed by these three fixes.

## Repeatable local tests (Linux or WSL, PostgreSQL 16 installed)

Use an isolated virtual environment. Do not source the repository `.env`.

```bash
python3 -m venv /tmp/meshkor-hq-ammar-venv
/tmp/meshkor-hq-ammar-venv/bin/pip install -r requirements-hq.txt -r requirements-hq-test.txt
PATH="/usr/lib/postgresql/16/bin:$PATH" /tmp/meshkor-hq-ammar-venv/bin/python -m pytest -q
```

Run as a non-root user. The fixture starts disposable PostgreSQL and sets the
connection before database tests run. It skips only database-dependent tests if
`pg_ctl` is absent; acceptance requires PostgreSQL installed and zero skips.
Tests generate temporary EC keys and organization credentials. These are not
production credentials and must not be handed to Vikram.

Verified on 2026-10-28 using Python 3.12 and disposable PostgreSQL 16: 167 passed, 0 skipped. One upstream Starlette/httpx deprecation warning; no test failures.

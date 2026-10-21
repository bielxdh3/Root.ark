# Root.ark #65 — independent CAS/witness mTLS peer-pin isolation

**Scope:** fix an actual certificate pin-bypass in the network clients already
used for CAS and witness protected-content authorization. The change does not
provision an independent authority, approve the normative protocol or authorize
production deployment. **Production remains NO-GO.**

## Trust boundary and reproduced failure

Four independently configured clients accepted their own
`serverFingerprint256`, but used the shared Node HTTPS agent:

- `zk1WitnessHttpsClient`: signed witness head, reservations and I/O admission
- `zk1CasManifestHttpsClient`: committed public manifest fetched during
  protected HTTP GET/PUT authorization
- `zk1CasStatusHttpsClient`: CAS terminal status proof
- `zk1CasWriteHttpsClient`: CAS registration and signed manifest commit

`checkServerIdentity` only runs when TLS establishes a socket. Node can reuse
an HTTPS keep-alive socket keyed by endpoint, TLS CA and client certificate,
without applying another **client instance's different server pin** to the
already-connected socket. An independent authority endpoint is not trusted
merely because an earlier request using a different pin succeeded.

The adversarial regression
`test/issue-65-authority-https-pin-reuse.test.js` creates **real, ephemeral
OpenSSL** CA/server/client certificates, a real mTLS listener and an explicit
shared keep-alive agent. For each client, it first sends a valid pinned request
then makes another request from a client whose pin is intentionally wrong.
On the original implementation the second witness request **succeeded**
instead of rejecting the pin: real TLS **RED**.

## Correction and verification

All four clients now set `agent: false` for each HTTPS request, preventing
socket reuse from another instance and forcing certificate pin verification
for **each network call**, as already done by
`zk1SharedPgGateHttpsClient`. The existing CA chain, hostname and TLSv1.3
checks remain in force; pin failures return generic transport errors.

After correction:

- `node --test test/issue-65-authority-https-pin-reuse.test.js`:
  **1/1 PASS native Windows and 1/1 PASS WSL Node 22**.
- Existing real mTLS CAS status, witness and protected bootstrap regression
  tests executed alongside the new regression: **4/4 PASS native Windows**.

This is an important **necessary** hardening for the online authority trust
boundary, not a claim that a single machine emulates two truly independently
operated services. It does not create a distributed linearizable rollback-safe
witness, a production-pinned signer, atomic nonce + admission + I/O effect,
remote provider fencing, or full user-facing device/recovery workflows.

## Separate opt-in authority identities at bootstrap

The normal application already mounts an experimental, development/test-only
protected ciphertext route by explicit operator configuration. Its bootstrap
now rejects configurations that try to designate CAS and witness using the
**same SHA-256 TLS peer certificate pin**, the **same client private key** or
the **same client certificate**, even if the credential files have different
paths or equivalent PEM formatting. The guard parses the private key and X.509
certificate, compares canonical SPKI/DER identities and requires that each
configured certificate match its private key. Invalid PEM fails closed before
the protected-content SQLite file is opened.
It accepts a shared CA root where separate server certificates/client
credentials are provisioned; sharing a CA is not evidence of sharing a
service/operator. This negative control does **not** establish that CAS and
witness execute on different physical hosts or have separately held signing
keys. Separate operator-root attestation and deployment evidence remain
mandatory for normative authorization.

`test/issue-65-protected-content-bootstrap.test.js` reproduced a missing
rejection (RED) for an identical server pin, then passed (GREEN) after the
separation guard. Independent review found a P2 gap with raw PEM-byte
comparison: a second RED regression used a real RSA private key and X.509
certificate with equivalent valid leading whitespace, then passed once the
decoded identities were compared. The existing content-route and signed
CAS/witness recovery regression tests also passed (**3/3 PASS** native Node).

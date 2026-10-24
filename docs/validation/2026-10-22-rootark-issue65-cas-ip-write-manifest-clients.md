# Issue #65 — CAS write and manifest clients over pinned private IP

The CAS write and manifest HTTPS clients now omit TLS SNI when the configured
endpoint uses a literal IP address. DNS endpoints retain their existing SNI.
The change follows `zk1CasStatusHttpsClient` and retains TLS 1.3, required
mTLS, trusted CA verification, the host's IP SAN verification by
`tls.checkServerIdentity`, and exact SHA-256 peer certificate fingerprint pin.
The strict writer base URL and manifest `/v1/manifest` URL restrictions are
unchanged. The CAS server still enforces per-certificate roles and scopes;
write acknowledgements and manifest bytes alone do not authorize ZK content.

## Bounded validation

- `test/issue-65-cas-private-ip-clients.test.js` exercises real HTTPS on an
  **OS-assigned RFC1918 interface**, generates disposable certificates with
  the exact IP SAN, and checks absence of SNI for successful write and
  manifest transports. It checks wrong SAN even with correct CA and matching
  fingerprint, wrong fingerprint, wrong client mTLS identity/role, and invalid
  endpoint paths. The stand-alone fixture server intentionally returns only
  synthetic CAS acknowledgements and untrusted manifest bytes.
- `test/issue-65-cas-status-mtls-http.test.js` exercises the **real CAS
  ledger** on the assigned private adapter with a signed witness ticket,
  register, commit, idempotent replay, committed manifest and history, and
  denial on wrong peer role, scope, SAN, fingerprint, or endpoint path.
- Windows native Node.js **22.23.0** and Node.js **24.14.1** both pass the
  SQLite-independent private-IP HTTPS/SNI test. The signed-ledger integration
  passed on Node.js 24. Linux and full Node.js 22 ledger integration were not
  established (the available `better-sqlite3` addon targets Node.js 24 ABI).

## Limits and open gate

Both tests use a locally assigned private adapter in one host, without an
independent remote operator, real two-host network, firewall controls,
cross-host durable receipt confirmation, external witness/CAS administration,
or remote storage I/O fencing. The experimental CAS status signer, witness
and data path are not a production-ready distributed authority. **Issue #65
remains NO-GO for production.**

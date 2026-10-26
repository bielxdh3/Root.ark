# Issue #65: standalone witness private-interface transport (experimental)

`scripts/zk1-witness-standalone.js` accepts an assigned RFC1918 IPv4 listener
only when independently pinned by the operator. Ordinary configurations still
accept only `127.0.0.1` or `::1`, with no private-bind environment variables.
This is a transport extension to the independent witness; it does not claim
distributed witness/CAS durability or safe production custody.

To opt in, the operator must set all three values together:

1. `listenHost`: one literal, canonical, assigned RFC1918 IPv4 address in the
   standalone witness JSON configuration.
2. `ROOTARK_ZK1_WITNESS_PRIVATE_BIND_HOST`: the **exact same** address, in the
   process environment independently of editable JSON.
3. `ROOTARK_ZK1_WITNESS_PRIVATE_BIND_INTERFACE`: the exact OS adapter name as
   reported by `os.networkInterfaces()`. This adapter must own the pinned IP.

The witness rejects partial pins, wildcard, public, CGNAT, link-local, mapped
IPv6, IPv6 non-loopback, DNS aliases, loopback alternatives, missing interface,
and mismatched IP/interface during configuration. It independently checks the
same assignment and exact bound address after `listen()`; failure drains the
listener. The provisioned server certificate **must** contain a matching IP SAN.
The clients preserve CA verification, TLS 1.3, mutual certificate authentication,
exact peer SHA-256 fingerprint, roles/scopes, nonce freshness, and Ed25519
signer pinning; IP endpoints omit DNS SNI but still verify the IP SAN.

## Validation

Windows Node.js 24 with `node --test test/issue-65-witness-mtls-http.test.js
test/issue-65-witness-cas-anchor-standalone.test.js`: **2 PASS / 0 FAIL**.
Disposable real HTTPS/mTLS listener processes were exercised on an assigned
private adapter, including a signed durable witness-head read and the separately
scoped CAS floor's nonce-bound signed head. Negative tests covered wrong/missing
operator pins, wrong interface, missing IP SAN, wildcard/public/CGNAT binds,
wrong peer fingerprint, alien scope, revoked head role, unauthorized principal,
foreign client CA, and mismatched signed status identity. `git diff --check`
and Node 22 `--check` syntax passed.

Windows Node 22 full integration was attempted but could not start SQLite:
existing `better-sqlite3` was compiled for Node 24 (native ABI 137 instead of
127). Linux/WSL Node 22 and real second-host transport were not validated.
No external deployment, firewall changes, independent operator custody,
network-continuity monitoring, external durability, or physical I/O fencing
is implied. The OS may reassign an interface after startup checks; operator
network isolation and monitoring are still required. Issue #65 remains NO-GO
for production use as a distributed zero-knowledge recovery system.

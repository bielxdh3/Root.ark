# Issue #65: standalone CAS private-interface transport (bounded experiment)

`scripts/zk1-cas-status-standalone.js` now permits an explicitly provisioned
CAS/status HTTPS listener on one assigned RFC1918 IPv4 address. Its ordinary
configuration still binds only `127.0.0.1` or `::1`. No default remote listener
is introduced. The new behavior does not affect the witness standalone server.

To opt in, the operator must perform **all** of the following:

1. Set `listenHost` in the existing strict JSON configuration to the **literal**
   private IP assigned to the intended host adapter. Set a suitable `listenPort`.
2. Set `ROOTARK_ZK1_CAS_PRIVATE_BIND_HOST` to that **exact same IP**, and
   `ROOTARK_ZK1_CAS_PRIVATE_BIND_INTERFACE` to the OS interface name from
   `os.networkInterfaces()`; both variables are mandatory and are independent
   of the JSON file. The process rejects partial, stale, and mismatching pins.
3. Provision an HTTPS server certificate with an IP subjectAltName for the
   exact listen address. Client endpoints must validate that SAN, their trusted
   CA **and** their pinned server SHA-256 fingerprint. Continue provisioning
   distinct client certificate fingerprints, explicit roles and precise scope
   grants in `principals`. The signer key and witness key pins are unchanged.

The process rejects wildcard, public, link-local, CGNAT, mapped IPv6, unassigned
private IP and wrong-interface binds before opening its CAS ledger. It checks
the interface assignment again after listening and closes on mismatch. HTTPS
requires TLS 1.3, mTLS with a client CA, certificate-fingerprint identity,
per-route roles, and per-scope grants. An IP-address client endpoint does not
emit an invalid IP SNI value; its IP SAN and peer fingerprint are still checked.

## Validation and limits

On Windows Node.js 24, `node --test test/issue-65-cas-status-mtls-http.test.js`
passed **1/1** including existing signed CAS status/commit flows, hostile
startup configurations, and an HTTPS/mTLS read on an assigned non-loopback
RFC1918 interface. A valid remote-IP cert SAN was created using an entirely
disposable test CA. A wrong client role, alien scope, wrong server fingerprint,
and missing/mismatching operator pins are denied. `git diff --check` passed.

Ubuntu/WSL Node.js 22 was attempted but the worktree's existing Windows native
`better-sqlite3` binding returned `invalid ELF header`; that run proves no Linux
transport behavior. No two-namespace Docker test, second host, independent
operator custody, cross-host durability, firewall enforcement, reliable
network-continuity guarantee, or physical storage I/O fencing was established.
The operating system may reassign an IP **after** the startup checks; network
policy and operational monitoring remain external responsibilities. CAS engine
status alone never authorizes protected content release. Issue #65 remains
NO-GO for production as a distributed witness/CAS system.

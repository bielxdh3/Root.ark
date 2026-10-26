# Root.ark independent catalog browser CSP

The authenticated workspace at `/` or `/index.html` can send direct CORS POST
probes to two independently configured catalog authorities. Its default
`connect-src` allows only the application origin and WebSocket schemes; a
browser otherwise refuses these POSTs before CORS or signature validation.

For a deployment that explicitly trusts the browser destinations, configure
`ROOTARK_ZK1_INDEPENDENT_CATALOG_CONNECT_ORIGINS` at Root.ark startup. Example:

```text
ROOTARK_ZK1_INDEPENDENT_CATALOG_CONNECT_ORIGINS=https://witness.example.net:8443,https://cas.example.net:8444
```

Values are **canonical origins**, not endpoint URLs: use exact lowercase
scheme, host, and any nondefault port; omit the path and trailing slash. The
HTTPS endpoint *paths* are still entered by the owner in the browser UI. Local
testing permits `http://localhost:<port>`, `http://127.0.0.1:<port>`, and
`http://[::1]:<port>` as origins. Public/plain HTTP, credentials, wildcards,
paths, queries, fragments, noncanonical forms, and malformed tokens fail
startup. An unset variable adds no external origin. No request-controlled
headers or UI field values contribute to CSP.

The extra origins appear only in the policy for `/` and `/index.html`, without
changing the other directives, share-page nonce, upload sandbox, or developer
WASM policy. Each independent authority must also enable CORS for the exact
Root.ark application origin, accept the browser's JSON POST preflight, and
return the independently signed CBOR proof. The browser omits credentials and
rejects redirects; CSP alone never proves an authority is trustworthy. Verify
the independently pinned authority keys before using catalog probes.

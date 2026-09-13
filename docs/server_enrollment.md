## Server discovery

The intro flow accepts one ordinary server address. It does not ask for an
enrollment artifact, a PEM, a fingerprint, or a checksum.

A public multi-label DNS name is verified through the platform TLS trust
store at:

```text
https://<normalized-domain>/.well-known/telegramd/client
```

The response is canonical JSON with no credentials or account data:

```json
{"version":1,"mtproto":{"endpoint":"mtproto.example.com:443","dc_id":2,"rsa_spki":"<standard padded base64 DER SubjectPublicKeyInfo>"}}
```

The client rejects redirects, certificate overrides, malformed or duplicate
JSON members, non-canonical base64, non-RSA or non-2048-bit keys, unsafe
delegated addresses, and a port that conflicts with an explicitly entered
port. Unknown response fields are ignored. A public selection never falls
back to local trust-on-first-use.

An eligible local or direct selection must include a port. This includes an
IP literal, `localhost`, a `.localhost`, `.local`, or `.home.arpa` name, and a
single-label hostname. Before any MTProto connection the client opens a fresh
anonymous TCP connection, writes
exactly the following request, and half-closes its write side:

```text
telegramd-key-v1 || 32-byte nonce
```

The server responds with the exact binary frame:

```text
telegramd-key-r1 || nonce || uint32(body_length) ||
int32(dc_id) || uint16(spki_length) || DER SubjectPublicKeyInfo
```

All integer fields are big-endian. The body length must be exactly
`6 + spki_length`, with `spki_length` from 1 through 4096. The client waits
for EOF, then checks the nonce, key, and DC id before closing the socket. The
preflight socket is never promoted into MTProto.

The normalized selection, selected policy, authenticated discovery origin,
and exact endpoint, DC, and RSA binding are committed to the account before
the username request. A failed, cancelled, stalled, or uncertain discovery
or persistence operation keeps the account on the server step and sends no
credential or account data.

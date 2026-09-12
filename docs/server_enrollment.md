## Server enrollment artifact

The client accepts one UTF-8 text artifact with this exact line-oriented
shape:

```text
telegramd-enrollment-v1
endpoint=100.64.0.5:443
public-key-begin
-----BEGIN PUBLIC KEY-----
<the complete public PEM, unchanged>
-----END PUBLIC KEY-----
public-key-end
checksum=sha256:<64 lowercase hexadecimal characters>
telegramd-enrollment-end
```

The PEM may use either `PUBLIC KEY` (SubjectPublicKeyInfo) or `RSA PUBLIC
KEY` (PKCS#1) armor. There must be exactly one `endpoint=` line, one
`public-key-begin` / `public-key-end` section, and one PEM key block. The
endpoint value is an IP literal or a DNS hostname with an explicit port from
1 through 65535. IPv6 literals use brackets, for example
`[2001:db8::1]:443`.

The parser trims only whitespace outside the artifact and converts CRLF to
LF. It normalizes a valid endpoint by lowercasing DNS names, rendering IP
literals with Qt's canonical address spelling, converting the port to
decimal, and retaining brackets around IPv6. The returned endpoint is thus a
single stable string such as `telegramd.example.com:443` or
`[2001:db8::1]:443`.

The checksum is SHA-256 over the UTF-8 bytes of the following canonical
payload, including the final LF after `public-key-end`:

```text
telegramd-enrollment-v1
endpoint=<normalized endpoint>
public-key-begin
<the PEM text after CRLF-to-LF conversion>
public-key-end
```

The checksum line and closing marker are not part of the payload. A changed
key, malformed key bytes, missing marker, truncated artifact, or any content
after `telegramd-enrollment-end` is rejected. The parser first validates the
endpoint and PEM so a damaged key receives its specific key reason; a changed
but still readable key fails the payload checksum as an unparseable envelope.

### Hand-generation example

Given an existing public PEM file named `server-public.pem` and the address
`100.64.0.5:443`, create the artifact without any server-side tool:

```bash
payload=$(mktemp)
{
    printf '%s\n' \
        'telegramd-enrollment-v1' \
        'endpoint=100.64.0.5:443' \
        'public-key-begin'
    awk '{ sub(/\r$/, ""); print }' server-public.pem
    printf '%s\n' 'public-key-end'
} > "$payload"
checksum=$(openssl dgst -sha256 -hex "$payload" | awk '{print $NF}')
{
    cat "$payload"
    printf 'checksum=sha256:%s\ntelegramd-enrollment-end\n' "$checksum"
} > server-enrollment.txt
rm "$payload"
```

Paste `server-enrollment.txt` as one value. After validation the client
returns the normalized endpoint, the validated RSA public key, and its
identity: the SHA-256 SubjectPublicKeyInfo digest rendered as 64 lowercase
hexadecimal characters in 16 groups of four. Compare that complete identity
with the server startup log's `key_id` before confirming enrollment.

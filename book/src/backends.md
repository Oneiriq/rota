# Backends

What ships today, what's coming, and the design choices behind each.

## CA backends

### Namecheap (traditional reissue)

`kind: namecheap` with `ssl_id: <numeric SSL id>`. Uses Namecheap's `namecheap.ssl.reissue` and `namecheap.ssl.getInfo` flow. Activation is one-shot: rota only handles **reissue** within an existing SSL subscription. First-time activation requires a long list of admin-contact fields rota does not model in the config. Operators activate once by hand in the Namecheap dashboard; rota handles every renewal after that.

DNS-01 only. The Namecheap reissue API folds every SAN under one DCV record, so rota's multi-challenge trait sees a single-element vec.

### ACME (RFC 8555)

`kind: acme`. Speaks Let's Encrypt, ZeroSSL (with External Account Binding), BuyPass, and any directory that follows the spec. Uses the [`instant-acme`](https://crates.io/crates/instant-acme) crate.

rota manages its own persistent ECDSA key per cert because operators rely on key continuity for cert pinning. The ACME submit path uses `finalize_csr(csr_der)` so the operator's key stays canonical across renewals.

The ACME backend walks the configured DCV solver's `supported_kinds()` to pick a challenge type per authorization. So `dcv: { kind: webroot }` automatically gets HTTP-01; `dcv: { kind: cloudflare }` automatically gets DNS-01.

## DCV backends

### Namecheap DNS

`kind: namecheap`. DNS-01 via `namecheap.domains.dns.{getHosts,setHosts}`.

Watch out: Namecheap's `setHosts` is a **full replacement** of every record on the domain, not a per-record edit. Publishing one TXT therefore requires reading every existing record first, merging the new one in, and writing the merged set back. rota does this transparently.

### Cloudflare DNS

`kind: cloudflare`. DNS-01 via Cloudflare's v4 API with Bearer-token auth. Token scopes: `Zone.DNS:Edit` on every zone rota will manage. rota does not support the legacy Global API Key.

Cloudflare's per-record edit API means rota doesn't have to read every record on the zone first. The flow: resolve the apex zone for the record name, look for an existing TXT match (idempotency), POST the record if absent. Removal mirrors the lookup-and-delete shape.

### Webroot (HTTP-01)

`kind: webroot` with `directory: <document root>`. rota writes the key authorization to `<directory>/.well-known/acme-challenge/<token>` (mode 644) and removes it after issuance. The operator's existing webserver (nginx, Caddy, Apache, anything that serves static files over HTTP on port 80) is responsible for actually exposing the directory.

Why webroot rather than a daemon-internal listener: most self-hosters already run a webserver on 80 and 443. Asking rota to bind 80 means coordinating port handoff (or running rota as root) for one purpose: serving a five-byte file the existing webserver could serve in its sleep.

Defensive against malformed challenge tokens: rota refuses path-shaped tokens (`/`, `\`, `..`, empty) so a misbehaving CA can't traverse out of the challenge directory.

## Install backends

### Synology DSM

`kind: dsm` with `description: <DSM panel label>`. Uses `synowebapi` to install the cert into DSM's certificate store. The cert id surfaces in the DSM Control Panel under the configured description.

### Filesystem

`kind: filesystem` with `directory: <path>`. Lays the issued cert, chain, and private key down under predictable filenames so any service that reads disk-based PEM (nginx, HAProxy, Caddy, custom Rust + rustls) can pick them up.

Filenames mirror the certbot convention so existing reload scripts that grep for `fullchain.pem` and `privkey.pem` work unchanged. Writes are atomic per file: each artifact goes to a sibling `.tmp`, fsync, rename.

### nginx

`kind: nginx` with `directory: <path>` and optional `reload_command: [<argv>]`. Filesystem write plus an nginx reload subprocess.

Default reload is `["nginx", "-s", "reload"]`. Operators on systemd typically override with `["systemctl", "reload", "nginx"]` and a sudoers rule that keeps the daemon unprivileged. The reload runs without a shell wrapper, so argv entries are not interpreted: no globbing, no env interpolation. A non-zero exit surfaces as an `Install` error so the renewer records the failure on the audit log.

### HAProxy

`kind: haproxy` with `directory:`, `socket_path:`, and `cert_storage_name:`. Filesystem write plus HAProxy runtime API hot-swap.

The runtime API sequence:

```text
set ssl cert <storage_name> <<EOL
<leaf + chain + key bundle>
EOL
commit ssl cert <storage_name>
```

No reload, no dropped TCP connections. HAProxy hands the new certificate to live SNI lookups on the next handshake. Requires HAProxy 2.x or later with the admin socket exposed:

```text
global
    stats socket /run/haproxy/admin.sock mode 660 level admin
```

### Kubernetes Secret

`kind: k8s_secret` with `namespace:`, `secret_name:`, and optional `kubeconfig_path:`. Server-side applies a `kubernetes.io/tls` Secret. Drop-in for Ingress, Gateway, and any controller that consumes the standard TLS Secret shape.

Auth resolution:

* `kubeconfig_path` omitted: in-cluster ServiceAccount (run rotad as a Pod).
* `kubeconfig_path` set: load the named kubeconfig (run rotad outside the cluster).

Required RBAC on `secrets` in the target namespace: `get`, `create`, `patch`. Server-side apply with FieldManager `"rota"` so concurrent managers (cert-manager, helm, etc.) get clean conflict signaling rather than silent overwrites.

## Alert backends

### Email

`kind: email`. Lettre-backed SMTP. Submission ports (587 STARTTLS, 465 SMTPS) both supported via `tls:`. Auth is username + password from a file the daemon reads at runtime; the password never sits in the parsed config tree.

### Webhook

`kind: webhook`. POSTs a generic JSON envelope to a URL:

```json
{"cert_id": "...", "kind": "renewal_failed", "message": "...", "timestamp": "RFC3339"}
```

Vendor-neutral on the wire. Slack-incoming, Discord, Microsoft Teams, and similar opinionated formats are out of scope: point a small relay (n8n, Pipedream, your own service) at this URL and translate. Keeps rota's wire format flat instead of growing a per-vendor bestiary.

Optional Bearer token auth from a file. Per-request timeout defaults to 10 seconds.

## Roadmap

More CAs: Sectigo direct, GoDaddy. More DNS-01 solvers: Route 53, DigitalOcean, Porkbun. More install targets: a native HTTP-01 listener (instead of webroot), more reload integrations as operators surface needs.

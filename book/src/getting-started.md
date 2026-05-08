# Getting started

This page walks through standing up a single-node rota that renews one cert against Let's Encrypt via DNS-01, with the cert installed to the local filesystem.

## Install

```bash
cargo install rota
```

This builds two binaries: `rotad` (the daemon) and `rota` (the CLI client that talks to the daemon over a UNIX socket).

## Minimal config

Create `/etc/rota/rota.yaml`:

```yaml
daemon:
  database_path: /var/lib/rota/rota.db
  listen_addr: 127.0.0.1:7878
  socket_path: /var/run/rota.sock
  check_interval_seconds: 3600
  renew_threshold_days: 30

acme:
  directory_url: https://acme-v02.api.letsencrypt.org/directory
  contact_email: ops@example.com
  account_credentials_file: /etc/rota/secrets/acme-account.json

cloudflare:
  api_token_file: /etc/rota/secrets/cloudflare.token

certs:
  - id: example-public
    description: example.com marketing site
    domains: [example.com, www.example.com]
    key_path: /var/lib/rota/keys/example.com.key
    ca:
      kind: acme
    dcv:
      kind: cloudflare
    install:
      kind: filesystem
      directory: /etc/ssl/example
```

Three things to provision before starting `rotad`:

1. **Cloudflare API token** at `/etc/rota/secrets/cloudflare.token`. Scope: `Zone.DNS:Edit` on every zone rota will publish DCV records in. rota only supports tokens, not the legacy Global API Key.
2. **ACME account credentials file**. The first run creates this automatically; just make sure the parent directory is writable.
3. **Private key directory** (`/var/lib/rota/keys/`) with `0700` mode. The first run also generates the per-cert key automatically; rota reuses the same key on every renewal so cert-pinning operators don't break.

## First run

```bash
rotad --config /etc/rota/rota.yaml
```

The daemon will:

1. Open the audit DB (SQLite by default).
2. Connect to the configured CAs, registrars / DCV solvers, and install backends.
3. Sweep every cert on the configured `check_interval_seconds`. The first sweep happens after one full interval, not immediately, so the daemon doesn't hammer the CA on startup.
4. Renew any cert whose installed copy is `< renew_threshold_days` from `notAfter`.

## Talking to the daemon

```bash
rota status
```

Prints a one-line summary per cert: id, domains, days until expiry, last renewal status. The same data is on the dashboard at `http://127.0.0.1:7878/`.

```bash
rota renew example-public
```

Force a renewal regardless of expiry. Useful when you've just rotated DNS and want to confirm the pipeline end-to-end.

```bash
rota log example-public
```

Print the most recent renewal's audit trail (CSR generated, CA submitted, DCV published, cert issued, cert installed, DCV removed).

## Where to go next

- [Architecture overview](./architecture.md) — the four trait surfaces and how they compose.
- [Configuration reference](./configuration.md) — every field of `rota.yaml`.
- [Backends](./backends.md) — what ships today and what's coming.
- [Federation runbook](./federation.md) — running multiple `rotad` instances with shared state.

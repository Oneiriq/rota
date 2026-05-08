# Configuration reference

`rota.yaml` is the single source of truth for daemon settings, CAs, DCV solvers, install targets, alerts, and federation. The path defaults to `/etc/rota/rota.yaml`; override with `--config <path>` or the `ROTA_CONFIG` env var.

## Top-level shape

```yaml
daemon: {...}            # daemon-wide settings
audit: {...}             # optional; defaults to SQLite at daemon.database_path
namecheap: {...}         # account-wide, required if any cert names namecheap
cloudflare: {...}        # account-wide, required if any cert names cloudflare
acme: {...}              # account-wide, required if any cert names acme
cluster: {...}           # optional federation block
alerts: [...]            # optional list of notification sinks
certs: [...]             # required list of cert configs
```

## `daemon`

```yaml
daemon:
  database_path: /var/lib/rota/rota.db
  listen_addr: 127.0.0.1:7878
  socket_path: /var/run/rota.sock
  check_interval_seconds: 3600
  renew_threshold_days: 30
```

| Field | Default | Notes |
|---|---|---|
| `database_path` | `/var/lib/rota/rota.db` | SQLite audit DB. Auto-created mode 600. |
| `listen_addr` | `127.0.0.1:7878` | Dashboard HTTP listen. Bind behind a reverse proxy for external access. |
| `socket_path` | `/var/run/rota.sock` | UNIX socket the `rota` CLI talks to. |
| `check_interval_seconds` | `3600` | Scheduler sweep cadence. |
| `renew_threshold_days` | `30` | Renew when the installed cert's notAfter is closer than this. |

## `audit`

Omit for SQLite at `daemon.database_path` (single-node default). For SurrealDB:

```yaml
audit:
  kind: surrealdb
  endpoint: ws://surreal.internal:8000
  namespace: rota
  database: prod
  username: rota
  password_file: /etc/rota/secrets/surreal.password
```

`endpoint` accepts `mem://`, `file://path`, `ws://`, `wss://`, `http://`, `https://`. Embedded engines (`mem://`, `file://`) skip auth; remote engines need `username` + `password_file`.

## CA accounts

### `namecheap`

```yaml
namecheap:
  api_key_file: /etc/rota/secrets/namecheap-api.key
  username: your-namecheap-username
  api_user: optional-sub-account-user   # defaults to username
  client_ip: 192.0.2.1
```

`client_ip` must be on the account's whitelisted IPs in Namecheap, or the API rejects every call. Same credentials authenticate both the CA backend (reissue) and the DCV backend (DNS).

### `cloudflare`

```yaml
cloudflare:
  api_token_file: /etc/rota/secrets/cloudflare.token
```

Token scope: `Zone.DNS:Edit` on every zone rota manages. rota does not support the legacy Global API Key.

### `acme`

```yaml
acme:
  directory_url: https://acme-v02.api.letsencrypt.org/directory
  contact_email: ops@example.com
  account_credentials_file: /etc/rota/secrets/acme-account.json
  external_account_binding:           # optional; ZeroSSL et al.
    kid: <CA-assigned key id>
    hmac_key_file: /etc/rota/secrets/zerossl.hmac
```

Common directory URLs:

- Let's Encrypt prod: `https://acme-v02.api.letsencrypt.org/directory`
- Let's Encrypt staging: `https://acme-staging-v02.api.letsencrypt.org/directory`
- ZeroSSL: `https://acme.zerossl.com/v2/DV90`
- BuyPass: `https://api.buypass.com/acme/directory`

`account_credentials_file` is created on first run; treat like a private key (mode 0o600).

## `cluster`

Omit for single-node. To enable federation:

```yaml
cluster:
  enabled: true
  node_id: host-a       # unique per node
  lease_seconds: 60     # refresh cadence is lease/3 (~20s here)
```

Requires `audit.kind: surrealdb` because the lock + cert blobs live in that database. See the [federation runbook](./federation.md) for end-to-end setup.

## `alerts`

A list. Every event fans out to every entry, so operators can mix sinks:

```yaml
alerts:
  - kind: email
    smtp_host: smtp.example.com
    smtp_port: 587
    tls: starttls            # starttls (587), implicit (465), or none
    username: alerts@example.com
    password_file: /etc/rota/secrets/smtp.password
    from: rota@example.com
    to: [oncall@example.com]
  - kind: webhook
    url: https://hooks.example.com/incoming/abc
    bearer_token_file: /etc/rota/secrets/webhook.token  # optional
    timeout_seconds: 10                                  # optional, default 10
```

## `certs`

Each cert picks one CA, one DCV solver, one install target:

```yaml
certs:
  - id: example-public                # stable; used in logs, CLI, dashboard
    description: example.com marketing site
    domains: [example.com, www.example.com]
    key_path: /var/lib/rota/keys/example.com.key
    ca:
      kind: <namecheap | acme>
    dcv:
      kind: <namecheap | cloudflare | webroot>
    install:
      kind: <dsm | filesystem | nginx | haproxy | k8s_secret>
```

### `ca` variants

```yaml
ca: { kind: namecheap, ssl_id: 12345678 }
ca: { kind: acme }
```

### `dcv` variants

```yaml
dcv: { kind: namecheap }
dcv: { kind: cloudflare }
dcv: { kind: webroot, directory: /var/www/example }
```

### `install` variants

```yaml
install: { kind: dsm, description: My Public Site }
install: { kind: filesystem, directory: /etc/ssl/example }
install:
  kind: nginx
  directory: /etc/nginx/certs/example
  reload_command: [systemctl, reload, nginx]      # optional, default [nginx, -s, reload]
install:
  kind: haproxy
  directory: /etc/haproxy/certs
  socket_path: /run/haproxy/admin.sock
  cert_storage_name: /etc/haproxy/certs/example.pem
install:
  kind: k8s_secret
  namespace: ingress-nginx
  secret_name: example-tls
  kubeconfig_path: /etc/rota/kubeconfig            # optional, omit for in-cluster SA
```

## Migration from earlier versions

### v0.5 → v0.6

- `rota.yaml`: rename `registrar:` → `dcv:` on every cert. The kind values (`namecheap`, `cloudflare`) are unchanged; only the parent field name moves.
- New optional `cluster:` block enables multi-host federation.
- Wire protocol bumped from 1 to 2 (`CertSummary.registrar_backend` → `dcv_backend`). The `rota` CLI must upgrade alongside `rotad`; older clients hit a clean version-mismatch error rather than silent misparse.

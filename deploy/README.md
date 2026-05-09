# Deploying rota

Reference template for standing up a private rota instance from this public repo. The image is generic; your config, credentials, and per-cert private keys live only on your host.

## What's in this directory

* `compose.yml` — operator-private deploy template. Bind-mounts a workdir layout (`rota.yaml`, `secrets/`, `keys/`, `data/`, `run/`) into the container.

The Dockerfile lives at the repo root.

## Public vs private split

Anything in this repo (Dockerfile, compose template, source) is public. Your operator copy of `compose.yml` plus `rota.yaml`, the secrets directory, and the per-cert private keys live ONLY on your deploy host. Never commit them back to this repo.

## Workdir layout

The compose template assumes you run `docker compose up -d` from a workdir that looks like this:

```
/volume1/docker/rota/
├── compose.yml           # copied from deploy/compose.yml
├── rota.yaml             # your real config (mode 600)
├── secrets/              # mode 700
│   └── namecheap-api.key # mode 600
├── keys/                 # mode 700
│   └── example.com.key   # mode 600 (rota auto-generates on first renewal)
├── data/                 # SQLite audit DB; auto-created
└── run/                  # UNIX socket dir; auto-created
```

`/volume1/docker/rota/` is the Synology DSM convention. Adjust as needed for your host.

## Build the image

Build on the same architecture you'll deploy to. Building amd64 images on Apple Silicon via QEMU has been unreliable; build on the deploy host directly when possible.

```bash
# On the deploy host:
git clone https://github.com/Oneiriq/rota /tmp/rota-build
cd /tmp/rota-build
docker build -t ghcr.io/oneiriq/rota:latest .
```

Or build elsewhere and `docker save | ssh host docker load` if your target is resource-constrained.

## Minimal `rota.yaml`

```yaml
daemon:
  database_path: /var/lib/rota/rota.db
  listen_addr: 0.0.0.0:7878
  socket_path: /var/run/rota.sock
  check_interval_seconds: 3600
  renew_threshold_days: 30

namecheap:
  api_key_file: /etc/rota/secrets/namecheap-api.key
  username: your-namecheap-username
  client_ip: 192.0.2.1            # your deploy host's outbound IP

certs:
  - id: example-public
    description: example.com marketing site
    domains: [example.com, www.example.com]
    key_path: /var/lib/rota/keys/example.com.key
    ca:
      kind: namecheap
      ssl_id: 12345678
    dcv:
      kind: namecheap
    install:
      kind: filesystem
      directory: /var/lib/rota/data/installed
```

`rota.example.yaml` at the repo root has the full annotated reference, including ACME, Cloudflare, webroot, nginx, HAProxy, Kubernetes Secret, alerts, and cluster federation.

## Bring it up

```bash
mkdir -p /volume1/docker/rota/{secrets,keys,data,run}
chmod 700 /volume1/docker/rota/secrets /volume1/docker/rota/keys
cp deploy/compose.yml /volume1/docker/rota/
$EDITOR /volume1/docker/rota/rota.yaml         # see template above
$EDITOR /volume1/docker/rota/secrets/namecheap-api.key
chmod 600 /volume1/docker/rota/rota.yaml /volume1/docker/rota/secrets/namecheap-api.key

cd /volume1/docker/rota
docker compose up -d
docker compose logs -f rotad
```

## Use the CLI

The `rota` CLI is bundled in the same image. Talk to the running daemon via `docker exec`:

```bash
docker exec rota /usr/local/bin/rota status
docker exec rota /usr/local/bin/rota renew example-public
docker exec rota /usr/local/bin/rota log example-public
```

If you want host-side CLI access without `docker exec`, the `./run` bind already exposes `/var/run/rota.sock` on the host filesystem. Wire your host's `rota` binary at that socket path.

## Dashboard

The dashboard listens on the port you set in `rota.yaml` (default 7878). The compose template binds to 127.0.0.1 so you can front it with a reverse proxy. For external access put it behind DSM's reverse proxy (or your nginx of choice) with whatever auth you already use.

## Federation

Multi-host federation needs SurrealDB-backed audit and a `cluster:` block. See the [federation runbook](https://oneiriq.github.io/rota/federation.html).

## Upgrades

```bash
cd /volume1/docker/rota
docker compose pull
docker compose up -d
docker image prune -f
```

The audit DB and per-cert private keys persist via the bind mounts; container churn is safe.

## Removing the deployment

```bash
cd /volume1/docker/rota
docker compose down
# data/ and keys/ stay on disk so you can restore later. Delete those
# directories yourself if you really want a clean teardown.
```

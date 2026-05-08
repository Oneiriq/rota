# Federation runbook

Multiple `rotad` instances pointing at the same SurrealDB elect a single leader to run the renewal scheduler. Followers stand by for failover and install cluster-distributed certs locally with operator-pre-provisioned private keys.

## Why this exists

Two operator-side use cases:

1. **High-availability renewer.** A single `rotad` is a single point of failure: if its host goes down within `renew_threshold_days` of a cert's `notAfter`, the cert lapses. A two-node cluster with leader election keeps renewal pulled forward through host failures.
2. **Multi-host install.** A cert that fronts multiple machines (load balancers, service mesh ingress, redundant API servers) needs to land on each host. With federation, one node renews and every node installs locally.

## Architecture

```
                ┌──────────────────────────┐
                │   SurrealDB (operator)   │
                │   namespace: rota        │
                │   database: prod         │
                │                          │
                │   cluster_lock:singleton │
                │   issued_cert:<rows>     │
                │   renewal:<rows>         │
                │   renewal_event:<rows>   │
                └──────────────────────────┘
                       ▲       ▲       ▲
                       │       │       │
              ┌────────┘       │       └────────┐
              │                │                │
        ┌─────┴────┐     ┌─────┴────┐     ┌─────┴────┐
        │ rotad A  │     │ rotad B  │     │ rotad C  │
        │ leader   │     │ follower │     │ follower │
        └──────────┘     └──────────┘     └──────────┘
        ↓ scheduler        ↓ install_sync   ↓ install_sync
        ↓ renewer          ↓ poll           ↓ poll
        ↓ install (local)
```

- All nodes share one SurrealDB (or a SurrealDB cluster — rota doesn't care which).
- One node holds the lock at `cluster_lock:singleton` and runs the renewal scheduler. Others have their schedulers gated on `is_leader()` and skip silently.
- The leader's renewer pipeline persists every successful issuance to the `issued_cert` table.
- Every node (including the leader, but the leader's `install_sync` self-suppresses) runs an `InstallSyncTask` that polls `issued_cert` and runs the local `InstallBackend` when the audit cert is fresher than what's installed locally.

## Trust model

- The audit store carries cert PEM + chain PEM. **Private keys are never written to the audit store.**
- Each cluster member's `key_path` private key is provisioned out-of-band — config-management, secrets manager, manual scp, whatever the operator already uses for sensitive material.
- The shared SurrealDB is in the trust boundary for cert metadata + renewal history but not for key material. If the database is compromised, an attacker can read which certs exist and when they were renewed; they cannot forge requests against the CA or impersonate any host.

## Setup

### 1. Provision SurrealDB

Operators who already run SurrealDB skip ahead. Otherwise the simplest is one `surreal` instance behind a reverse proxy on a stable host:

```bash
surreal start --user root --pass <root-password> file:///var/lib/surrealdb
```

Then create the namespace + database for rota:

```bash
surreal sql --user root --pass <root-password> --ns rota --db prod
> DEFINE NAMESPACE rota;
> DEFINE DATABASE prod;
```

### 2. Provision per-cert private keys on each node

Pick the `key_path` directory each node will use. Mode `0700`. Place the same private key file on every cluster member that participates in installing this cert:

```bash
# On every node:
install -d -m 0700 /var/lib/rota/keys
install -m 0600 example.com.key /var/lib/rota/keys/example.com.key
```

The keys must be byte-identical across nodes; rota uses one key per cert (no per-node keys) so the cert validates against any node's TLS handshake.

### 3. Configure each node

Each `rota.yaml` is the same except for the `cluster.node_id`:

```yaml
daemon:
  database_path: /var/lib/rota/rota.db   # local SQLite for local audit only; the shared audit lives in SurrealDB
  listen_addr: 127.0.0.1:7878
  socket_path: /var/run/rota.sock
  check_interval_seconds: 3600
  renew_threshold_days: 30

audit:
  kind: surrealdb
  endpoint: wss://surreal.internal:8000
  namespace: rota
  database: prod
  username: rota
  password_file: /etc/rota/secrets/surreal.password

cluster:
  enabled: true
  node_id: host-a            # different per node: host-a, host-b, host-c
  lease_seconds: 60

# ... ca / dcv / alerts / certs blocks identical across nodes
```

### 4. Start each node

```bash
# host-a:
rotad --config /etc/rota/rota.yaml &

# host-b:
rotad --config /etc/rota/rota.yaml &

# host-c:
rotad --config /etc/rota/rota.yaml &
```

Whichever node wins the initial lock acquisition becomes leader. The others log `cluster: still follower` and stand by.

## Verifying

### Who's the leader?

```bash
# On every node:
rota status
```

Each node shows the same cert table (it's pulled from the shared audit). `rotad`'s logs differentiate:

```text
INFO cluster: acquired leader lock     ← leader
INFO cluster: still follower           ← followers
```

A direct query against SurrealDB:

```surql
SELECT * FROM cluster_lock:singleton;
```

returns the holder's node_id and lease expiry.

### Did the cert distribute?

After a successful renewal:

```surql
SELECT * FROM issued_cert WHERE cert_id = 'example-public' ORDER BY issued_at DESC LIMIT 1;
```

shows the fresh cert blob. Each follower's `install_sync` task picks it up on its next poll (one `check_interval_seconds`), installs locally, and the `last_renewal_status` on each node's `rota status` output reflects the fresh cert.

## Failover

When the leader dies (host crash, kernel oom, network partition), its lease lapses after `lease_seconds` (default 60s). The next polling follower acquires the lock and becomes the new leader; renewals pick back up automatically. No operator intervention needed.

If a leader recovers from a transient failure and re-acquires the lock, no harm: the `record_issued_cert` writes are append-only, and `latest_issued_cert` is monotonic by `issued_at`.

## Failure modes worth knowing

- **SurrealDB unreachable from the leader.** The lease loop logs lock-check failures and demotes defensively. Followers see no leader; on their next sweep one of them tries to acquire and may succeed (if their network sees SurrealDB) or also fail. Renewals pause until SurrealDB is reachable from at least one node.
- **Private key drift across nodes.** If the per-node `key_path` differs, follower installs will succeed locally but the served cert won't match any other node's chain. Audit this with a cross-node `openssl x509 -in` + `openssl rsa -in` modulus comparison.
- **Cert distribution lag.** Followers poll on `check_interval_seconds`. With the default 1h, a follower can be up to 1h behind the leader's renewal. Tune the interval down if you need tighter sync (the cost is more SurrealDB traffic, but it's a single SELECT per cert per tick).

## Rolling back to single-node

Set `cluster.enabled: false` (or remove the block entirely) on the surviving node and restart it. The leader lock will lapse; no other node tries to acquire. The audit store retains its history; just point the surviving node at SQLite instead of SurrealDB if you want to fully decouple.

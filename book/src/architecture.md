# Architecture overview

rota is one Rust binary running as a daemon, with two thin clients sharing its state.

```
rota CLI ──── socket ────▶ rotad (daemon)
                           scheduler, audit, API
                           HTTP + WS, SQLite or SurrealDB
Dashboard ──── HTTP ─────▶
(htmx + SSR)   WS                │   │   │   │
                          ┌──────┘   │   │   └──────┐
                          ▼          ▼   ▼          ▼
                        CABackend  Dcv Install   Alert
                                   Backend Backend Backend

                        Namecheap  Namecheap  DSM        Email (SMTP)
                        ACME       Cloudflare Filesystem Webhook
                                   Webroot    nginx
                                              HAProxy
                                              Kubernetes
```

Daemon, CLI, and dashboard all build from one Cargo workspace and ship as a single binary. No Node, no Deno, no npm.

## Four trait surfaces

The renewal pipeline composes generically across vendors. Adding support for a new CA, DCV strategy, install target, or alert sink is one trait impl, not a fork of the renewal logic.

### `CABackend`

Issues certificates from a Certificate Authority. Two methods:

* `submit(domains, csr_pem, preferred_kinds)`. Submits a CSR. Returns one or more `DcvChallenge` values the caller must satisfy via the DCV backend. `preferred_kinds` lets the caller hint at DNS-01 vs HTTP-01; CAs that offer a choice walk the list and pick.
* `await_issuance(domains)`. Polls until the cert is signed.

Today: `NamecheapCa` (traditional reissue, DNS-01 only) and `AcmeCa` (RFC 8555: Let's Encrypt, ZeroSSL with EAB, BuyPass, any directory that speaks the spec).

### `DcvBackend`

Solves the CA's domain-control challenge.

* `supported_kinds()`. Which `ChallengeKind`s the backend can satisfy: `Dns01`, `Http01`.
* `supports(challenge)`. Whether this specific challenge is satisfiable. Default impl matches against `supported_kinds()`.
* `publish(challenge)`. Make the response visible to the CA. Idempotent.
* `remove(challenge)`. Clean up after issuance. Idempotent.

`DcvChallenge` is a tagged enum:

* `Dns01 { record_name, record_value, ttl }`. TXT record at `record_name`. Solvers: `NamecheapDcv`, `CloudflareDcv`.
* `Http01 { domain, token, key_authorization }`. `key_authorization` body served at `http://<domain>/.well-known/acme-challenge/<token>`. Solver: `WebrootDcv` (drops the file under a directory served by an existing webserver).

### `InstallBackend`

Places the issued cert and chain where the system serving the domain can read them. Implementations may also trigger a service reload.

* `install(cert, private_key_pem, domains)`. Land the artifacts.
* `current_cert_pem(cert_id)`. Read back the installed leaf cert for the scheduler's days-until-expiry calculation. Default returns `None`; backends opt in.

Today: `DsmInstall` (Synology), `FilesystemInstall` (mode-600 key + mode-644 cert + chain + fullchain), `NginxInstall` (filesystem + reload subprocess), `HaproxyInstall` (filesystem + runtime API hot-swap), `K8sSecretInstall` (server-side-apply a `kubernetes.io/tls` Secret).

### `AlertBackend`

Daemon-wide notification sinks. Every renewal failure fans out to every configured sink.

* `dispatch(event)`. Deliver. Errors are logged but never break the renewal pipeline.

Today: `EmailAlert` (lettre, STARTTLS / implicit TLS / plaintext) and `WebhookAlert` (generic JSON envelope POST).

## Renewer pipeline

For one cert, one renewal:

1. Load (or generate) the persistent private key from `key_path`.
2. Generate a CSR against that key.
3. `ca.submit()` returns DCV challenges.
4. Pre-flight check: `dcv.supports()` for each challenge. Fast-fail if the configured solver can't handle what the CA returned.
5. `dcv.publish()` every challenge.
6. `ca.await_issuance()` waits for the CA to validate and sign.
7. `dcv.remove()` cleans up. Runs unconditionally, even if issuance failed, so a partial run doesn't leave stray records.
8. Persist the issued cert and chain to the audit store (for cluster cert distribution).
9. `install.install()` writes locally.
10. The audit log records every step.

## Scheduler

Ticks every `check_interval_seconds`. For each cert: read the install backend's `current_cert_pem`, parse `notAfter`, compare to `renew_threshold_days`, queue a renewal if due. A per-cert failure cooldown prevents a flaky CA from getting hammered every tick.

In a cluster, the scheduler's sweep is gated on `cluster.is_leader()`. Followers skip silently; the leader keeps doing the work.

## Audit store

Every renewal opens a row, appends step events, and closes with a status. Two backends:

* `SqliteAuditStore` (default). Single-file SQLite, no external service. Good for single-node deployments.
* `SurrealAuditStore`. Connects to an existing SurrealDB. Required for cluster federation: the lock and cert distribution rows live in the same database.

## Cluster

When `cluster.enabled = true` and audit is SurrealDB, the daemon runs a `SurrealClusterCoordinator` that holds a lock at `cluster_lock:singleton` with a TTL refresh. The leader's renewer pipeline writes successful issuances to `issued_cert` rows. An `InstallSyncTask` on every node polls the table and runs the local install backend with the operator-pre-provisioned private key when the audit cert is fresher than what's installed locally. Private keys are never distributed through the audit store.

See the [federation runbook](./federation.md) for the operator-side walkthrough.

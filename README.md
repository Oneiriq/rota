# rota

Cert renewal for self-hosters. One Rust binary, CLI plus dashboard, pluggable CAs, registrars, and install targets.

**Docs:** <https://oneiriq.github.io/rota/>

## Why I'm building this

Public TLS certificate lifetimes are getting shorter on a fixed schedule. CA/Browser Forum [Ballot SC-081][sc-081], adopted in April 2025, drops the maximum validity of publicly trusted certs from 397 days down to 47 days over four years:

| Effective | Max validity |
|---|---|
| 2026-03-15 | 200 days |
| 2027-03-15 | 100 days |
| 2029-03-15 | 47 days |

Apple championed the ballot. Their argument ([Apple Platform Security][apple-pki]) is that shorter validity reduces the damage window when a key gets compromised, encourages more automation, and reduces dependence on revocation infrastructure that has been historically unreliable.

Fair enough as far as it goes. Where it falls down for me:

1. Revocation isn't broken so much as underfunded. OCSP stapling and CRLite are real and deployed.
2. The historic CA failures (DigiNotar, Symantec, TrustCor) weren't validity failures. They were infrastructure compromises and policy failures. Shorter cert lifetimes wouldn't have helped.
3. The cost falls hardest on small operators. Cloud customers absorb 47-day renewal automatically; air-gapped, embedded, IoT, and self-hosted setups pay the entire complexity tax. The rational response from a small operator is to hand DNS to a managed proxy and stop self-hosting. That's a power shift away from individuals running their own infrastructure.

I run my own stuff and I'd like to keep doing that. So I'm writing the tool I'd want.

[sc-081]: https://cabforum.org/2025/04/11/ballot-sc-081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/
[apple-pki]: https://support.apple.com/guide/security/welcome/web

## What it does

- Watches your CA-issued certs and knows when they're close to expiry.
- Generates fresh CSRs against persistent private keys you control.
- Submits reissue or renewal requests to the CA over that CA's API.
- Completes domain-control validation by writing TXT records at your registrar.
- Installs issued certs where they need to land. v0.1 covers Synology DSM and a plain filesystem target. More on the roadmap.
- Logs every step. Surfaces a real-time dashboard. Alerts before failures, not after.

## Architecture

One Rust binary running as a daemon, with two thin clients sharing its state.

```
rota CLI ──── socket ────▶ rotad (daemon)
                           scheduler, audit, API
                           HTTP + WS, SQLite
Dashboard ──── HTTP ─────▶
(htmx + SSR)   WS                │   │   │
                          ┌──────┘   │   └──────┐
                          ▼          ▼          ▼
                        CABackend  DCV       Install
                                   Backend   Backend

                        Namecheap  Namecheap DSM (Synology)
                        ACME       Cloudflare Filesystem
                        (more)     (more)    nginx, HAProxy, K8s
```

Daemon, CLI, and dashboard all build from one Cargo workspace and ship as a single binary. No Node, no Deno, no npm. `cargo install rota` and you have everything.

## Backends

Three trait surfaces decouple the renewal pipeline from any one vendor:

- **`CABackend`**: issues certs. Ships with Namecheap (traditional reissue) and ACME (Let's Encrypt, ZeroSSL with EAB, BuyPass, any RFC 8555 directory). Roadmap: Sectigo direct, GoDaddy.
- **`DcvBackend`**: satisfies the CA's domain-control challenge. DNS-01 solvers ship for Namecheap and Cloudflare. HTTP-01 solver lands in v0.6. Roadmap: Route 53, DigitalOcean, Porkbun.
- **`InstallBackend`**: drops issued cert + chain where the system serving the domain can read them. Ships with DSM (Synology) via `synowebapi`, plain filesystem, nginx reload, HAProxy runtime API hot-swap, and Kubernetes Secret.

Each entry in `rota.yaml` picks one of each, so a mixed fleet runs through the same pipeline. Adding a new vendor is one trait impl, not a fork of the renewal logic.

## Status

v0.3.0. Two new vendor backends. ACME CA so rota can issue against Let's Encrypt, ZeroSSL (with EAB), BuyPass, or any directory that follows RFC 8555. Cloudflare registrar so DNS-01 DCV works against Cloudflare-hosted zones with a scoped API token. Audit, scheduler, CLI, and dashboard from earlier releases are unchanged.

## Roadmap

- v0.4: Email + webhook alerts. Prometheus `/metrics` endpoint.
- v0.5: Kubernetes Secret + nginx reload + HAProxy install backends.
- v0.6: HTTP-01 DCV strategy, multi-host federation.

## A note on logging

rota redacts known auth patterns (`ApiKey=`, `password=`, `Bearer `, etc.) from any error string before it lands in a log line or the audit DB. That said, some Rust HTTP-client crates can emit the full request URL at TRACE level, and Namecheap's API carries auth in the URL query string. Don't enable `RUST_LOG=reqwest=trace` (or any `*=trace` that captures the network layer) on a production rotad instance. The default `info` level is fine.

## License

Apache 2.0. See [LICENSE](./LICENSE).

## Author

Shon Thomas, [Oneiriq](https://oneiriq.com).

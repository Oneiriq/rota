# rota

Cert renewal for self-hosters. Single binary, CLI plus dashboard, works against any CA, any registrar, any install target.

---

## Why this exists

Public TLS certificate lifetimes are shrinking on a fixed schedule. CA/Browser Forum [Ballot SC-081][sc-081] — adopted unanimously in April 2025 — drops the maximum validity of publicly trusted certificates from 397 days down to 47 days over four years:

| Effective | Max validity |
|---|---|
| 2026-03-15 | 200 days |
| 2027-03-15 | 100 days |
| 2029-03-15 | 47 days |

### Apple's stated reasoning

The ballot was authored and championed by Apple. Their public position ([Apple Platform Security][apple-pki]) is that shorter validity:

- Reduces the damage window when a key or domain registration is compromised.
- Encourages broader adoption of automation, which they argue makes the ecosystem more secure overall.
- Reduces dependence on revocation infrastructure (CRL / OCSP), which has been historically unreliable.

That position is defensible. Short-validity ecosystems do reduce some classes of risk, and revocation has, in practice, been hard to make work at scale.

### Where the reasoning frays

Three trade-offs the public framing mostly steps around:

1. **Revocation isn't broken so much as underfunded.** OCSP-stapling and CRLite are both real, both deployed, and both demonstrably reduce reliance on the legacy CRL fetch path. Mozilla and Cloudflare have published the operational playbooks. Shortening validity papers over a fixable problem rather than fixing it.
2. **The historic failures aren't validity failures.** DigiNotar (2011), Symantec's distrust (2017), TrustCor's removal (2022) — none of those would have been mitigated by shorter validity. They were CA infrastructure compromises and policy failures. The largest classes of PKI risk are not in the cert lifetime axis.
3. **The cost is unevenly distributed.** Cloud providers and managed-CA customers absorb 47-day renewal automatically; the contractual surface where automation lives is theirs. Air-gapped, embedded, IoT, and self-hosted deployments — where automation is harder by design or is the operator's responsibility — pay the entire complexity tax. The rational response from a small operator is to hand DNS to a managed proxy and call it a day. Net effect: shifting power away from individuals running their own infrastructure, toward a smaller pool of managed-CA and edge-proxy vendors.

This isn't a screed. The CA/Browser Forum vote was unanimous; technically literate people on the other side of the trade-off think it's the right call. The trade-off is real, though, and self-hosters bear most of the cost.

**rota is the tooling that puts running your own certs back within reach.**

[sc-081]: https://cabforum.org/2025/04/11/ballot-sc-081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/
[apple-pki]: https://support.apple.com/guide/security/welcome/web

---

## What rota does

- Watches your CA-issued certs. Knows when they're close to expiry.
- Generates fresh CSRs against persistent private keys you control.
- Submits reissue / renewal requests to the CA over that CA's preferred API.
- Completes domain-control validation by writing TXT records at your registrar.
- Installs issued certs where they need to land — DSM Synology, plain filesystem, future: Kubernetes Secret, nginx reload, HAProxy.
- Logs every step. Surfaces a real-time dashboard. Alerts before failures, not after them.

---

## Architecture

A single Rust binary running as a daemon, with two thin clients sharing its state.

```
┌──────────────┐        ┌──────────────────────────┐
│  rota CLI    │ ─────▶ │       rotad (daemon)     │
└──────────────┘ socket │  scheduler · audit · API │
                        │  HTTP + WS · SQLite      │
┌──────────────┐  HTTP  │                          │
│  Dashboard   │ ─────▶ │                          │
│ (htmx + SSR) │   WS   └──────────────────────────┘
└──────────────┘                  │   │   │
                          ┌───────┘   │   └────────┐
                          ▼           ▼            ▼
                       CABackend  Registrar   InstallBackend
                                  Backend
                       Namecheap  Namecheap    DSM (Synology)
                       (more →)   (more →)     Filesystem
                                                (more →)
```

The daemon, CLI, and dashboard all build from the same Cargo workspace and ship as one binary. No Node, no Deno, no npm — `cargo install rota` and you have everything.

---

## Backends

Three load-bearing abstractions decouple the renewal pipeline from any one vendor:

- **`CABackend`** — issues certs. v0.1 ships with Namecheap (traditional reissue API). Roadmap: Let's Encrypt via ACME, Sectigo direct, ZeroSSL, GoDaddy.
- **`RegistrarBackend`** — completes DNS-01 DCV by writing TXT records. v0.1 ships with Namecheap. Roadmap: Cloudflare, Route 53, DigitalOcean, Porkbun.
- **`InstallBackend`** — drops issued cert + chain where the system serving the domain can read them. v0.1 ships with DSM (Synology) via `synowebapi` and a plain filesystem target. Roadmap: Kubernetes Secret, nginx reload, HAProxy CLI.

Each entry in `rota.yaml` picks one of each, so a fleet of self-hosted sites across mixed registrars and hosts runs through the same renewal pipeline.

Adding support for a new vendor is one trait impl, not a fork of the renewal logic.

---

## Status

**v0.0.0 — scaffolding.** The trait surface, config schema, and CLI/daemon skeletons are in place. Backends are not yet implemented. See the roadmap below.

---

## Roadmap

- **v0.1** — CLI and daemon end-to-end. Namecheap CA + registrar backends. DSM and filesystem install backends. SQLite audit log. Dashboard cert table + per-cert detail view.
- **v0.2** — ACME backend (Let's Encrypt, ZeroSSL). Cloudflare registrar backend.
- **v0.3** — Email + webhook alerts. Prometheus `/metrics` endpoint.
- **v0.4** — Kubernetes Secret + nginx reload + HAProxy install backends.
- **v0.5** — HTTP-01 DCV strategy, multi-host federation.

---

## License

Apache 2.0. See [LICENSE](./LICENSE).

## Author

Shon Thomas — [Oneiriq](https://oneiriq.com).

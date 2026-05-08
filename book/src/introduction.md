# rota

Cert renewal for self-hosters. One Rust binary, CLI plus dashboard, pluggable CAs, registrars, and install targets.

## Why this exists

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
- Completes domain-control validation by writing TXT records at your registrar (DNS-01) or dropping a token under `.well-known/acme-challenge/` for an existing webserver to serve (HTTP-01).
- Installs issued certs where they need to land. Today: Synology DSM, plain filesystem, nginx reload, HAProxy runtime API hot-swap, Kubernetes Secret.
- Logs every step. Surfaces a real-time dashboard. Alerts before failures, not after.
- Optionally federates across multiple `rotad` instances: one node renews, peers pick up the cert from a shared SurrealDB and install locally.

## Who this is for

Operators who:

- Run their own webservers, mail servers, dashboards, hobby boxes, homelabs.
- Want renewal automation without surrendering DNS or HTTPS termination to a managed proxy.
- Are comfortable with a single Rust binary and a YAML config.
- Don't want a sprawling Python toolchain just to keep certs fresh.

If you're already happy with `certbot`, this isn't a replacement; it's a different tradeoff for the operator who wants pluggable backends and built-in operational surface (audit log, dashboard, alerts, metrics, federation) in one process.

## License

[Apache 2.0](https://github.com/Oneiriq/rota/blob/main/LICENSE).

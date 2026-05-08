//! Config schema for `rota.yaml`.
//!
//! The config is a list of certs. Each cert names a CA backend, a
//! registrar backend, and an install backend by tag, plus their
//! per-instance settings. A daemon-wide section sets scheduling,
//! storage, and listen-address policy.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Top-level config: what `rota.yaml` deserializes into.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotaConfig {
  #[serde(default)]
  pub daemon: DaemonConfig,
  /// Audit log backend selector. Defaults to SQLite at
  /// `daemon.database_path` if omitted.
  #[serde(default)]
  pub audit: Option<AuditSpec>,
  /// Account-wide Namecheap credentials. The CA + registrar backends
  /// share a single API key + username + whitelisted client IP, so
  /// the creds live at the top of the config rather than duplicated
  /// across every cert. Required if any cert names Namecheap as its
  /// CA or registrar.
  #[serde(default)]
  pub namecheap: Option<NamecheapAccount>,
  /// Account-wide Cloudflare credentials. Required if any cert names
  /// Cloudflare as its registrar.
  #[serde(default)]
  pub cloudflare: Option<CloudflareAccount>,
  /// Account-wide ACME directory + account material. Required if any
  /// cert names ACME as its CA.
  #[serde(default)]
  pub acme: Option<AcmeAccount>,
  /// Daemon-wide alert sinks. Every event fans out to every entry,
  /// so operators can mix (e.g.) email + webhook in one config.
  /// Empty or omitted = silent (renewal failures still hit the audit
  /// log).
  #[serde(default)]
  pub alerts: Vec<AlertSpec>,
  pub certs: Vec<CertConfig>,
}

impl RotaConfig {
  /// Load a config file, returning a typed parse error on failure.
  pub fn load(path: &Path) -> Result<Self> {
    if !path.exists() {
      return Err(Error::ConfigNotFound {
        path: path.to_owned(),
      });
    }
    let raw = std::fs::read_to_string(path)?;
    serde_yaml::from_str(&raw).map_err(|err| Error::ConfigParse {
      path: path.to_owned(),
      message: err.to_string(),
    })
  }

  /// Look up a cert by id.
  pub fn cert(&self, id: &str) -> Option<&CertConfig> {
    self.certs.iter().find(|c| c.id == id)
  }
}

/// Daemon-wide settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
  /// Path to the SQLite audit database.
  #[serde(default = "default_db_path")]
  pub database_path: PathBuf,
  /// HTTP listen address for the dashboard.
  #[serde(default = "default_listen_addr")]
  pub listen_addr: String,
  /// UNIX socket the CLI talks to.
  #[serde(default = "default_socket_path")]
  pub socket_path: PathBuf,
  /// How often to sweep for certs nearing expiry.
  #[serde(default = "default_check_interval_seconds")]
  pub check_interval_seconds: u64,
  /// Renew when fewer than this many days remain on the cert.
  #[serde(default = "default_renew_threshold_days")]
  pub renew_threshold_days: u32,
}

impl Default for DaemonConfig {
  fn default() -> Self {
    Self {
      database_path: default_db_path(),
      listen_addr: default_listen_addr(),
      socket_path: default_socket_path(),
      check_interval_seconds: default_check_interval_seconds(),
      renew_threshold_days: default_renew_threshold_days(),
    }
  }
}

/// Per-cert configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertConfig {
  /// Stable identifier for this cert (used in logs, CLI, dashboard).
  pub id: String,
  /// Human-readable description, surfaced in the dashboard.
  #[serde(default)]
  pub description: String,
  /// FQDNs the cert covers. First entry is the CN.
  pub domains: Vec<String>,
  /// Persistent private key path (mode 600 expected). Reused across
  /// every renewal; only the cert rotates.
  pub key_path: PathBuf,
  /// CA that issues this cert.
  pub ca: CaSpec,
  /// DCV strategy that satisfies the CA's challenge. Renamed from
  /// `registrar` in v0.6 because HTTP-01 solvers (webroot, internal
  /// listener) do not involve a registrar.
  pub dcv: DcvSpec,
  /// Where the issued cert + chain land.
  pub install: InstallSpec,
}

/// Account-wide Namecheap credentials. Whitelisted client IP is the
/// daemon's outbound IP. Namecheap rejects API calls from anywhere
/// else.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamecheapAccount {
  /// Path to a file containing the API key. Read at runtime so the
  /// secret never sits in the parsed config tree.
  pub api_key_file: PathBuf,
  /// Namecheap username (account owner).
  pub username: String,
  /// API user. Almost always the same as `username`, but Namecheap
  /// permits split values for sub-accounts.
  #[serde(default)]
  pub api_user: Option<String>,
  /// Outbound IP the daemon presents when calling the API. Must be
  /// listed under the account's "Whitelisted IPs" in Namecheap.
  pub client_ip: String,
}

/// Account-wide Cloudflare credentials. The API token must have the
/// `Zone.DNS:Edit` scope on the zones rota will publish DCV records
/// in. Tokens are preferred over the legacy Global API Key; rota
/// only supports tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflareAccount {
  /// Path to a file containing the API token. Read at runtime so
  /// the secret never sits in the parsed config tree.
  pub api_token_file: PathBuf,
}

/// Account-wide ACME directory + account material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeAccount {
  /// ACME directory URL. Common values:
  /// `https://acme-v02.api.letsencrypt.org/directory` (Let's Encrypt prod),
  /// `https://acme-staging-v02.api.letsencrypt.org/directory` (Let's Encrypt staging),
  /// `https://acme.zerossl.com/v2/DV90` (ZeroSSL),
  /// `https://api.buypass.com/acme/directory` (BuyPass).
  pub directory_url: String,
  /// Email surfaced to the CA on account registration. Optional but
  /// strongly recommended; CAs use it to send revocation and expiry
  /// notices.
  #[serde(default)]
  pub contact_email: Option<String>,
  /// Where the JWS account key + URL are persisted between daemon
  /// restarts. Treat like a private key (mode 0o600). If missing,
  /// rota registers a fresh account on first run and writes the
  /// credentials here.
  pub account_credentials_file: PathBuf,
  /// External Account Binding for CAs that require it (ZeroSSL,
  /// some commercial ACME deployments). Skip for Let's Encrypt and
  /// BuyPass.
  #[serde(default)]
  pub external_account_binding: Option<EabConfig>,
}

/// External Account Binding material. The CA assigns a key id and
/// HMAC key out-of-band; rota uses both to bind a new ACME account
/// to an existing customer record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EabConfig {
  /// Key id the CA gave you.
  pub kid: String,
  /// File containing the base64url-encoded HMAC key.
  pub hmac_key_file: PathBuf,
}

/// Audit log backend selector. SQLite is the default if the
/// top-level `audit:` block is omitted; rota's own daemon owns the
/// SQLite file with no external service to provision. SurrealDB is
/// available for operators who already run a SurrealDB instance and
/// want renewal history queryable alongside the rest of their data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditSpec {
  /// Single-file SQLite at the given path. Defaults to
  /// `daemon.database_path` when this block is omitted.
  Sqlite {
    #[serde(default)]
    path: Option<PathBuf>,
  },
  /// SurrealDB at the given endpoint. Endpoint accepts every form
  /// surql-rs accepts: `mem://` and `memory://` for embedded
  /// in-memory; `file://path` for embedded persistent; `ws://`,
  /// `wss://`, `http://`, `https://` for remote. Auth fields are
  /// optional for embedded engines.
  Surrealdb {
    endpoint: String,
    namespace: String,
    database: String,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password_file: Option<PathBuf>,
  },
}

/// CA-backend selector. Each variant carries the backend-specific
/// settings inline.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CaSpec {
  /// Namecheap traditional reissue API (Sectigo-backed). Account
  /// creds come from the top-level `namecheap` block.
  Namecheap {
    /// Numeric SSL ID from the Namecheap dashboard.
    ssl_id: u64,
  },
  /// ACME (RFC 8555) issuance — Let's Encrypt, ZeroSSL, BuyPass,
  /// any directory that speaks the spec. Account creds come from
  /// the top-level `acme` block.
  Acme,
}

/// DCV-backend selector. Each variant carries the strategy-specific
/// settings inline. Today's variants are all DNS-01 (Namecheap,
/// Cloudflare); HTTP-01 solvers layer on as additional variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DcvSpec {
  /// DNS-01 via Namecheap-managed DNS. Account creds come from the
  /// top-level `namecheap` block.
  Namecheap,
  /// DNS-01 via Cloudflare's v4 API. Account creds come from the
  /// top-level `cloudflare` block.
  Cloudflare,
}

/// Alert-backend selector. Each variant carries the sink-specific
/// settings inline. Account-wide creds are inlined too (rather than
/// referenced from a separate top-level block) because alert sinks
/// are typically used at most once per deployment, so the duplication
/// of a single SMTP host across two `email` entries is rare and not
/// worth a dedicated `smtp:` block.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AlertSpec {
  /// SMTP email. Submission ports (587 STARTTLS, 465 SMTPS) both
  /// supported via the `tls` field. Auth is username + password
  /// stored in a file the daemon reads at runtime.
  Email {
    /// SMTP server hostname.
    smtp_host: String,
    /// SMTP server port. Common values: 587 (STARTTLS), 465 (SMTPS).
    smtp_port: u16,
    /// TLS mode for the SMTP connection.
    #[serde(default)]
    tls: SmtpTls,
    /// SMTP auth username. Many providers use the full `from`
    /// address here.
    username: String,
    /// File holding the SMTP auth password. Read at runtime so the
    /// secret never sits in the parsed config tree.
    password_file: PathBuf,
    /// `From:` header on outbound messages. Must be an address the
    /// SMTP relay is willing to send for.
    from: String,
    /// `To:` recipients. At least one is required; multiple entries
    /// translate to a comma-separated header list.
    to: Vec<String>,
  },
  /// HTTPS webhook. POSTs a generic JSON envelope
  /// (`{cert_id, kind, message, timestamp}`) to the configured URL.
  /// For Slack-incoming or Discord webhook formats, run the events
  /// through a small relay (n8n, Pipedream, your own service); rota
  /// stays vendor-neutral on the wire.
  Webhook {
    /// Full URL to POST to (must include scheme).
    url: String,
    /// Optional file containing a Bearer token. When set, the daemon
    /// adds `Authorization: Bearer <token>` to the request.
    #[serde(default)]
    bearer_token_file: Option<PathBuf>,
    /// Per-request timeout in seconds. Defaults to 10 if omitted; the
    /// scheduler waits synchronously, so a runaway sink would stall
    /// other alerts in the same fan-out.
    #[serde(default)]
    timeout_seconds: Option<u64>,
  },
}

/// TLS mode for SMTP submission.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmtpTls {
  /// STARTTLS upgrade on a plaintext port (port 587 on most relays).
  #[default]
  Starttls,
  /// Implicit TLS (port 465 on most relays).
  Implicit,
  /// No TLS. Only safe on a localhost relay; refuse to authenticate
  /// over unencrypted transit.
  None,
}

/// Install-backend selector.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InstallSpec {
  /// Synology DSM via `synowebapi`. The cert id surfaces in the DSM
  /// Control Panel under the configured description.
  Dsm {
    /// Description shown in DSM's Certificate panel.
    description: String,
  },
  /// Plain filesystem: write `<dir>/<id>.crt`, `<dir>/<id>.chain.crt`,
  /// and a copy of the private key with mode 600.
  Filesystem { directory: PathBuf },
  /// Filesystem write + nginx reload. Files land in `<directory>`
  /// using the same naming convention as `Filesystem`, then the
  /// configured `reload_command` runs to make nginx pick the new
  /// cert up. Default reload is `["nginx", "-s", "reload"]`; override
  /// for systemd (`["systemctl", "reload", "nginx"]`) or sudo wrappers.
  Nginx {
    directory: PathBuf,
    /// Override the reload invocation. Argv-style; empty list falls
    /// back to the default. The daemon does not pass through a shell,
    /// so quoting is unnecessary.
    #[serde(default)]
    reload_command: Option<Vec<String>>,
  },
  /// Filesystem write + HAProxy runtime API hot-swap. Files land in
  /// `<directory>` using the same naming convention as `Filesystem`
  /// (so an operator restart still reads the latest cert from disk),
  /// then the daemon pushes the new cert to HAProxy's admin socket
  /// using the runtime API: `set ssl cert <storage_name>` followed
  /// by `commit ssl cert <storage_name>`. No reload, no dropped
  /// connections. Requires HAProxy 2.x or later with the admin
  /// socket exposed (`stats socket /run/haproxy/admin.sock mode 660
  /// level admin` in the HAProxy config).
  Haproxy {
    /// Directory to land the cert + chain + key bundle in (used
    /// both for operator visibility and to feed `current_cert_pem`
    /// without round-tripping through the runtime API).
    directory: PathBuf,
    /// Path to HAProxy's admin socket. Common defaults:
    /// `/run/haproxy/admin.sock`, `/var/run/haproxy.sock`.
    socket_path: PathBuf,
    /// Storage name HAProxy uses internally for the cert. Matches
    /// the path declared in `bind ... ssl crt <name>` in haproxy.cfg
    /// (or under `crt-list`).
    cert_storage_name: String,
  },
  /// Kubernetes `kubernetes.io/tls` Secret. Server-side applies a
  /// Secret named `secret_name` in `namespace` with `tls.crt`
  /// (cert + chain bundle) and `tls.key` data fields, suitable for
  /// Ingress, Gateway, and any controller that consumes the
  /// standard TLS Secret shape. Auth is in-cluster service account
  /// when `kubeconfig_path` is omitted (the daemon reads
  /// `/var/run/secrets/kubernetes.io/serviceaccount/`), otherwise
  /// it loads the named kubeconfig file. The service account
  /// (or kubeconfig user) needs `get`, `create`, and `patch` on
  /// `secrets` in the target namespace.
  K8sSecret {
    /// Namespace the Secret lives in.
    namespace: String,
    /// Name of the Secret resource. Matches the `secretName` field
    /// on Ingress / Gateway TLS configurations.
    secret_name: String,
    /// Optional kubeconfig file. Omit when running inside a pod
    /// to use the mounted service account credentials.
    #[serde(default)]
    kubeconfig_path: Option<PathBuf>,
  },
}

fn default_db_path() -> PathBuf {
  PathBuf::from("/var/lib/rota/rota.db")
}

fn default_listen_addr() -> String {
  "127.0.0.1:7878".to_owned()
}

fn default_socket_path() -> PathBuf {
  PathBuf::from("/var/run/rota.sock")
}

fn default_check_interval_seconds() -> u64 {
  60 * 60 // 1 hour
}

fn default_renew_threshold_days() -> u32 {
  30
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_example_yaml() {
    let example_path = Path::new(env!("CARGO_MANIFEST_DIR"))
      .parent()
      .unwrap()
      .parent()
      .unwrap()
      .join("rota.example.yaml");
    let cfg = RotaConfig::load(&example_path).expect("rota.example.yaml must parse");
    assert_eq!(cfg.certs.len(), 1);
    let cert = &cfg.certs[0];
    assert_eq!(cert.id, "example-public");
    assert_eq!(cert.domains, vec!["example.com", "www.example.com"]);
    let nc = cfg.namecheap.expect("example uses namecheap");
    assert_eq!(nc.username, "your-namecheap-username");
    assert_eq!(nc.client_ip, "192.0.2.1");
    match cert.ca {
      CaSpec::Namecheap { ssl_id } => assert_eq!(ssl_id, 12345678),
      _ => panic!("expected namecheap ca"),
    }
    assert!(matches!(cert.dcv, DcvSpec::Namecheap));
    match &cert.install {
      InstallSpec::Dsm { description } => assert_eq!(description, "My Public Site"),
      _ => panic!("expected dsm install"),
    }
  }

  #[test]
  fn missing_namecheap_block_still_parses() {
    let yaml = r#"
certs: []
"#;
    let cfg: RotaConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(cfg.namecheap.is_none());
    assert!(cfg.certs.is_empty());
  }

  #[test]
  fn parses_email_alert_spec() {
    let yaml = r#"
alerts:
  - kind: email
    smtp_host: smtp.example.com
    smtp_port: 587
    tls: starttls
    username: alerts@example.com
    password_file: /etc/rota/secrets/smtp.password
    from: rota@example.com
    to:
      - oncall@example.com
      - secondary@example.com
certs: []
"#;
    let cfg: RotaConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(cfg.alerts.len(), 1);
    match &cfg.alerts[0] {
      AlertSpec::Email {
        smtp_host,
        smtp_port,
        tls,
        username,
        password_file,
        from,
        to,
      } => {
        assert_eq!(smtp_host, "smtp.example.com");
        assert_eq!(*smtp_port, 587);
        assert!(matches!(tls, SmtpTls::Starttls));
        assert_eq!(username, "alerts@example.com");
        assert_eq!(
          password_file,
          &PathBuf::from("/etc/rota/secrets/smtp.password")
        );
        assert_eq!(from, "rota@example.com");
        assert_eq!(
          to,
          &vec![
            "oncall@example.com".to_owned(),
            "secondary@example.com".to_owned()
          ]
        );
      }
      _ => panic!("expected email alert"),
    }
  }

  #[test]
  fn parses_webhook_alert_spec() {
    let yaml = r#"
alerts:
  - kind: webhook
    url: https://hooks.example.com/incoming/abc
    bearer_token_file: /etc/rota/secrets/webhook.token
    timeout_seconds: 5
certs: []
"#;
    let cfg: RotaConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(cfg.alerts.len(), 1);
    match &cfg.alerts[0] {
      AlertSpec::Webhook {
        url,
        bearer_token_file,
        timeout_seconds,
      } => {
        assert_eq!(url, "https://hooks.example.com/incoming/abc");
        assert_eq!(
          bearer_token_file.as_ref().unwrap(),
          &PathBuf::from("/etc/rota/secrets/webhook.token")
        );
        assert_eq!(*timeout_seconds, Some(5));
      }
      _ => panic!("expected webhook alert"),
    }
  }

  #[test]
  fn webhook_optional_fields_default() {
    let yaml = r#"
alerts:
  - kind: webhook
    url: https://hooks.example.com/incoming/abc
certs: []
"#;
    let cfg: RotaConfig = serde_yaml::from_str(yaml).unwrap();
    match &cfg.alerts[0] {
      AlertSpec::Webhook {
        bearer_token_file,
        timeout_seconds,
        ..
      } => {
        assert!(bearer_token_file.is_none());
        assert!(timeout_seconds.is_none());
      }
      _ => panic!("expected webhook alert"),
    }
  }

  #[test]
  fn missing_alerts_block_defaults_to_empty() {
    let yaml = r#"
certs: []
"#;
    let cfg: RotaConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(cfg.alerts.is_empty());
  }

  #[test]
  fn smtp_tls_defaults_to_starttls() {
    let yaml = r#"
alerts:
  - kind: email
    smtp_host: smtp.example.com
    smtp_port: 587
    username: u
    password_file: /tmp/pw
    from: a@example.com
    to: [b@example.com]
certs: []
"#;
    let cfg: RotaConfig = serde_yaml::from_str(yaml).unwrap();
    let AlertSpec::Email { tls, .. } = &cfg.alerts[0] else {
      panic!("expected email alert");
    };
    assert!(matches!(tls, SmtpTls::Starttls));
  }

  #[test]
  fn parses_filesystem_install_variant() {
    let yaml = r#"
namecheap:
  api_key_file: /tmp/k
  username: u
  client_ip: 1.2.3.4
certs:
  - id: example-fs
    domains: [example.org]
    key_path: /tmp/example.key
    ca: { kind: namecheap, ssl_id: 1 }
    dcv: { kind: namecheap }
    install:
      kind: filesystem
      directory: /etc/ssl/example
"#;
    let cfg: RotaConfig = serde_yaml::from_str(yaml).unwrap();
    let cert = &cfg.certs[0];
    match &cert.install {
      InstallSpec::Filesystem { directory } => {
        assert_eq!(directory, &PathBuf::from("/etc/ssl/example"));
      }
      _ => panic!("expected filesystem install"),
    }
  }

  #[test]
  fn parses_nginx_install_variant_with_reload_override() {
    let yaml = r#"
namecheap:
  api_key_file: /tmp/k
  username: u
  client_ip: 1.2.3.4
certs:
  - id: example-nginx
    domains: [example.org]
    key_path: /tmp/example.key
    ca: { kind: namecheap, ssl_id: 1 }
    dcv: { kind: namecheap }
    install:
      kind: nginx
      directory: /etc/nginx/certs/example
      reload_command: ["systemctl", "reload", "nginx"]
"#;
    let cfg: RotaConfig = serde_yaml::from_str(yaml).unwrap();
    match &cfg.certs[0].install {
      InstallSpec::Nginx {
        directory,
        reload_command,
      } => {
        assert_eq!(directory, &PathBuf::from("/etc/nginx/certs/example"));
        assert_eq!(
          reload_command.as_ref().unwrap(),
          &vec![
            "systemctl".to_owned(),
            "reload".to_owned(),
            "nginx".to_owned(),
          ]
        );
      }
      _ => panic!("expected nginx install"),
    }
  }

  #[test]
  fn parses_haproxy_install_variant() {
    let yaml = r#"
namecheap:
  api_key_file: /tmp/k
  username: u
  client_ip: 1.2.3.4
certs:
  - id: example-haproxy
    domains: [example.org]
    key_path: /tmp/example.key
    ca: { kind: namecheap, ssl_id: 1 }
    dcv: { kind: namecheap }
    install:
      kind: haproxy
      directory: /etc/haproxy/certs
      socket_path: /run/haproxy/admin.sock
      cert_storage_name: /etc/haproxy/certs/example.pem
"#;
    let cfg: RotaConfig = serde_yaml::from_str(yaml).unwrap();
    match &cfg.certs[0].install {
      InstallSpec::Haproxy {
        directory,
        socket_path,
        cert_storage_name,
      } => {
        assert_eq!(directory, &PathBuf::from("/etc/haproxy/certs"));
        assert_eq!(socket_path, &PathBuf::from("/run/haproxy/admin.sock"));
        assert_eq!(cert_storage_name, "/etc/haproxy/certs/example.pem");
      }
      _ => panic!("expected haproxy install"),
    }
  }

  #[test]
  fn parses_k8s_secret_install_variant_with_kubeconfig() {
    let yaml = r#"
namecheap:
  api_key_file: /tmp/k
  username: u
  client_ip: 1.2.3.4
certs:
  - id: example-k8s
    domains: [example.org]
    key_path: /tmp/example.key
    ca: { kind: namecheap, ssl_id: 1 }
    dcv: { kind: namecheap }
    install:
      kind: k8s_secret
      namespace: ingress-nginx
      secret_name: example-tls
      kubeconfig_path: /etc/rota/kubeconfig
"#;
    let cfg: RotaConfig = serde_yaml::from_str(yaml).unwrap();
    match &cfg.certs[0].install {
      InstallSpec::K8sSecret {
        namespace,
        secret_name,
        kubeconfig_path,
      } => {
        assert_eq!(namespace, "ingress-nginx");
        assert_eq!(secret_name, "example-tls");
        assert_eq!(
          kubeconfig_path.as_ref().unwrap(),
          &PathBuf::from("/etc/rota/kubeconfig")
        );
      }
      _ => panic!("expected k8s_secret install"),
    }
  }

  #[test]
  fn k8s_secret_kubeconfig_path_is_optional() {
    let yaml = r#"
namecheap:
  api_key_file: /tmp/k
  username: u
  client_ip: 1.2.3.4
certs:
  - id: example-k8s-incluster
    domains: [example.org]
    key_path: /tmp/example.key
    ca: { kind: namecheap, ssl_id: 1 }
    dcv: { kind: namecheap }
    install:
      kind: k8s_secret
      namespace: default
      secret_name: example-tls
"#;
    let cfg: RotaConfig = serde_yaml::from_str(yaml).unwrap();
    match &cfg.certs[0].install {
      InstallSpec::K8sSecret {
        kubeconfig_path, ..
      } => {
        assert!(
          kubeconfig_path.is_none(),
          "in-cluster mode = kubeconfig_path: None"
        );
      }
      _ => panic!("expected k8s_secret install"),
    }
  }

  #[test]
  fn nginx_reload_command_is_optional() {
    let yaml = r#"
namecheap:
  api_key_file: /tmp/k
  username: u
  client_ip: 1.2.3.4
certs:
  - id: example-nginx-default
    domains: [example.org]
    key_path: /tmp/example.key
    ca: { kind: namecheap, ssl_id: 1 }
    dcv: { kind: namecheap }
    install:
      kind: nginx
      directory: /etc/nginx/certs/example
"#;
    let cfg: RotaConfig = serde_yaml::from_str(yaml).unwrap();
    match &cfg.certs[0].install {
      InstallSpec::Nginx { reload_command, .. } => {
        assert!(reload_command.is_none());
      }
      _ => panic!("expected nginx install"),
    }
  }
}

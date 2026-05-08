//! Prometheus metrics for the daemon.
//!
//! All metrics are process-local: counters and gauges live in a
//! private `Registry` and are scraped via the `/metrics` route on
//! the dashboard's axum server. There is no push gateway and no
//! external aggregator. A daemon restart resets every counter to
//! zero, which matches Prometheus's standard expectation for
//! ephemeral targets (the operator's `rate()` queries handle
//! restarts automatically).
//!
//! Metric inventory:
//!
//! - `rota_renewal_attempts_total{cert, outcome}` (counter): one tick
//!   per `attempt_renewal` call. `outcome` is `success` or `failure`.
//! - `rota_certs_days_until_expiry{cert}` (gauge): days until the
//!   currently-installed cert's `notAfter`. Negative if expired.
//!   Updated each scheduler sweep for every cert with a parseable
//!   installed PEM. Certs without a readable cert (never installed,
//!   bad install backend) leave their gauge at the previous sample
//!   or absent.
//! - `rota_alert_dispatch_total{backend, outcome}` (counter): one
//!   tick per alert backend dispatch. `outcome` is `success` or
//!   `failure`.

use std::sync::LazyLock;

use prometheus::{Encoder, GaugeVec, IntCounterVec, Opts, Registry, TextEncoder};

pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);

static RENEWAL_ATTEMPTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
  let v = IntCounterVec::new(
    Opts::new(
      "rota_renewal_attempts_total",
      "Total renewal attempts since daemon start, by cert and outcome.",
    ),
    &["cert", "outcome"],
  )
  .expect("renewal_attempts metric construction");
  REGISTRY
    .register(Box::new(v.clone()))
    .expect("register renewal_attempts");
  v
});

static DAYS_UNTIL_EXPIRY: LazyLock<GaugeVec> = LazyLock::new(|| {
  let v = GaugeVec::new(
    Opts::new(
      "rota_certs_days_until_expiry",
      "Days until the currently-installed cert's notAfter (negative if expired).",
    ),
    &["cert"],
  )
  .expect("days_until_expiry metric construction");
  REGISTRY
    .register(Box::new(v.clone()))
    .expect("register days_until_expiry");
  v
});

static ALERT_DISPATCH: LazyLock<IntCounterVec> = LazyLock::new(|| {
  let v = IntCounterVec::new(
    Opts::new(
      "rota_alert_dispatch_total",
      "Total alert sink dispatches since daemon start, by backend and outcome.",
    ),
    &["backend", "outcome"],
  )
  .expect("alert_dispatch metric construction");
  REGISTRY
    .register(Box::new(v.clone()))
    .expect("register alert_dispatch");
  v
});

/// Outcome label for renewal + alert counters. Kept as `&'static str`
/// constants so call sites cannot typo a label that would split a
/// counter across two timeseries.
pub const OUTCOME_SUCCESS: &str = "success";
pub const OUTCOME_FAILURE: &str = "failure";

pub fn record_renewal_attempt(cert_id: &str, outcome: &str) {
  RENEWAL_ATTEMPTS
    .with_label_values(&[cert_id, outcome])
    .inc();
}

pub fn set_days_until_expiry(cert_id: &str, days: f64) {
  DAYS_UNTIL_EXPIRY.with_label_values(&[cert_id]).set(days);
}

pub fn record_alert_dispatch(backend_name: &str, outcome: &str) {
  ALERT_DISPATCH
    .with_label_values(&[backend_name, outcome])
    .inc();
}

/// Render every registered metric as a Prometheus text-format body.
/// Caller is responsible for setting the response Content-Type.
pub fn gather_text() -> String {
  let metric_families = REGISTRY.gather();
  let mut buf = Vec::with_capacity(1024);
  TextEncoder::new()
    .encode(&metric_families, &mut buf)
    .expect("text-encoding prometheus metrics never fails");
  String::from_utf8(buf).expect("prometheus text encoder emits valid utf-8")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn gather_text_returns_registered_metric_names() {
    // Touch each metric so it's registered (LazyLock is per-process,
    // so other tests may already have done this; either way the
    // .inc() / .set() initialises the vec).
    record_renewal_attempt("metrics-test-a", OUTCOME_SUCCESS);
    record_renewal_attempt("metrics-test-a", OUTCOME_FAILURE);
    set_days_until_expiry("metrics-test-a", 42.0);
    record_alert_dispatch("metrics-test-sink", OUTCOME_SUCCESS);

    let text = gather_text();
    assert!(text.contains("rota_renewal_attempts_total"));
    assert!(text.contains("rota_certs_days_until_expiry"));
    assert!(text.contains("rota_alert_dispatch_total"));
    assert!(text.contains(r#"cert="metrics-test-a""#));
    assert!(text.contains(r#"outcome="success""#));
    assert!(text.contains(r#"outcome="failure""#));
    assert!(text.contains(r#"backend="metrics-test-sink""#));
  }

  #[test]
  fn renewal_attempt_counter_increments() {
    let cert = "metrics-test-counter";
    record_renewal_attempt(cert, OUTCOME_SUCCESS);
    let before = RENEWAL_ATTEMPTS
      .with_label_values(&[cert, OUTCOME_SUCCESS])
      .get();
    record_renewal_attempt(cert, OUTCOME_SUCCESS);
    record_renewal_attempt(cert, OUTCOME_SUCCESS);
    let after = RENEWAL_ATTEMPTS
      .with_label_values(&[cert, OUTCOME_SUCCESS])
      .get();
    assert_eq!(after - before, 2);
  }

  #[test]
  fn days_until_expiry_gauge_overwrites() {
    let cert = "metrics-test-gauge";
    set_days_until_expiry(cert, 10.0);
    set_days_until_expiry(cert, -3.5);
    assert_eq!(
      DAYS_UNTIL_EXPIRY.with_label_values(&[cert]).get(),
      -3.5,
      "gauge must reflect the latest set value"
    );
  }
}

//! Single-node "always leader" coordinator.
//!
//! Used when the operator omits the cluster config block. The
//! daemon runs as the only instance, so leadership is trivially
//! true and there is no lock to refresh.

use async_trait::async_trait;
use rota_core::cluster::ClusterCoordinator;
use rota_core::Result;

#[derive(Debug, Clone)]
pub struct NoOpCoordinator {
  node_id: String,
}

impl NoOpCoordinator {
  pub fn new(node_id: String) -> Self {
    Self { node_id }
  }
}

#[async_trait]
impl ClusterCoordinator for NoOpCoordinator {
  fn name(&self) -> &str {
    "no-op"
  }

  fn node_id(&self) -> &str {
    &self.node_id
  }

  fn is_leader(&self) -> bool {
    // Single-node mode: always leader.
    true
  }

  async fn run(&self) -> Result<()> {
    // Park forever. The runtime keeps the task alive so the
    // supervisor sees a stable spawn slot, even though we have
    // nothing to do.
    std::future::pending::<()>().await;
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn always_leader() {
    let coordinator = NoOpCoordinator::new("test-node".to_owned());
    assert!(coordinator.is_leader());
    assert_eq!(coordinator.node_id(), "test-node");
    assert_eq!(coordinator.name(), "no-op");
  }
}

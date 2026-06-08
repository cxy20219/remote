use anyhow::Context;
use clap::Parser;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;
use tunnel_rs_common::CryptoManager;

use tunnel_rs_agent::{agent::Agent, config::Config, identity::AgentIdentity, logger};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    logger::init();

    let cfg = Config::parse();
    let identity_dir = cfg.identity_dir();
    info!(
        server = %cfg.server,
        identity_dir = ?identity_dir,
        "tunnel-rs-agent starting"
    );

    let identity = AgentIdentity::load_or_create(&identity_dir, &cfg.server)
        .await
        .with_context(|| format!("loading identity in {}", identity_dir.display()))?;

    let identity = Arc::new(Mutex::new(identity));
    let crypto_mgr = Arc::new(CryptoManager::new());

    let agent = Agent::new(cfg, identity, identity_dir, crypto_mgr);
    agent.run().await;
    Ok(())
}

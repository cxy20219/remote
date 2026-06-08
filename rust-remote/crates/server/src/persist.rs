//! In-memory state store with optional JSON persistence.
//!
//! Phase 2 kept the state purely in RAM. Phase 4 wires up the durable
//! backend, mirroring Go's `internal/server/persist.go`:
//!
//! * Edits go through `RwLock`-guarded mutators and set the dirty flag.
//! * A background task flushes to disk every 3 s when dirty.
//! * Writes go to `<path>.tmp` first, then `rename` for atomic replacement.
//! * Files are created with `0600` perms; the parent dir with `0700`.
//! * On first start the server generates an ed25519 keypair and a random
//!   admin password; the plain password is returned exactly once so the
//!   bootstrap log can surface it to the operator.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Mutex, RwLock};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::state::{DeviceState, DeviceStatus, ServerSettings};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerState {
    #[serde(default)]
    pub server_sign_privkey: String,
    #[serde(default)]
    pub server_sign_pubkey: String,
    #[serde(default)]
    pub admin_password_hash: String,
    /// Plain password — only populated on first boot, then cleared after
    /// the bootstrap log surfaces it. Never written to disk after that.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub admin_password: String,
    #[serde(default)]
    pub settings: ServerSettings,
    #[serde(default)]
    pub devices: Vec<DeviceState>,
}

#[derive(Default)]
struct Inner {
    devices: HashMap<String, DeviceState>,
    settings: ServerSettings,
    // Plain password kept in memory until cleared; never serialized after init.
    admin_password: String,
    admin_password_hash: String,
    server_sign_privkey: String,
    server_sign_pubkey: String,
}

pub struct StateStore {
    inner: Arc<RwLock<Inner>>,
    path: Option<PathBuf>,
    dirty: Mutex<bool>,
}

impl StateStore {
    pub fn new_in_memory() -> Self {
        Self::new_in_memory_handle()
    }

    /// Cheap, no-file alias used by callers that need an `Arc<StateStore>`
    /// purely to satisfy a type signature (e.g. `TunnelManager` placeholder
    /// before `bind_state` injects the real store).
    pub fn new_in_memory_handle() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner::default())),
            path: None,
            dirty: Mutex::new(false),
        }
    }

    /// Load from `path`, or initialise a fresh state file there.
    ///
    /// **Failure modes** (and what they degrade to):
    ///
    /// | condition                              | result                                  |
    /// |----------------------------------------|-----------------------------------------|
    /// | file missing                           | generate + write fresh state, full RW   |
    /// | file present, valid JSON               | load as-is, full RW                     |
    /// | file present, **invalid JSON**         | log a loud warning, fall back to an      |
    /// |                                        | in-memory state with `path = None` —     |
    /// |                                        | no flushes will be attempted, so the     |
    /// |                                        | broken file is left untouched for the   |
    /// |                                        | operator to inspect / repair.            |
    /// | IO error (permissions, disk gone, …)   | propagates so the operator sees it; the |
    /// |                                        | server fails to start.                    |
    pub async fn load_or_init(path: PathBuf) -> std::io::Result<Self> {
        let state_result: std::result::Result<ServerState, ()> =
            match tokio::fs::read(&path).await {
                Ok(bytes) => match serde_json::from_slice::<ServerState>(&bytes) {
                    Ok(s) => Ok(s),
                    Err(e) => {
                        // Don't kill the server on a corrupt state file —
                        // degrade to in-memory so the operator can still
                        // log in, look around, and (hopefully) fix the
                        // file. The on-disk file is left untouched.
                        tracing::error!(
                            path = %path.display(),
                            error = %e,
                            "========================================"
                        );
                        tracing::error!(
                            "state file is corrupt; falling back to in-memory mode"
                        );
                        tracing::error!(
                            "fix or remove the file, then restart the server"
                        );
                        tracing::error!("========================================");
                        Err(())
                    }
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    let s = generate_initial_state();
                    write_state(&path, &s).await?;
                    Ok(s)
                }
                Err(e) => return Err(e),
            };

        let mut state = match state_result {
            Ok(s) => s,
            Err(()) => {
                // Parse failure → degrade to in-memory. Return a fresh
                // store with `path = None` so `flush_if_dirty` is a
                // no-op. The corrupt file is left on disk for the
                // operator to inspect.
                return Ok(Self::new_in_memory_handle());
            }
        };

        if state.settings.port_range_start == 0 {
            state.settings.port_range_start = 10000;
        }
        if state.settings.port_range_end == 0 {
            state.settings.port_range_end = 20000;
        }

        let inner = Inner {
            devices: state.devices.into_iter().map(|d| (d.id.clone(), d)).collect(),
            settings: state.settings,
            admin_password: state.admin_password.clone(),
            admin_password_hash: state.admin_password_hash.clone(),
            server_sign_privkey: state.server_sign_privkey.clone(),
            server_sign_pubkey: state.server_sign_pubkey.clone(),
        };
        if !state.admin_password.is_empty() {
            tracing::info!("========================================");
            tracing::info!("Generated admin credentials");
            tracing::info!("Admin password: {}", state.admin_password);
            tracing::info!("========================================");
        }
        let store = Self {
            inner: Arc::new(RwLock::new(inner)),
            path: Some(path),
            dirty: Mutex::new(false),
        };
        // After logging, clear the in-memory plain password so it doesn't
        // linger.
        store.inner.write().admin_password.clear();
        Ok(store)
    }

    /// `true` when the store has no on-disk backing (e.g. `load_or_init`
    /// fell back to in-memory mode because the existing file was
    /// corrupt, or the caller used `new_in_memory_handle`). All mutator
    /// paths still update in-memory state; only persistence is skipped.
    /// The background sync loop in `main.rs` checks this and skips
    /// `start_sync_loop_with_handle` when read-only.
    pub fn is_read_only(&self) -> bool {
        self.path.is_none()
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Start the background flush task. Returns the JoinHandle — keep it
    /// around so the caller can `abort()` it on graceful shutdown and
    /// ensure a final `flush_if_dirty` runs to completion via [`Self::stop`].
    pub fn start_sync_loop_with_handle(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let store = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(3));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                store.flush_if_dirty().await;
            }
        })
    }

    /// Force a final flush to disk. Call this during graceful shutdown
    /// *before* aborting the sync loop JoinHandle.
    pub async fn stop(&self) {
        self.flush_if_dirty().await;
    }

    async fn flush_if_dirty(&self) {
        let was_dirty = {
            let mut g = self.dirty.lock();
            if *g {
                *g = false;
                true
            } else {
                false
            }
        };
        if !was_dirty {
            return;
        }
        if let Some(path) = &self.path {
            let snapshot = {
                let g = self.inner.read();
                ServerState {
                    server_sign_privkey: g.server_sign_privkey.clone(),
                    server_sign_pubkey: g.server_sign_pubkey.clone(),
                    admin_password_hash: g.admin_password_hash.clone(),
                    admin_password: String::new(),
                    settings: g.settings.clone(),
                    devices: g.devices.values().cloned().collect(),
                }
            };
            if let Err(e) = write_state(path, &snapshot).await {
                tracing::error!(error = %e, "failed to flush state to disk");
                // Restore dirty flag so we retry on the next tick.
                *self.dirty.lock() = true;
            }
        }
    }

    fn mark_dirty(&self) {
        *self.dirty.lock() = true;
    }

    // ---------- server keys / admin credentials ----------

    pub fn server_sign_privkey_hex(&self) -> String {
        self.inner.read().server_sign_privkey.clone()
    }

    pub fn server_sign_pubkey_hex(&self) -> String {
        self.inner.read().server_sign_pubkey.clone()
    }

    pub fn verify_admin_password(&self, password: &str) -> bool {
        // bcrypt is in scope via the bcrypt crate; we keep verification here
        // as a callback to avoid leaking the hashing into every call site.
        if self.inner.read().admin_password_hash.is_empty() {
            return false;
        }
        crate::admin_auth::verify_password(&self.inner.read().admin_password_hash, password)
            .unwrap_or(false)
    }

    /// Test-only: directly set the admin password hash. Skips the bcrypt
    /// step. Use to seed deterministic credentials for integration tests.
    pub fn set_admin_hash_for_test(&self, hashed: impl Into<String>) {
        let mut g = self.inner.write();
        g.admin_password_hash = hashed.into();
        g.admin_password.clear();
        // Persist so reload on a fresh process still works.
        drop(g);
        self.mark_dirty();
    }

    // ---------- settings ----------

    pub fn get_settings(&self) -> ServerSettings {
        self.inner.read().settings.clone()
    }

    pub fn update_settings<F>(&self, f: F)
    where
        F: FnOnce(&mut ServerSettings),
    {
        let mut g = self.inner.write();
        f(&mut g.settings);
        drop(g);
        self.mark_dirty();
    }

    // ---------- devices ----------

    pub fn list_devices(&self) -> Vec<DeviceState> {
        self.inner.read().devices.values().cloned().collect()
    }

    pub fn list_devices_by_status(&self, status: DeviceStatus) -> Vec<DeviceState> {
        self.inner
            .read()
            .devices
            .values()
            .filter(|d| d.status == status)
            .cloned()
            .collect()
    }

    pub fn get_device(&self, id: &str) -> Option<DeviceState> {
        self.inner.read().devices.get(id).cloned()
    }

    pub fn find_device_by_sign_pubkey(&self, pubkey: &str) -> Option<DeviceState> {
        self.inner
            .read()
            .devices
            .values()
            .find(|d| d.device_sign_pubkey == pubkey && d.status == DeviceStatus::Pending)
            .cloned()
    }

    pub fn insert_device(&self, device: DeviceState) {
        self.inner
            .write()
            .devices
            .insert(device.id.clone(), device);
        self.mark_dirty();
    }

    pub fn update_device<F>(&self, id: &str, f: F) -> bool
    where
        F: FnOnce(&mut DeviceState),
    {
        let mut g = self.inner.write();
        if let Some(d) = g.devices.get_mut(id) {
            f(d);
            drop(g);
            self.mark_dirty();
            true
        } else {
            false
        }
    }

    pub fn remove_device(&self, id: &str) -> bool {
        let removed = self.inner.write().devices.remove(id).is_some();
        if removed {
            self.mark_dirty();
        }
        removed
    }
}

// ---------- helpers ----------

fn generate_initial_state() -> ServerState {
    use tunnel_rs_common::{generate_sign_keypair, generate_enc_key};

    let (vk, sk) = generate_sign_keypair();
    let password = random_password();
    let hash = crate::admin_auth::hash_password(&password).unwrap_or_default();
    let _ = generate_enc_key; // keep the import in scope
    ServerState {
        server_sign_privkey: hex::encode(sk.to_bytes()),
        server_sign_pubkey: hex::encode(vk.to_bytes()),
        admin_password: password,
        admin_password_hash: hash,
        ..Default::default()
    }
}

fn random_password() -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    // Pull each character directly from the OS CSPRNG. This avoids the
    // shared state of `thread_rng` (the 0.8 implementation is already a
    // CSPRNG, but using `OsRng` keeps the call site unambiguous and
    // matches the project's other key/secret generation paths).
    (0..12)
        .map(|_| CHARS[OsRng.gen_range(0..CHARS.len())] as char)
        .collect()
}

async fn write_state(path: &Path, state: &ServerState) -> std::io::Result<()> {
    let data = serde_json::to_vec_pretty(state)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = tokio::fs::metadata(parent).await {
                let mut perm = meta.permissions();
                perm.set_mode(0o700);
                let _ = tokio::fs::set_permissions(parent, perm.clone()).await;
            }
        }
    }
    let tmp = path.with_extension("json.tmp");
    tokio::fs::write(&tmp, &data).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = tokio::fs::metadata(&tmp).await?.permissions();
        perm.set_mode(0o600);
        tokio::fs::set_permissions(&tmp, perm.clone()).await?;
    }
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tempfile::TempDir;

    fn sample(id: &str) -> DeviceState {
        DeviceState {
            id: id.to_string(),
            name: id.to_string(),
            device_sign_pubkey: format!("pub-{id}"),
            device_dh_pubkey: String::new(),
            hostname: "h".into(),
            os: "linux".into(),
            status: DeviceStatus::Pending,
            enc_key: String::new(),
            enc_enabled: false,
            ip_whitelist: vec![],
            first_seen: Utc::now(),
            approved_at: None,
        }
    }

    #[tokio::test]
    async fn init_creates_state_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("server-state.json");
        let store = StateStore::load_or_init(path.clone()).await.unwrap();
        assert!(path.exists());
        // After init, empty password is rejected (real password was generated
        // and printed to the log).
        assert!(!store.verify_admin_password(""));
    }

    #[tokio::test]
    async fn round_trip_persists() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("server-state.json");
        let store = StateStore::load_or_init(path.clone()).await.unwrap();
        store.insert_device(sample("c1"));
        store.update_settings(|s| s.port_range_start = 5000);
        // Force a flush
        store.stop().await;
        // Reload
        let store2 = StateStore::load_or_init(path).await.unwrap();
        assert_eq!(store2.get_device("c1").unwrap().id, "c1");
        assert_eq!(store2.get_settings().port_range_start, 5000);
    }

    #[tokio::test]
    async fn dirty_loop_flushes() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("server-state.json");
        let store = Arc::new(StateStore::load_or_init(path.clone()).await.unwrap());
        let _h = store.start_sync_loop_with_handle();
        store.insert_device(sample("c1"));
        // Wait for at least one tick.
        tokio::time::sleep(Duration::from_millis(3_500)).await;
        let raw = tokio::fs::read(&path).await.unwrap();
        let parsed: ServerState = serde_json::from_slice(&raw).unwrap();
        assert!(parsed.devices.iter().any(|d| d.id == "c1"));
    }

    /// A corrupt state file must not bring the server down: load_or_init
    /// falls back to an in-memory store, the on-disk file is left
    /// untouched, and subsequent mutations only affect memory.
    #[tokio::test]
    async fn corrupt_state_falls_back_to_read_only() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("server-state.json");
        // Pre-write garbage that is not valid JSON.
        tokio::fs::write(&path, b"{ not valid json :::")
            .await
            .unwrap();

        let store = StateStore::load_or_init(path.clone()).await.unwrap();
        assert!(
            store.is_read_only(),
            "corrupt-file load must produce a read-only store"
        );

        // Mutators still work in memory.
        store.insert_device(sample("c1"));
        store.update_settings(|s| s.port_range_start = 12345);
        assert_eq!(store.get_device("c1").unwrap().id, "c1");
        assert_eq!(store.get_settings().port_range_start, 12345);

        // The on-disk file is *not* clobbered by a stop() flush.
        store.stop().await;
        let raw = tokio::fs::read(&path).await.unwrap();
        assert_eq!(
            raw, b"{ not valid json :::",
            "corrupt file must be left untouched for the operator"
        );
    }

    /// A non-existent state file must still produce a read-write store
    /// (so a fresh start works) — only the corrupt-file path is the
    /// read-only one.
    #[tokio::test]
    async fn missing_state_file_is_read_write() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("server-state.json");
        // No file present at all.
        let store = StateStore::load_or_init(path.clone()).await.unwrap();
        assert!(
            !store.is_read_only(),
            "fresh init must be read-write, not read-only"
        );
        // A file was created.
        assert!(path.exists());
    }
}

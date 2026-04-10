// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! A dual-write [`KVStore`]/[`KVStoreSync`] that wraps both a [`VssStore`] and a [`SqliteStore`],
//! writing to both on every write and reading from local with VSS fallback.
//!
//! This ensures that channel state is always persisted locally even when the VSS server is
//! unreachable, preventing data loss during VSS outages.
//!
//! ## Design
//!
//! **Reads always go to local.** Local SQLite is the source of truth. VSS is only consulted
//! for reads during a restore-from-seed, detected automatically when the local store is empty
//! at construction time. Once local has data, VSS is never read — preventing stale VSS data
//! from causing channel state mismatches and force closes.
//!
//! **Writes go to local first, then VSS (best-effort).** If the VSS write fails the data is
//! still safe in local. The next write will try VSS again.
//!
//! **Background bulk sync.** On construction, a background thread is spawned that reads every
//! key from local SQLite and writes each one to VSS. This catches up any data that was written
//! while VSS was down. The sync runs independently with its own 60-second timeout and does not
//! block node startup.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use lightning::io;
use lightning::util::persist::{KVStore, KVStoreSync};
// Note: we use eprintln! instead of the `log` crate because the DualStore is constructed
// before the LDK Node Logger is available, and the `log` facade may not be initialized.
// eprintln! reliably reaches the device console on both iOS and Android.

use crate::io::sqlite_store::SqliteStore;
use crate::io::vss_store::VssStore;

/// Timeout for the background bulk sync operation.
const BULK_SYNC_TIMEOUT: Duration = Duration::from_secs(60);

/// A [`KVStore`]/[`KVStoreSync`] implementation that writes to both a [`VssStore`] and a local
/// [`SqliteStore`].
///
/// ## Read strategy
/// - **Normal mode** (local has data): read from local [`SqliteStore`] only. Never consults VSS.
/// - **Restore mode** (local was empty at construction): read from local first, fall back to
///   [`VssStore`] on `NotFound`, and copy VSS data to local for future reads.
///
/// ## Write strategy
/// 1. Write to local [`SqliteStore`] first (fast, reliable, must succeed)
/// 2. Write to [`VssStore`] (may fail/timeout — non-fatal, logged)
///
/// ## Remove strategy
/// 1. Remove from both stores; local must succeed, VSS is best-effort
///
/// ## List strategy
/// - **Normal mode**: list from local only.
/// - **Restore mode**: list from local first; if empty, fall back to VSS.
///
/// ## Background bulk sync
/// On construction, spawns a background thread that syncs all local keys to VSS with a
/// 60-second timeout. Does not block node startup.
///
/// **Restore mode** is auto-detected: if the local store is empty at construction time,
/// restore mode is enabled and reads will fall back to VSS. Otherwise, reads are local-only.
pub struct DualStore {
	vss: Arc<VssStore>,
	local: Arc<SqliteStore>,
	/// When true, reads fall back to VSS on local `NotFound`. Auto-detected at construction:
	/// `true` if local was empty (restore-from-seed), `false` otherwise.
	restore_mode: bool,
}

impl DualStore {
	/// Creates a new [`DualStore`] wrapping the given [`VssStore`] and [`SqliteStore`].
	///
	/// Spawns a background thread to bulk-sync all local keys to VSS. This catches up any
	/// data written while VSS was previously unreachable. The sync does not block construction.
	pub fn new(vss: VssStore, local: SqliteStore) -> Self {
		let vss = Arc::new(vss);
		let local = Arc::new(local);

		// Auto-detect restore mode: if local is empty, this is a restore-from-seed
		// and we should fall back to VSS for reads. Otherwise, local is the sole
		// source of truth for reads — never consult VSS (which may have stale data).
		let restore_mode = match local.list_all_keys() {
			Ok(keys) => {
				if keys.is_empty() {
					eprintln!("DualStore: Local store is empty — entering restore mode (will read from VSS)");
					true
				} else {
					eprintln!("DualStore: Local store has {} keys — normal mode (local-only reads)", keys.len());
					false
				}
			},
			Err(e) => {
				eprintln!("DualStore: Failed to check local store — assuming normal mode: {}", e);
				false
			},
		};

		// Spawn background bulk sync (local → VSS)
		let vss_bg = Arc::clone(&vss);
		let local_bg = Arc::clone(&local);
		std::thread::Builder::new()
			.name("dual-store-bulk-sync".to_string())
			.spawn(move || {
				bulk_sync_to_vss(&local_bg, &vss_bg);
			})
			.expect("Failed to spawn bulk sync thread");

		Self { vss, local, restore_mode }
	}
}

/// Bulk-sync all local keys to VSS with a timeout. Runs on a background thread.
fn bulk_sync_to_vss(local: &SqliteStore, vss: &VssStore) {
	let start = std::time::Instant::now();
	eprintln!("DualStore: Background bulk sync to VSS started");

	let entries = match local.list_all_keys() {
		Ok(entries) => entries,
		Err(e) => {
			eprintln!("DualStore: Bulk sync failed — could not list local keys: {}", e);
			return;
		},
	};

	let total = entries.len();
	let mut synced = 0usize;
	let mut failed = 0usize;
	let mut timed_out = false;

	for (primary_ns, secondary_ns, key) in &entries {
		// Check timeout
		if start.elapsed() >= BULK_SYNC_TIMEOUT {
			eprintln!(
				"DualStore: Bulk sync timed out after {}s — {}/{} keys synced, stopping",
				BULK_SYNC_TIMEOUT.as_secs(),
				synced,
				total
			);
			timed_out = true;
			break;
		}

		let data = match KVStoreSync::read(local, primary_ns, secondary_ns, key) {
			Ok(data) => data,
			Err(e) => {
				eprintln!(
					"DualStore: Bulk sync — failed to read local key {}/{}/{}: {}",
					primary_ns, secondary_ns, key, e
				);
				failed += 1;
				continue;
			},
		};

		match KVStoreSync::write(vss, primary_ns, secondary_ns, key, data) {
			Ok(()) => {
				synced += 1;
			},
			Err(e) => {
				eprintln!(
					"DualStore: Bulk sync — failed to write to VSS {}/{}/{}: {}",
					primary_ns, secondary_ns, key, e
				);
				failed += 1;
			},
		}
	}

	let elapsed = start.elapsed();
	if timed_out {
		eprintln!(
			"DualStore: Background bulk sync incomplete — {}/{} synced, {} failed in {:.1}s (timeout)",
			synced, total, failed, elapsed.as_secs_f64()
		);
	} else if failed > 0 {
		eprintln!(
			"DualStore: Background bulk sync finished with errors — {}/{} synced, {} failed in {:.1}s",
			synced, total, failed, elapsed.as_secs_f64()
		);
	} else {
		eprintln!(
			"DualStore: Background bulk sync complete — {}/{} keys synced to VSS in {:.1}s",
			synced, total, elapsed.as_secs_f64()
		);
	}
}

impl KVStoreSync for DualStore {
	fn read(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> io::Result<Vec<u8>> {
		// Always read from local first — it has the latest data since writes go there first.
		match KVStoreSync::read(self.local.as_ref(), primary_namespace, secondary_namespace, key) {
			Ok(data) => Ok(data),
			Err(local_err) if local_err.kind() == io::ErrorKind::NotFound => {
				if !self.restore_mode {
					// Normal mode: local is the sole source of truth. Never fall back to
					// VSS, which may have stale data that could cause channel state
					// mismatches and force closes.
					return Err(local_err);
				}

				// Restore mode: local is empty, try VSS (restore-from-seed on new device).
				match KVStoreSync::read(
					self.vss.as_ref(),
					primary_namespace,
					secondary_namespace,
					key,
				) {
					Ok(data) => {
						// Populate local for future reads.
						if let Err(e) = KVStoreSync::write(
							self.local.as_ref(),
							primary_namespace,
							secondary_namespace,
							key,
							data.clone(),
						) {
							eprintln!(
								"DualStore: Failed to populate local from VSS for {}/{}/{}: {}",
								primary_namespace, secondary_namespace, key, e
							);
						}
						Ok(data)
					},
					Err(_) => {
						// Neither store has it — return the original NotFound.
						Err(local_err)
					},
				}
			},
			Err(local_err) => Err(local_err),
		}
	}

	fn write(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>,
	) -> io::Result<()> {
		// Write to local first (must succeed)
		KVStoreSync::write(
			self.local.as_ref(),
			primary_namespace,
			secondary_namespace,
			key,
			buf.clone(),
		)?;

		// Write to VSS in background (fire-and-forget).
		// VssStore retries for up to 180s — we must not block the caller.
		let vss = Arc::clone(&self.vss);
		let pns = primary_namespace.to_string();
		let sns = secondary_namespace.to_string();
		let k = key.to_string();
		std::thread::Builder::new()
			.name("dual-store-vss-write".to_string())
			.spawn(move || {
				if let Err(e) = KVStoreSync::write(vss.as_ref(), &pns, &sns, &k, buf) {
					eprintln!(
						"DualStore: VSS write failed for {}/{}/{} (local succeeded): {}",
						pns, sns, k, e
					);
				}
			})
			.ok();

		Ok(())
	}

	fn remove(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, lazy: bool,
	) -> io::Result<()> {
		// Local removal must succeed
		KVStoreSync::remove(
			self.local.as_ref(),
			primary_namespace,
			secondary_namespace,
			key,
			lazy,
		)?;

		// VSS removal in background (fire-and-forget)
		let vss = Arc::clone(&self.vss);
		let pns = primary_namespace.to_string();
		let sns = secondary_namespace.to_string();
		let k = key.to_string();
		std::thread::Builder::new()
			.name("dual-store-vss-remove".to_string())
			.spawn(move || {
				if let Err(e) = KVStoreSync::remove(vss.as_ref(), &pns, &sns, &k, lazy) {
					eprintln!(
						"DualStore: VSS remove failed for {}/{}/{} (local succeeded): {}",
						pns, sns, k, e
					);
				}
			})
			.ok();

		Ok(())
	}

	fn list(
		&self, primary_namespace: &str, secondary_namespace: &str,
	) -> io::Result<Vec<String>> {
		let local_keys =
			KVStoreSync::list(self.local.as_ref(), primary_namespace, secondary_namespace)?;

		if !local_keys.is_empty() || !self.restore_mode {
			// Normal mode: always return local results (even if empty).
			// Restore mode with local results: return them.
			return Ok(local_keys);
		}

		// Restore mode and local is empty — try VSS.
		match KVStoreSync::list(self.vss.as_ref(), primary_namespace, secondary_namespace) {
			Ok(vss_keys) => Ok(vss_keys),
			Err(e) => {
				eprintln!(
					"DualStore: VSS list failed for {}/{}: {}",
					primary_namespace, secondary_namespace, e
				);
				Ok(local_keys)
			},
		}
	}
}

impl KVStore for DualStore {
	fn read(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> impl Future<Output = Result<Vec<u8>, io::Error>> + 'static + Send {
		let result = KVStoreSync::read(self, primary_namespace, secondary_namespace, key);
		async move { result }
	}

	fn write(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>,
	) -> impl Future<Output = Result<(), io::Error>> + 'static + Send {
		let result = KVStoreSync::write(self, primary_namespace, secondary_namespace, key, buf);
		async move { result }
	}

	fn remove(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, lazy: bool,
	) -> impl Future<Output = Result<(), io::Error>> + 'static + Send {
		let result = KVStoreSync::remove(self, primary_namespace, secondary_namespace, key, lazy);
		async move { result }
	}

	fn list(
		&self, primary_namespace: &str, secondary_namespace: &str,
	) -> impl Future<Output = Result<Vec<String>, io::Error>> + 'static + Send {
		let result = KVStoreSync::list(self, primary_namespace, secondary_namespace);
		async move { result }
	}
}

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
//! from causing channel state mismatches and force closes. During a restore, VSS errors other
//! than `NotFound` are propagated (failing the build) rather than masked: treating an
//! unreachable VSS as an empty one would silently produce a fresh node with no channels.
//!
//! **Writes go to local first, then VSS (best-effort, in order).** Local must succeed; the
//! key is then marked dirty, and one background worker uploads dirty keys, reading the
//! CURRENT local value at upload time. So a key's newest value always wins, superseded writes
//! are never sent, and nothing older can land after something newer (ZeusLN/ldk-node#10: one
//! thread per write let an older blob win). Failed keys stay dirty and are retried with
//! backoff.
//!
//! **Monitors before the manager.** VSS must never hold a manager newer than a monitor it
//! treats as persisted: LDK refuses to load that (`DecodeError::DangerousValue`), so a restore
//! from it fails. The worker reads the manager BEFORE taking its batch of dirty keys, uploads
//! the monitor keys (full monitors, `MonitorUpdatingPersister` updates, archived monitors),
//! then removes keys deleted locally, and uploads that manager last, only if every monitor key
//! in the batch went through. A monitor update LDK treats as complete was marked dirty inside
//! `write`, before it returned, so it is in the batch or already on VSS. Monitor-key removes
//! wait for the batch's monitor writes, so an update key is only deleted once the full
//! monitor that supersedes it is on VSS. The worker clears the manager's dirty mark before reading
//! it, so a manager write that lands after the read marks it again and goes out next round.
//!
//! **Push safety gate.** All pushes to VSS (per-key writes, removes, and the bulk sync) are
//! gated on a per-session safety check: if the local store has no channel monitors (active or
//! archived) while VSS holds at least one, the local state is presumed to be a fresh node
//! built over an existing backup, and every VSS write is disabled for the session to avoid
//! overwriting the only copy of the real channel state. See `vss_push_verdict`.
//!
//! **Background bulk sync.** On construction (except in restore mode), every local key is
//! marked dirty and the same worker uploads them. This catches up anything written while VSS
//! was down, follows the same ordering, and cannot race a live write. It does not block node
//! startup. Dropping the store waits up to `FLUSH_ON_DROP` for the worker to finish.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use lightning::io;
use lightning::util::persist::{
	KVStore, KVStoreSync, ARCHIVED_CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
	ARCHIVED_CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE, CHANNEL_MANAGER_PERSISTENCE_KEY,
	CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE, CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
	CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE, CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
	CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE,
};
// Note: we use eprintln! instead of the `log` crate because the DualStore is constructed
// before the LDK Node Logger is available, and the `log` facade may not be initialized.
// eprintln! reliably reaches the device console on both iOS and Android.

use crate::io::sqlite_store::SqliteStore;
use crate::io::vss_store::VssStore;

/// How long dropping the store waits for the worker to upload its remaining dirty keys.
const FLUSH_ON_DROP: Duration = Duration::from_secs(5);

/// Backoff between upload rounds while VSS keeps failing.
const RETRY_BACKOFF_MIN: Duration = Duration::from_secs(1);
const RETRY_BACKOFF_MAX: Duration = Duration::from_secs(60);

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
/// 2. Mark the key dirty; the VSS worker uploads it in order (see module docs)
///
/// ## Remove strategy
/// 1. Remove from local (must succeed), then mark the key dirty; the worker removes it from VSS
///
/// ## List strategy
/// - **Normal mode**: list from local only.
/// - **Restore mode**: list from local first; if empty, fall back to VSS.
///
/// ## Background bulk sync
/// On construction (except in restore mode), marks every local key dirty for the VSS worker,
/// subject to the push safety gate. Does not block node startup.
///
/// **Restore mode** is auto-detected: if the local store is empty at construction time,
/// restore mode is enabled and reads will fall back to VSS. Otherwise, reads are local-only.
pub struct DualStore {
	vss: Arc<VssStore>,
	local: Arc<SqliteStore>,
	/// When true, reads fall back to VSS on local `NotFound`. Auto-detected at construction:
	/// `true` if local was empty (restore-from-seed), `false` otherwise.
	restore_mode: bool,
	/// Dirty keys for the VSS worker thread. The worker also holds the push safety gate: the
	/// lazily-determined verdict on whether pushing local state to VSS is safe (`None` means
	/// undetermined, e.g. VSS unreachable during the check; keys stay dirty and the check is
	/// retried). See `vss_push_verdict`.
	mirror: Arc<MirrorQueue>,
}

impl DualStore {
	/// Creates a new [`DualStore`] wrapping the given [`VssStore`] and [`SqliteStore`].
	///
	/// Spawns the VSS worker thread. Unless restore mode is detected (local store empty —
	/// nothing to catch up), every local key starts dirty, so the worker uploads them subject
	/// to the push safety check (`vss_push_verdict`). This catches up any data written while
	/// VSS was previously unreachable. The sync does not block construction.
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
					eprintln!(
						"DualStore: Local store has {} keys — normal mode (local-only reads)",
						keys.len()
					);
					false
				}
			},
			Err(e) => {
				eprintln!("DualStore: Failed to check local store — assuming normal mode: {}", e);
				false
			},
		};

		// A legitimate restore (local empty at construction) pre-arms the gate open:
		// everything in local derives from VSS reads or live node operation, so pushing
		// it back cannot destroy anything.
		let push_gate = Arc::new(Mutex::new(if restore_mode { Some(true) } else { None }));

		let initial: HashSet<Key> = if restore_mode {
			// Nothing to catch up — local started empty this session.
			eprintln!("DualStore: Restore mode — skipping background bulk sync");
			HashSet::new()
		} else {
			match local.list_all_keys() {
				Ok(entries) => entries.into_iter().collect(),
				Err(e) => {
					eprintln!("DualStore: Bulk sync skipped — could not list local keys: {}", e);
					HashSet::new()
				},
			}
		};
		let mirror = Arc::new(MirrorQueue::new(initial));
		spawn_mirror_worker(Arc::clone(&local), Arc::clone(&vss), push_gate, Arc::clone(&mirror));

		Self { vss, local, restore_mode, mirror }
	}
}

/// Outcome of the push safety check. See `vss_push_verdict`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PushVerdict {
	/// Pushing local data to VSS is safe.
	Allowed,
	/// Safety could not be determined (a store could not be listed). The current push is
	/// skipped (local data is safe; a later bulk sync catches VSS up) and the check runs
	/// again on the next push attempt.
	Undetermined,
	/// The poison signature was detected — all VSS pushes are disabled for this session.
	Disabled,
}

/// Determines whether pushing local data to VSS is safe.
///
/// Poison signature: local has no channel monitors (active or archived) while VSS has at
/// least one. That state means VSS knows about channels this device does not — it can only
/// arise when a fresh node was built locally over an existing backup (e.g. a restore that
/// fell back to an empty local store). Pushing local keys would overwrite the only copy of
/// the real channel state, so all VSS writes are disabled for the session.
///
/// The verdict is cached once determined ([`PushVerdict::Undetermined`] is never cached).
/// The check runs while holding the gate mutex, single-flighting it: a burst of first
/// pushes queues on the lock instead of fanning out into parallel VSS list calls, and
/// once one thread determines the verdict the rest read it from the cache.
///
/// ## Limitations
///
/// - The check is defeated once a poisoned local store gains a channel monitor of its own
///   (e.g. the user opens a new channel from the fresh node in a later session): the local
///   listing is then non-empty and pushes resume, overwriting the backed-up manager. Closing
///   that hole would require content-level reconciliation; the gate protects the common case
///   of a poisoned device with no new channel activity.
/// - While pushes are disabled, the session runs with no VSS backup at all — including for
///   any new channels opened during it. The logged recovery instruction (restore from seed
///   into a new wallet) is the intended path; a wallet should not be operated long-term in
///   this state.
fn vss_push_verdict<L: KVStoreSync, R: KVStoreSync>(
	gate: &Mutex<Option<bool>>, local: &L, vss: &R,
) -> PushVerdict {
	// A panicked holder can't invalidate a plain Option cache — recover the guard rather
	// than wedging every future push on a poisoned mutex.
	let mut verdict_slot = gate.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
	if let Some(allowed) = *verdict_slot {
		return if allowed { PushVerdict::Allowed } else { PushVerdict::Disabled };
	}

	let monitors = KVStoreSync::list(
		local,
		CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
		CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
	);
	let archived = KVStoreSync::list(
		local,
		ARCHIVED_CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
		ARCHIVED_CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
	);
	let local_has_monitor_history = match (monitors, archived) {
		(Ok(monitors), Ok(archived)) => !monitors.is_empty() || !archived.is_empty(),
		_ => {
			eprintln!("DualStore: Could not list local monitors to verify push safety");
			return PushVerdict::Undetermined;
		},
	};

	if local_has_monitor_history {
		// This device has (or had) channels of its own — normal operation.
		*verdict_slot = Some(true);
		return PushVerdict::Allowed;
	}

	// Local has no monitor history. Only safe to push if VSS has none either.
	match KVStoreSync::list(
		vss,
		CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE,
		CHANNEL_MONITOR_PERSISTENCE_SECONDARY_NAMESPACE,
	) {
		Ok(vss_monitors) => {
			if vss_monitors.is_empty() {
				*verdict_slot = Some(true);
				PushVerdict::Allowed
			} else {
				eprintln!(
					"DualStore: CRITICAL — VSS holds {} channel monitor(s) but the local store has none. \
					 Local state looks like a fresh node built over an existing backup; disabling all VSS \
					 writes this session to avoid overwriting the backup. Recover by restoring from seed \
					 into a new wallet.",
					vss_monitors.len()
				);
				*verdict_slot = Some(false);
				PushVerdict::Disabled
			}
		},
		Err(e) => {
			eprintln!("DualStore: Could not list VSS monitors to verify push safety: {}", e);
			PushVerdict::Undetermined
		},
	}
}

/// `(primary_namespace, secondary_namespace, key)`.
type Key = (String, String, String);

fn key_of(primary_namespace: &str, secondary_namespace: &str, key: &str) -> Key {
	(primary_namespace.to_string(), secondary_namespace.to_string(), key.to_string())
}

fn manager_key() -> Key {
	key_of(
		CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
		CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
		CHANNEL_MANAGER_PERSISTENCE_KEY,
	)
}

/// Keys whose VSS copy a restore needs consistent with the manager: full monitors, the
/// `MonitorUpdatingPersister` update keys, and archived monitors.
fn is_monitor_family(key: &Key) -> bool {
	key.0 == CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE
		|| key.0 == CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE
		|| key.0 == ARCHIVED_CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE
}

/// Dirty keys waiting for VSS, plus worker bookkeeping.
struct MirrorQueue {
	state: Mutex<QueueState>,
	/// Signalled on new dirty keys, on shutdown, and when the worker finishes a round or exits.
	wake: Condvar,
	/// Test hook, run once on the worker right after it reads the manager snapshot.
	#[cfg(test)]
	after_manager_read: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

struct QueueState {
	dirty: HashSet<Key>,
	/// Set by `Drop`: upload what is dirty, then exit.
	shutdown: bool,
	exited: bool,
	/// Startup-sync progress, logged once, the first time no dirty keys are left.
	startup_total: usize,
	startup_started: Instant,
	startup_logged: bool,
}

impl MirrorQueue {
	fn new(initial: HashSet<Key>) -> Self {
		Self {
			state: Mutex::new(QueueState {
				startup_total: initial.len(),
				startup_logged: initial.is_empty(),
				dirty: initial,
				shutdown: false,
				exited: false,
				startup_started: Instant::now(),
			}),
			wake: Condvar::new(),
			#[cfg(test)]
			after_manager_read: Mutex::new(None),
		}
	}

	fn mark_dirty(&self, key: Key) {
		let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
		state.dirty.insert(key);
		self.wake.notify_all();
	}

	/// Ask the worker to finish its dirty keys and wait for it, at most `timeout`.
	fn shutdown_and_wait(&self, timeout: Duration) {
		let deadline = Instant::now() + timeout;
		let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
		state.shutdown = true;
		self.wake.notify_all();
		while !state.exited {
			let now = Instant::now();
			if now >= deadline {
				eprintln!(
					"DualStore: {} key(s) not yet on VSS at shutdown; \
					 the next startup sync uploads them",
					state.dirty.len()
				);
				return;
			}
			state =
				self.wake.wait_timeout(state, deadline - now).unwrap_or_else(|p| p.into_inner()).0;
		}
	}
}

/// Start the VSS worker thread for `queue`.
fn spawn_mirror_worker<L, R>(
	local: Arc<L>, vss: Arc<R>, gate: Arc<Mutex<Option<bool>>>, queue: Arc<MirrorQueue>,
) where
	L: KVStoreSync + Send + Sync + 'static,
	R: KVStoreSync + Send + Sync + 'static,
{
	let queue_bg = Arc::clone(&queue);
	let spawned = std::thread::Builder::new()
		.name("dual-store-vss-mirror".to_string())
		.spawn(move || run_mirror_worker(local.as_ref(), vss.as_ref(), &gate, &queue_bg));
	if let Err(e) = spawned {
		eprintln!(
			"DualStore: Failed to spawn the VSS worker, VSS backup is off this session: {}",
			e
		);
		let mut state = queue.state.lock().unwrap_or_else(|p| p.into_inner());
		state.exited = true;
	}
}

/// What happened to one key in an upload round.
enum Outcome {
	Done,
	Failed,
	/// Gone locally; to be removed from VSS after the round's writes.
	Removed,
}

fn upload_key<L: KVStoreSync, R: KVStoreSync>(local: &L, vss: &R, key: &Key) -> Outcome {
	let (pns, sns, k) = key;
	match KVStoreSync::read(local, pns, sns, k) {
		Ok(buf) => match KVStoreSync::write(vss, pns, sns, k, buf) {
			Ok(()) => Outcome::Done,
			Err(e) => {
				eprintln!(
					"DualStore: VSS write failed for {}/{}/{} (local succeeded): {}",
					pns, sns, k, e
				);
				Outcome::Failed
			},
		},
		Err(e) if e.kind() == io::ErrorKind::NotFound => Outcome::Removed,
		Err(e) => {
			eprintln!("DualStore: Failed to read local {}/{}/{} for VSS: {}", pns, sns, k, e);
			Outcome::Failed
		},
	}
}

fn remove_key<R: KVStoreSync>(vss: &R, key: &Key) -> bool {
	let (pns, sns, k) = key;
	match KVStoreSync::remove(vss, pns, sns, k, false) {
		Ok(()) => true,
		Err(e) => {
			eprintln!(
				"DualStore: VSS remove failed for {}/{}/{} (local succeeded): {}",
				pns, sns, k, e
			);
			false
		},
	}
}

/// Upload rounds until shutdown. See the module docs for the ordering rules.
fn run_mirror_worker<L: KVStoreSync, R: KVStoreSync>(
	local: &L, vss: &R, gate: &Mutex<Option<bool>>, queue: &MirrorQueue,
) {
	let manager = manager_key();
	let mut backoff = Duration::ZERO;

	loop {
		// Wait for work. If the manager is dirty, consume its mark now, before reading it: a
		// write that lands after this point marks it again and is uploaded next round instead
		// of being swallowed by the older snapshot.
		let manager_dirty = {
			let mut state = queue.state.lock().unwrap_or_else(|p| p.into_inner());
			while state.dirty.is_empty() && !state.shutdown {
				state = queue.wake.wait(state).unwrap_or_else(|p| p.into_inner());
			}
			if state.dirty.is_empty() {
				state.exited = true;
				queue.wake.notify_all();
				return;
			}
			state.dirty.remove(&manager)
		};

		let mut failed: Vec<Key> = Vec::new();
		let verdict = vss_push_verdict(gate, local, vss);
		match verdict {
			PushVerdict::Allowed => {
				// Read the manager BEFORE taking the batch, so every monitor key it treats
				// as persisted is already dirty or on VSS.
				let manager_snapshot = if manager_dirty {
					Some(KVStoreSync::read(local, &manager.0, &manager.1, &manager.2))
				} else {
					None
				};
				#[cfg(test)]
				if manager_snapshot.is_some() {
					if let Some(hook) = queue.after_manager_read.lock().unwrap().take() {
						hook();
					}
				}

				let mut batch: Vec<Key> = {
					let mut state = queue.state.lock().unwrap_or_else(|p| p.into_inner());
					let mut taken = std::mem::take(&mut state.dirty);
					if taken.remove(&manager) {
						// Written after the snapshot read: upload it next round.
						state.dirty.insert(manager.clone());
					}
					taken.into_iter().collect()
				};
				// Monitor keys first; the order of the rest does not matter.
				batch.sort_by_key(|k| (!is_monitor_family(k), k.clone()));

				let mut removals: Vec<Key> = Vec::new();
				for key in batch {
					match upload_key(local, vss, &key) {
						Outcome::Done => {},
						Outcome::Failed => failed.push(key),
						Outcome::Removed => removals.push(key),
					}
				}

				// Removes go after the writes: a monitor update key is only deleted once the
				// full monitor that supersedes it is on VSS. If a monitor write failed, hold
				// the monitor removes back with it.
				let monitor_write_failed = failed.iter().any(is_monitor_family);
				for key in removals {
					if (monitor_write_failed && is_monitor_family(&key)) || !remove_key(vss, &key) {
						failed.push(key);
					}
				}

				if let Some(snapshot) = manager_snapshot {
					if failed.iter().any(is_monitor_family) {
						// Never put a manager on VSS ahead of its monitors.
						eprintln!(
							"DualStore: Holding back the manager upload until the failed \
							 monitor uploads succeed"
						);
						failed.push(manager.clone());
					} else {
						let (pns, sns, k) = &manager;
						let ok = match snapshot {
							Ok(buf) => match KVStoreSync::write(vss, pns, sns, k, buf) {
								Ok(()) => true,
								Err(e) => {
									eprintln!(
										"DualStore: VSS write failed for the manager \
										 (local succeeded): {}",
										e
									);
									false
								},
							},
							Err(e) if e.kind() == io::ErrorKind::NotFound => {
								remove_key(vss, &manager)
							},
							Err(e) => {
								eprintln!(
									"DualStore: Failed to read the local manager for VSS: {}",
									e
								);
								false
							},
						};
						if !ok {
							failed.push(manager.clone());
						}
					}
				}
			},
			PushVerdict::Undetermined => {
				eprintln!("DualStore: VSS uploads waiting — push safety not yet determined");
				if manager_dirty {
					failed.push(manager.clone());
				}
			},
			PushVerdict::Disabled => {
				// The CRITICAL line logged at verdict time explains why. Drop the keys:
				// nothing may be pushed this session.
				let mut state = queue.state.lock().unwrap_or_else(|p| p.into_inner());
				state.dirty.clear();
				state.startup_logged = true;
			},
		}

		let retry = !failed.is_empty() || verdict == PushVerdict::Undetermined;
		let shutting_down = {
			let mut state = queue.state.lock().unwrap_or_else(|p| p.into_inner());
			state.dirty.extend(failed);
			if state.dirty.is_empty() && !state.startup_logged {
				state.startup_logged = true;
				eprintln!(
					"DualStore: Background bulk sync complete — {}/{} keys synced to VSS \
					 in {:.1}s",
					state.startup_total,
					state.startup_total,
					state.startup_started.elapsed().as_secs_f64()
				);
			}
			if retry && state.shutdown {
				eprintln!(
					"DualStore: Stopping the VSS worker with {} key(s) not on VSS; \
					 the next startup sync uploads them",
					state.dirty.len()
				);
				state.exited = true;
				queue.wake.notify_all();
				return;
			}
			queue.wake.notify_all();
			state.shutdown
		};

		backoff = if retry {
			(backoff * 2).clamp(RETRY_BACKOFF_MIN, RETRY_BACKOFF_MAX)
		} else {
			Duration::ZERO
		};
		if retry && !shutting_down {
			// Wake early on shutdown; new dirty keys wait out the backoff.
			let state = queue.state.lock().unwrap_or_else(|p| p.into_inner());
			let _ = queue.wake.wait_timeout_while(state, backoff, |s| !s.shutdown);
		}
	}
}

impl Drop for DualStore {
	/// Let the worker upload its remaining dirty keys, bounded by `FLUSH_ON_DROP`.
	fn drop(&mut self) {
		self.mirror.shutdown_and_wait(FLUSH_ON_DROP);
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
					Err(vss_err) if vss_err.kind() == io::ErrorKind::NotFound => {
						// Neither store has it — return the original NotFound.
						Err(local_err)
					},
					Err(vss_err) => {
						// A network/auth/server error during restore must NOT be masked as
						// NotFound: that would make the node come up fresh (no channels)
						// and look like a successful restore. Fail the read — and thereby
						// the build — so the caller can surface the error and retry.
						eprintln!(
							"DualStore: VSS read failed during restore for {}/{}/{}: {}",
							primary_namespace, secondary_namespace, key, vss_err
						);
						Err(vss_err)
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
		KVStoreSync::write(self.local.as_ref(), primary_namespace, secondary_namespace, key, buf)?;

		// The worker uploads it. Marking before returning is what keeps VSS's monitors ahead
		// of its manager (module docs).
		self.mirror.mark_dirty(key_of(primary_namespace, secondary_namespace, key));
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

		// The worker finds the key gone locally and removes it from VSS.
		self.mirror.mark_dirty(key_of(primary_namespace, secondary_namespace, key));
		Ok(())
	}

	fn list(&self, primary_namespace: &str, secondary_namespace: &str) -> io::Result<Vec<String>> {
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
				// Same rationale as in read(): masking a VSS failure as an empty
				// namespace during restore silently produces a fresh node. Propagate
				// so the restore fails loudly instead.
				eprintln!(
					"DualStore: VSS list failed during restore for {}/{}: {}",
					primary_namespace, secondary_namespace, e
				);
				Err(e)
			},
		}
	}
}

impl KVStore for DualStore {
	fn read(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, io::Error>> + Send>> {
		let result = KVStoreSync::read(self, primary_namespace, secondary_namespace, key);
		Box::pin(async move { result })
	}

	fn write(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>,
	) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send>> {
		let result = KVStoreSync::write(self, primary_namespace, secondary_namespace, key, buf);
		Box::pin(async move { result })
	}

	fn remove(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, lazy: bool,
	) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send>> {
		let result = KVStoreSync::remove(self, primary_namespace, secondary_namespace, key, lazy);
		Box::pin(async move { result })
	}

	fn list(
		&self, primary_namespace: &str, secondary_namespace: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, io::Error>> + Send>> {
		let result = KVStoreSync::list(self, primary_namespace, secondary_namespace);
		Box::pin(async move { result })
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::collections::HashMap;
	use std::sync::atomic::{AtomicUsize, Ordering};

	/// (namespace, key, value written; `None` for a remove)
	type LogEntry = (String, String, Option<Vec<u8>>);

	/// In-memory store. As the VSS side: `fail_namespace` refuses writes to one primary
	/// namespace, `fail_lists` makes list calls error, `gate_key` holds uploads of one key
	/// until `open_gate`, and `log` lists successful writes and removes in order.
	#[derive(Default)]
	struct MemStore {
		data: Mutex<HashMap<Key, Vec<u8>>>,
		fail_namespace: Mutex<Option<String>>,
		fail_lists: Mutex<bool>,
		failed_writes: AtomicUsize,
		gate_key: Mutex<Option<String>>,
		gate_cv: Condvar,
		gate_entered: AtomicUsize,
		log: Mutex<Vec<LogEntry>>,
	}

	impl MemStore {
		fn get(&self, pns: &str, sns: &str, key: &str) -> Option<Vec<u8>> {
			self.data.lock().unwrap().get(&key_of(pns, sns, key)).cloned()
		}

		fn put(&self, pns: &str, sns: &str, key: &str, val: &[u8]) {
			self.data.lock().unwrap().insert(key_of(pns, sns, key), val.to_vec());
		}

		fn close_gate(&self, key: &str) {
			*self.gate_key.lock().unwrap() = Some(key.to_string());
		}

		fn open_gate(&self) {
			*self.gate_key.lock().unwrap() = None;
			self.gate_cv.notify_all();
		}

		/// Position of the first logged write of `key` with `val` (`None` = a remove).
		fn logged_at(&self, key: &str, val: Option<&[u8]>) -> Option<usize> {
			self.log.lock().unwrap().iter().position(|(_, k, v)| k == key && v.as_deref() == val)
		}
	}

	impl KVStoreSync for MemStore {
		fn read(&self, pns: &str, sns: &str, key: &str) -> io::Result<Vec<u8>> {
			self.get(pns, sns, key)
				.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "mem: not found"))
		}

		fn write(&self, pns: &str, sns: &str, key: &str, buf: Vec<u8>) -> io::Result<()> {
			if self.fail_namespace.lock().unwrap().as_deref() == Some(pns) {
				self.failed_writes.fetch_add(1, Ordering::SeqCst);
				return Err(io::Error::new(io::ErrorKind::Other, "mem: write refused"));
			}
			{
				let mut gate = self.gate_key.lock().unwrap();
				if gate.as_deref() == Some(key) {
					self.gate_entered.fetch_add(1, Ordering::SeqCst);
					while gate.as_deref() == Some(key) {
						gate = self.gate_cv.wait(gate).unwrap();
					}
				}
			}
			self.log.lock().unwrap().push((pns.to_string(), key.to_string(), Some(buf.clone())));
			self.data.lock().unwrap().insert(key_of(pns, sns, key), buf);
			Ok(())
		}

		fn remove(&self, pns: &str, sns: &str, key: &str, _lazy: bool) -> io::Result<()> {
			self.log.lock().unwrap().push((pns.to_string(), key.to_string(), None));
			self.data.lock().unwrap().remove(&key_of(pns, sns, key));
			Ok(())
		}

		fn list(&self, pns: &str, sns: &str) -> io::Result<Vec<String>> {
			if *self.fail_lists.lock().unwrap() {
				return Err(io::Error::new(io::ErrorKind::Other, "mem: unreachable"));
			}
			Ok(self
				.data
				.lock()
				.unwrap()
				.keys()
				.filter(|(p, s, _)| p == pns && s == sns)
				.map(|(_, _, k)| k.clone())
				.collect())
		}
	}

	/// The worker wired as `DualStore` wires it, over in-memory stores.
	struct Harness {
		local: Arc<MemStore>,
		vss: Arc<MemStore>,
		queue: Arc<MirrorQueue>,
	}

	impl Harness {
		/// Push gate open, as after a legitimate restore or once the check passed.
		fn new() -> Self {
			Self::with(Arc::new(MemStore::default()), Arc::new(MemStore::default()), Some(true))
		}

		fn with(local: Arc<MemStore>, vss: Arc<MemStore>, gate: Option<bool>) -> Self {
			let initial: HashSet<Key> = local.data.lock().unwrap().keys().cloned().collect();
			let queue = Arc::new(MirrorQueue::new(initial));
			spawn_mirror_worker(
				Arc::clone(&local),
				Arc::clone(&vss),
				Arc::new(Mutex::new(gate)),
				Arc::clone(&queue),
			);
			Self { local, vss, queue }
		}

		/// What `DualStore::write` does.
		fn write(&self, pns: &str, key: &str, val: &[u8]) {
			self.local.put(pns, "", key, val);
			self.queue.mark_dirty(key_of(pns, "", key));
		}

		/// What `DualStore::remove` does.
		fn remove(&self, pns: &str, key: &str) {
			self.local.data.lock().unwrap().remove(&key_of(pns, "", key));
			self.queue.mark_dirty(key_of(pns, "", key));
		}
	}

	impl Drop for Harness {
		fn drop(&mut self) {
			self.queue.shutdown_and_wait(FLUSH_ON_DROP);
		}
	}

	fn wait_until(cond: impl Fn() -> bool) {
		let deadline = Instant::now() + Duration::from_secs(5);
		while !cond() {
			assert!(Instant::now() < deadline, "condition not met within 5s");
			std::thread::sleep(Duration::from_millis(10));
		}
	}

	const MON: &str = CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE;
	const UPD: &str = CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE;

	/// #10 — a slow older upload must not land after a newer write.
	#[test]
	fn newer_write_wins_when_an_older_upload_is_slow() {
		let h = Harness::new();
		h.vss.close_gate("mon1");
		h.write(MON, "mon1", b"v1");
		wait_until(|| h.vss.gate_entered.load(Ordering::SeqCst) == 1);
		h.write(MON, "mon1", b"v2");
		h.vss.open_gate();

		wait_until(|| h.vss.get(MON, "", "mon1").as_deref() == Some(&b"v2"[..]));
		assert!(h.vss.logged_at("mon1", Some(b"v1")) < h.vss.logged_at("mon1", Some(b"v2")));
	}

	/// #10 — writes queued behind an in-flight upload are sent once, as the newest value.
	#[test]
	fn writes_queued_behind_an_upload_collapse_to_the_newest() {
		let h = Harness::new();
		h.vss.close_gate("mon1");
		h.write(MON, "mon1", b"v1");
		wait_until(|| h.vss.gate_entered.load(Ordering::SeqCst) == 1);
		for v in [&b"v2"[..], b"v3", b"v4"] {
			h.write(MON, "mon1", v);
		}
		h.vss.open_gate();

		wait_until(|| h.vss.get(MON, "", "mon1").as_deref() == Some(&b"v4"[..]));
		let values: Vec<_> = h.vss.log.lock().unwrap().iter().map(|(_, _, v)| v.clone()).collect();
		assert_eq!(values, vec![Some(b"v1".to_vec()), Some(b"v4".to_vec())]);
	}

	/// #10 — while a monitor upload fails, the manager must stay off VSS.
	#[test]
	fn manager_waits_for_failed_monitor_upload() {
		let h = Harness::new();
		*h.vss.fail_namespace.lock().unwrap() = Some(MON.to_string());
		h.write(MON, "mon1", b"mon-v1");
		h.write("", "manager", b"mgr-v1");
		wait_until(|| h.vss.failed_writes.load(Ordering::SeqCst) >= 1);
		std::thread::sleep(Duration::from_millis(200));
		assert!(h.vss.get("", "", "manager").is_none(), "manager uploaded ahead of its monitor");

		*h.vss.fail_namespace.lock().unwrap() = None;
		wait_until(|| h.vss.get("", "", "manager").is_some());
		let mon = h.vss.logged_at("mon1", Some(b"mon-v1"));
		assert!(mon < h.vss.logged_at("manager", Some(b"mgr-v1")));
	}

	/// #10 — within one round the manager goes after the monitor keys.
	#[test]
	fn manager_is_uploaded_after_monitor_keys_in_a_round() {
		let h = Harness::new();
		h.vss.close_gate("scorer");
		h.write("", "scorer", b"s");
		wait_until(|| h.vss.gate_entered.load(Ordering::SeqCst) == 1);
		h.write("", "manager", b"mgr");
		h.write(MON, "mon1", b"a");
		h.write(UPD, "1", b"u1");
		h.vss.open_gate();

		wait_until(|| h.vss.get("", "", "manager").is_some());
		let mgr = h.vss.logged_at("manager", Some(b"mgr")).unwrap();
		assert!(h.vss.logged_at("mon1", Some(b"a")).unwrap() < mgr);
		assert!(h.vss.logged_at("1", Some(b"u1")).unwrap() < mgr);
	}

	/// #10 — `MonitorUpdatingPersister` consolidation: the full monitor is rewritten and the
	/// update keys it supersedes are deleted. VSS must not lose an update key before it holds
	/// the new full monitor.
	#[test]
	fn update_keys_are_removed_only_after_the_full_monitor_is_on_vss() {
		let h = Harness::new();
		h.write(MON, "mon1", b"full-v1");
		h.write(UPD, "7", b"upd-7");
		wait_until(|| h.vss.get(UPD, "", "7").is_some());

		*h.vss.fail_namespace.lock().unwrap() = Some(MON.to_string());
		h.write(MON, "mon1", b"full-v2");
		h.remove(UPD, "7");
		wait_until(|| h.vss.failed_writes.load(Ordering::SeqCst) >= 1);
		std::thread::sleep(Duration::from_millis(200));
		assert!(h.vss.get(UPD, "", "7").is_some(), "update key removed before its full monitor");

		*h.vss.fail_namespace.lock().unwrap() = None;
		wait_until(|| h.vss.get(UPD, "", "7").is_none());
		assert!(h.vss.logged_at("mon1", Some(b"full-v2")) < h.vss.logged_at("7", None));
	}

	#[test]
	fn remove_reaches_vss() {
		let h = Harness::new();
		h.write("", "scorer", b"s");
		wait_until(|| h.vss.get("", "", "scorer").is_some());
		h.remove("", "scorer");
		wait_until(|| h.vss.get("", "", "scorer").is_none());
	}

	/// The startup sync uploads every local key, monitors before the manager.
	#[test]
	fn startup_sync_uploads_existing_keys_in_order() {
		let local = Arc::new(MemStore::default());
		local.put("", "", "manager", b"mgr");
		local.put(MON, "", "mon1", b"m");
		let h = Harness::with(local, Arc::new(MemStore::default()), None);

		wait_until(|| h.vss.get("", "", "manager").is_some());
		assert!(h.vss.logged_at("mon1", Some(b"m")) < h.vss.logged_at("manager", Some(b"mgr")));
	}

	/// The push safety gate still applies: local has no monitors while VSS has one, so
	/// nothing may be uploaded this session.
	#[test]
	fn poisoned_local_store_uploads_nothing() {
		let local = Arc::new(MemStore::default());
		local.put("", "", "manager", b"fresh-manager");
		let vss = Arc::new(MemStore::default());
		vss.put(MON, "", "mon1", b"backed-up");
		vss.put("", "", "manager", b"backed-up-manager");
		let h = Harness::with(local, vss, None);

		h.write("", "scorer", b"s");
		std::thread::sleep(Duration::from_millis(300));
		assert!(h.vss.log.lock().unwrap().is_empty());
		assert_eq!(h.vss.get("", "", "manager").unwrap(), b"backed-up-manager");
	}

	/// An undetermined verdict (VSS list fails) keeps the keys dirty until it resolves.
	#[test]
	fn undetermined_gate_keeps_keys_until_vss_answers() {
		let local = Arc::new(MemStore::default());
		local.put("", "", "manager", b"mgr");
		let vss = Arc::new(MemStore::default());
		*vss.fail_lists.lock().unwrap() = true;
		let h = Harness::with(local, vss, None);

		std::thread::sleep(Duration::from_millis(200));
		assert!(h.vss.get("", "", "manager").is_none());
		*h.vss.fail_lists.lock().unwrap() = false;
		wait_until(|| h.vss.get("", "", "manager").is_some());
	}

	/// A clean shutdown uploads what is still dirty before returning.
	#[test]
	fn shutdown_flushes_dirty_keys() {
		let h = Harness::new();
		h.vss.close_gate("mon1");
		h.write(MON, "mon1", b"v1");
		wait_until(|| h.vss.gate_entered.load(Ordering::SeqCst) == 1);
		h.write("", "manager", b"mgr");

		let vss = Arc::clone(&h.vss);
		let opener = std::thread::spawn(move || {
			std::thread::sleep(Duration::from_millis(100));
			vss.open_gate();
		});
		h.queue.shutdown_and_wait(FLUSH_ON_DROP);
		opener.join().unwrap();
		assert_eq!(h.vss.get(MON, "", "mon1").unwrap(), b"v1");
		assert_eq!(h.vss.get("", "", "manager").unwrap(), b"mgr");
	}

	/// Shutdown does not hang on a VSS that keeps failing.
	#[test]
	fn shutdown_does_not_wait_forever_on_a_failing_vss() {
		let h = Harness::new();
		*h.vss.fail_namespace.lock().unwrap() = Some(MON.to_string());
		h.write(MON, "mon1", b"v1");
		wait_until(|| h.vss.failed_writes.load(Ordering::SeqCst) >= 1);
		let start = Instant::now();
		h.queue.shutdown_and_wait(FLUSH_ON_DROP);
		assert!(start.elapsed() < FLUSH_ON_DROP);
	}

	/// A manager write that lands after the worker read its manager snapshot must still reach
	/// VSS, including when it is the last write before shutdown.
	#[test]
	fn manager_written_after_the_snapshot_read_is_not_lost() {
		use std::sync::mpsc;
		let h = Harness::new();
		let (read_tx, read_rx) = mpsc::channel::<()>();
		let (go_tx, go_rx) = mpsc::channel::<()>();
		*h.queue.after_manager_read.lock().unwrap() = Some(Box::new(move || {
			read_tx.send(()).unwrap();
			go_rx.recv().unwrap();
		}));

		h.write("", "manager", b"v1");
		// The worker has read v1 and is paused before taking its batch.
		read_rx.recv_timeout(Duration::from_secs(5)).unwrap();
		h.write("", "manager", b"v2");
		go_tx.send(()).unwrap();

		h.queue.shutdown_and_wait(FLUSH_ON_DROP);
		assert_eq!(h.vss.get("", "", "manager").unwrap(), b"v2");
	}

	/// The manager mark consumed before an undetermined push verdict is kept for a later round.
	#[test]
	fn manager_mark_survives_an_undetermined_verdict() {
		// No local monitors, so the gate has to ask VSS, and VSS cannot answer yet.
		let local = Arc::new(MemStore::default());
		local.put("", "", "scorer", b"s");
		let vss = Arc::new(MemStore::default());
		*vss.fail_lists.lock().unwrap() = true;
		let h = Harness::with(local, vss, None);
		h.write("", "manager", b"mgr");

		std::thread::sleep(Duration::from_millis(200));
		assert!(h.vss.get("", "", "manager").is_none());
		*h.vss.fail_lists.lock().unwrap() = false;
		wait_until(|| h.vss.get("", "", "manager").is_some());
	}
}

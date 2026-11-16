// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;

use bitcoin::FeeRate;
use lightning::chain::chaininterface::{
	ConfirmationTarget as LdkConfirmationTarget, FeeEstimator as LdkFeeEstimator,
	FEERATE_FLOOR_SATS_PER_KW,
};
use lightning::impl_writeable_tlv_based;

use crate::Error;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum ConfirmationTarget {
	/// The default target for onchain payments.
	OnchainPayment,
	/// The target used for funding transactions.
	ChannelFunding,
	/// Targets used by LDK.
	Lightning(LdkConfirmationTarget),
}

impl ConfirmationTarget {
	// The identifier under which we persist a target's fee rate. These are stored, so an
	// identifier must never be reused for a different target.
	fn persistence_id(&self) -> u8 {
		match self {
			Self::OnchainPayment => 0,
			Self::ChannelFunding => 1,
			Self::Lightning(ldk_target) => match ldk_target {
				LdkConfirmationTarget::MaximumFeeEstimate => 2,
				LdkConfirmationTarget::UrgentOnChainSweep => 3,
				LdkConfirmationTarget::MinAllowedAnchorChannelRemoteFee => 4,
				LdkConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee => 5,
				LdkConfirmationTarget::AnchorChannelFee => 6,
				LdkConfirmationTarget::NonAnchorChannelFee => 7,
				LdkConfirmationTarget::ChannelCloseMinimum => 8,
				LdkConfirmationTarget::OutputSpendingFee => 9,
			},
		}
	}

	fn from_persistence_id(id: u8) -> Option<Self> {
		get_all_conf_targets().into_iter().find(|target| target.persistence_id() == id)
	}
}

/// A fee rate estimate as we persist it, so that a node starting without a reachable chain source
/// can use the estimates of its previous run rather than the hardcoded fallback rates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PersistedFeeRate {
	target_id: u8,
	sat_per_kwu: u64,
}

impl_writeable_tlv_based!(PersistedFeeRate, {
	(0, target_id, required),
	(2, sat_per_kwu, required),
});

pub(crate) trait FeeEstimator {
	fn estimate_fee_rate(&self, confirmation_target: ConfirmationTarget) -> FeeRate;
}

impl From<LdkConfirmationTarget> for ConfirmationTarget {
	fn from(value: LdkConfirmationTarget) -> Self {
		Self::Lightning(value)
	}
}

pub(crate) struct OnchainFeeEstimator {
	fee_rate_cache: RwLock<HashMap<ConfirmationTarget, FeeRate>>,
	// Set when the node started although its startup fee rate update failed, and cleared by the
	// next update that succeeds. While set, `estimate_fee_rate` may return the hardcoded
	// fallback rates.
	awaiting_first_update: AtomicBool,
}

impl OnchainFeeEstimator {
	pub(crate) fn new() -> Self {
		let fee_rate_cache = RwLock::new(HashMap::new());
		let awaiting_first_update = AtomicBool::new(false);
		Self { fee_rate_cache, awaiting_first_update }
	}

	// Returns the current cache for persistence. Empty if we never retrieved any estimates.
	pub(crate) fn fee_rate_cache_snapshot(&self) -> Vec<PersistedFeeRate> {
		let locked_fee_rate_cache = self.fee_rate_cache.read().unwrap();
		let mut snapshot = locked_fee_rate_cache
			.iter()
			.map(|(target, fee_rate)| PersistedFeeRate {
				target_id: target.persistence_id(),
				sat_per_kwu: fee_rate.to_sat_per_kwu(),
			})
			.collect::<Vec<_>>();
		snapshot.sort_by_key(|entry| entry.target_id);
		snapshot
	}

	// Fills the cache with the estimates persisted by a previous run. They only serve until the
	// first update of this run, and don't count as one: `ensure_estimates_available` keeps
	// failing after a failed startup update, as these rates may be arbitrarily old.
	pub(crate) fn seed_fee_rate_cache(&self, persisted: &[PersistedFeeRate]) {
		let mut locked_fee_rate_cache = self.fee_rate_cache.write().unwrap();
		if !locked_fee_rate_cache.is_empty() {
			return;
		}
		for entry in persisted {
			// Skip targets we don't know, e.g., ones written by a newer version.
			if let Some(target) = ConfirmationTarget::from_persistence_id(entry.target_id) {
				locked_fee_rate_cache.insert(target, FeeRate::from_sat_per_kwu(entry.sat_per_kwu));
			}
		}
	}

	pub(crate) fn set_awaiting_first_update(&self, awaiting: bool) {
		self.awaiting_first_update.store(awaiting, Ordering::Release);
	}

	// Fails while the node runs on fallback rates because its startup fee rate update failed.
	// User-initiated wallet spends that rely on our estimate call this first: nothing bumps
	// their fee later, so they must not be built on a hardcoded rate.
	pub(crate) fn ensure_estimates_available(&self) -> Result<(), Error> {
		if self.awaiting_first_update.load(Ordering::Acquire) {
			Err(Error::FeerateEstimationUpdateFailed)
		} else {
			Ok(())
		}
	}

	// Updates the fee rate cache and returns if the new values changed.
	pub(crate) fn set_fee_rate_cache(
		&self, fee_rate_cache_update: HashMap<ConfirmationTarget, FeeRate>,
	) -> bool {
		let mut locked_fee_rate_cache = self.fee_rate_cache.write().unwrap();
		self.awaiting_first_update.store(false, Ordering::Release);
		if fee_rate_cache_update != *locked_fee_rate_cache {
			*locked_fee_rate_cache = fee_rate_cache_update;
			true
		} else {
			false
		}
	}
}

impl FeeEstimator for OnchainFeeEstimator {
	fn estimate_fee_rate(&self, confirmation_target: ConfirmationTarget) -> FeeRate {
		let locked_fee_rate_cache = self.fee_rate_cache.read().unwrap();

		let fallback_sats_kwu = get_fallback_rate_for_target(confirmation_target);

		// We'll fall back on this, if we really don't have any other information.
		let fallback_rate = FeeRate::from_sat_per_kwu(fallback_sats_kwu as u64);

		let estimate = *locked_fee_rate_cache.get(&confirmation_target).unwrap_or(&fallback_rate);

		// For ChannelCloseMinimum, use a lower floor so we don't reject
		// cooperative close proposals from peers using sub-relay feerates.
		let floor = match confirmation_target {
			ConfirmationTarget::Lightning(LdkConfirmationTarget::ChannelCloseMinimum) => {
				FEERATE_FLOOR_SATS_PER_KW as u64 / 2
			},
			_ => FEERATE_FLOOR_SATS_PER_KW as u64,
		};

		FeeRate::from_sat_per_kwu(estimate.to_sat_per_kwu().max(floor))
	}
}

impl LdkFeeEstimator for OnchainFeeEstimator {
	fn get_est_sat_per_1000_weight(&self, confirmation_target: LdkConfirmationTarget) -> u32 {
		let rate = self
			.estimate_fee_rate(confirmation_target.into())
			.to_sat_per_kwu()
			.try_into()
			.unwrap_or_else(|_| get_fallback_rate_for_ldk_target(confirmation_target));

		// For ChannelCloseMinimum, return a value that won't be clamped up
		// by LowerBoundedFeeEstimator. We want to accept cooperative close
		// proposals below the standard relay fee floor.
		if confirmation_target == LdkConfirmationTarget::ChannelCloseMinimum {
			return core::cmp::min(rate, FEERATE_FLOOR_SATS_PER_KW / 2);
		}

		rate
	}
}

pub(crate) fn get_num_block_defaults_for_target(target: ConfirmationTarget) -> usize {
	match target {
		ConfirmationTarget::OnchainPayment => 6,
		ConfirmationTarget::ChannelFunding => 12,
		ConfirmationTarget::Lightning(ldk_target) => match ldk_target {
			LdkConfirmationTarget::MaximumFeeEstimate => 1,
			LdkConfirmationTarget::UrgentOnChainSweep => 6,
			LdkConfirmationTarget::MinAllowedAnchorChannelRemoteFee => 1008,
			LdkConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee => 144,
			LdkConfirmationTarget::AnchorChannelFee => 1008,
			LdkConfirmationTarget::NonAnchorChannelFee => 12,
			LdkConfirmationTarget::ChannelCloseMinimum => 1008,
			LdkConfirmationTarget::OutputSpendingFee => 12,
		},
	}
}

pub(crate) fn get_fallback_rate_for_target(target: ConfirmationTarget) -> u32 {
	match target {
		ConfirmationTarget::OnchainPayment => 5000,
		ConfirmationTarget::ChannelFunding => 1000,
		ConfirmationTarget::Lightning(ldk_target) => get_fallback_rate_for_ldk_target(ldk_target),
	}
}

pub(crate) fn get_fallback_rate_for_ldk_target(target: LdkConfirmationTarget) -> u32 {
	match target {
		LdkConfirmationTarget::MaximumFeeEstimate => 8000,
		LdkConfirmationTarget::UrgentOnChainSweep => 5000,
		LdkConfirmationTarget::MinAllowedAnchorChannelRemoteFee => FEERATE_FLOOR_SATS_PER_KW,
		LdkConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee => FEERATE_FLOOR_SATS_PER_KW,
		LdkConfirmationTarget::AnchorChannelFee => 500,
		LdkConfirmationTarget::NonAnchorChannelFee => 1000,
		LdkConfirmationTarget::ChannelCloseMinimum => 500,
		LdkConfirmationTarget::OutputSpendingFee => 1000,
	}
}

pub(crate) fn get_all_conf_targets() -> [ConfirmationTarget; 10] {
	[
		ConfirmationTarget::OnchainPayment,
		ConfirmationTarget::ChannelFunding,
		LdkConfirmationTarget::MaximumFeeEstimate.into(),
		LdkConfirmationTarget::UrgentOnChainSweep.into(),
		LdkConfirmationTarget::MinAllowedAnchorChannelRemoteFee.into(),
		LdkConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee.into(),
		LdkConfirmationTarget::AnchorChannelFee.into(),
		LdkConfirmationTarget::NonAnchorChannelFee.into(),
		LdkConfirmationTarget::ChannelCloseMinimum.into(),
		LdkConfirmationTarget::OutputSpendingFee.into(),
	]
}

pub(crate) fn apply_post_estimation_adjustments(
	target: ConfirmationTarget, estimated_rate: FeeRate,
) -> FeeRate {
	match target {
		ConfirmationTarget::Lightning(
			LdkConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee,
		) => {
			let slightly_less_than_background = estimated_rate
				.to_sat_per_kwu()
				.saturating_sub(250)
				.max(FEERATE_FLOOR_SATS_PER_KW as u64);
			FeeRate::from_sat_per_kwu(slightly_less_than_background)
		},
		ConfirmationTarget::Lightning(LdkConfirmationTarget::ChannelCloseMinimum) => {
			// ChannelCloseMinimum is the floor we accept from a counterparty's proposed
			// cooperative close fee. We reduce it slightly so that we don't reject
			// proposals that are just below our Esplora estimate.
			let slightly_less = estimated_rate
				.to_sat_per_kwu()
				.saturating_sub(250)
				.max(FEERATE_FLOOR_SATS_PER_KW as u64);
			FeeRate::from_sat_per_kwu(slightly_less)
		},
		ConfirmationTarget::Lightning(LdkConfirmationTarget::MaximumFeeEstimate) => {
			// MaximumFeeEstimate is mostly used for protection against fee-inflation attacks. As
			// users were previously impacted by this limit being too restrictive (read: too low),
			// we bump it here a bit to give them some leeway.
			let slightly_bump = estimated_rate
				.to_sat_per_kwu()
				.saturating_mul(11)
				.saturating_div(10)
				.saturating_add(2500);
			FeeRate::from_sat_per_kwu(slightly_bump)
		},
		_ => estimated_rate,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn estimates_unavailable_until_first_update() {
		let estimator = OnchainFeeEstimator::new();
		assert_eq!(estimator.ensure_estimates_available(), Ok(()));

		estimator.set_awaiting_first_update(true);
		assert_eq!(
			estimator.ensure_estimates_available(),
			Err(Error::FeerateEstimationUpdateFailed)
		);
		// The fallback rates still serve LDK while we wait.
		assert_eq!(
			estimator.estimate_fee_rate(ConfirmationTarget::OnchainPayment),
			FeeRate::from_sat_per_kwu(5000)
		);

		let mut update = HashMap::new();
		update.insert(ConfirmationTarget::OnchainPayment, FeeRate::from_sat_per_kwu(750));
		estimator.set_fee_rate_cache(update);
		assert_eq!(estimator.ensure_estimates_available(), Ok(()));
		assert_eq!(
			estimator.estimate_fee_rate(ConfirmationTarget::OnchainPayment),
			FeeRate::from_sat_per_kwu(750)
		);
	}

	#[test]
	fn persistence_ids_are_unique_and_round_trip() {
		let targets = get_all_conf_targets();
		let mut ids = targets.iter().map(|t| t.persistence_id()).collect::<Vec<_>>();
		ids.sort();
		ids.dedup();
		assert_eq!(ids.len(), targets.len());
		for target in targets {
			assert_eq!(
				ConfirmationTarget::from_persistence_id(target.persistence_id()),
				Some(target)
			);
		}
		assert_eq!(ConfirmationTarget::from_persistence_id(200), None);
	}

	#[test]
	fn snapshot_seeds_a_new_estimator() {
		let estimator = OnchainFeeEstimator::new();
		assert!(estimator.fee_rate_cache_snapshot().is_empty());

		let mut update = HashMap::new();
		for (i, target) in get_all_conf_targets().into_iter().enumerate() {
			update.insert(target, FeeRate::from_sat_per_kwu(1000 + i as u64));
		}
		estimator.set_fee_rate_cache(update);
		let snapshot = estimator.fee_rate_cache_snapshot();
		assert_eq!(snapshot.len(), 10);

		let restarted = OnchainFeeEstimator::new();
		restarted.seed_fee_rate_cache(&snapshot);
		for target in get_all_conf_targets() {
			assert_eq!(restarted.estimate_fee_rate(target), estimator.estimate_fee_rate(target));
		}
		assert_eq!(restarted.fee_rate_cache_snapshot(), snapshot);
	}

	#[test]
	fn seeding_skips_unknown_targets_and_keeps_fresh_estimates() {
		let estimator = OnchainFeeEstimator::new();
		let persisted = vec![
			PersistedFeeRate { target_id: 0, sat_per_kwu: 2000 },
			PersistedFeeRate { target_id: 200, sat_per_kwu: 9000 },
		];
		estimator.seed_fee_rate_cache(&persisted);
		assert_eq!(
			estimator.estimate_fee_rate(ConfirmationTarget::OnchainPayment),
			FeeRate::from_sat_per_kwu(2000)
		);
		// A target missing from the persisted set still uses its fallback.
		assert_eq!(
			estimator.estimate_fee_rate(ConfirmationTarget::ChannelFunding),
			FeeRate::from_sat_per_kwu(1000)
		);

		// Seeding never replaces estimates we already hold.
		let newer = vec![PersistedFeeRate { target_id: 0, sat_per_kwu: 4000 }];
		estimator.seed_fee_rate_cache(&newer);
		assert_eq!(
			estimator.estimate_fee_rate(ConfirmationTarget::OnchainPayment),
			FeeRate::from_sat_per_kwu(2000)
		);
	}

	#[test]
	fn seeded_estimates_do_not_open_the_spend_gate() {
		let estimator = OnchainFeeEstimator::new();
		estimator.seed_fee_rate_cache(&[PersistedFeeRate { target_id: 0, sat_per_kwu: 2000 }]);
		estimator.set_awaiting_first_update(true);
		assert_eq!(
			estimator.ensure_estimates_available(),
			Err(Error::FeerateEstimationUpdateFailed)
		);
	}

	#[test]
	fn clearing_the_flag_without_a_cache_update() {
		let estimator = OnchainFeeEstimator::new();
		estimator.set_awaiting_first_update(true);
		estimator.set_awaiting_first_update(false);
		assert_eq!(estimator.ensure_estimates_available(), Ok(()));
	}
}

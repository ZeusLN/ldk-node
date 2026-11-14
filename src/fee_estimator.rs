// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::collections::HashMap;
use std::sync::RwLock;

use bitcoin::constants::WITNESS_SCALE_FACTOR;
use bitcoin::{FeeRate, TxOut};
use lightning::chain::chaininterface::{
	ConfirmationTarget as LdkConfirmationTarget, FeeEstimator as LdkFeeEstimator,
	FEERATE_FLOOR_SATS_PER_KW,
};
use lightning::ln::chan_utils::FUNDING_TRANSACTION_WITNESS_WEIGHT;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum ConfirmationTarget {
	/// The default target for onchain payments.
	OnchainPayment,
	/// The target used for funding transactions.
	ChannelFunding,
	/// Targets used by LDK.
	Lightning(LdkConfirmationTarget),
}

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
}

impl OnchainFeeEstimator {
	pub(crate) fn new() -> Self {
		let fee_rate_cache = RwLock::new(HashMap::new());
		Self { fee_rate_cache }
	}

	// Updates the fee rate cache and returns if the new values changed.
	pub(crate) fn set_fee_rate_cache(
		&self, fee_rate_cache_update: HashMap<ConfirmationTarget, FeeRate>,
	) -> bool {
		let mut locked_fee_rate_cache = self.fee_rate_cache.write().unwrap();
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

/// The highest feerate we accept for a splice we initiate: 250 sat/vB, or 62,500 sat/kW.
///
/// As 1 sat/vB is 250 sat/kW, a sat/kW feerate given in sat/vB is 250 times too high. Any such
/// feerate at or above [`FEERATE_FLOOR_SATS_PER_KW`] then lands above this bound, so the mistake is
/// refused instead of overpaying a splice that can't be undone.
pub(crate) const MAX_SPLICE_FEE_RATE: FeeRate = FeeRate::from_sat_per_vb_unchecked(250);

/// Returns whether `fee_rate` may be used as the feerate of a splice we initiate.
///
/// As a splice can't be fee-bumped, it must be at least the floor we apply to our own estimates, so
/// it confirms, and at most [`MAX_SPLICE_FEE_RATE`], as an overpayment is just as permanent.
pub(crate) fn is_valid_splice_fee_rate(fee_rate: FeeRate) -> bool {
	fee_rate.to_sat_per_kwu() >= FEERATE_FLOOR_SATS_PER_KW as u64 && fee_rate <= MAX_SPLICE_FEE_RATE
}

/// Returns the fee, in sats, that a splice-out paying to `output` at `fee_rate_per_kw` takes from
/// our channel balance.
///
/// As the initiator, we pay for the transaction's common fields, the input spending the current
/// funding output and the new funding output, along with our own output. This mirrors how LDK
/// estimates the fee of our contribution when we call `ChannelManager::splice_channel`.
pub(crate) fn splice_out_fee_sats(output: &TxOut, fee_rate_per_kw: u32) -> u64 {
	// Version, locktime, input count and output count, plus the segwit marker and flag.
	const COMMON_FIELDS_WEIGHT: u64 = (4 + 4 + 1 + 1) * WITNESS_SCALE_FACTOR as u64 + 2;
	// Outpoint, sequence and an empty script_sig, plus the 2-of-2 multisig witness. LDK takes 1 WU
	// off, as its default `grind_signatures` feature makes our signature a byte shorter.
	const FUNDING_INPUT_WEIGHT: u64 =
		(32 + 4 + 4 + 1) * WITNESS_SCALE_FACTOR as u64 + FUNDING_TRANSACTION_WITNESS_WEIGHT - 1;
	// Value, script length and a P2WSH script.
	const FUNDING_OUTPUT_WEIGHT: u64 = (8 + 1 + 34) * WITNESS_SCALE_FACTOR as u64;

	let weight = COMMON_FIELDS_WEIGHT
		+ FUNDING_INPUT_WEIGHT
		+ FUNDING_OUTPUT_WEIGHT
		+ output.weight().to_wu();
	// Rounded up, as LDK does.
	(u64::from(fee_rate_per_kw) * weight).div_ceil(1000)
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
	use bitcoin::hashes::Hash;
	use bitcoin::{Amount, FeeRate, ScriptBuf, TxOut, WPubkeyHash, WScriptHash};
	use lightning::chain::chaininterface::FEERATE_FLOOR_SATS_PER_KW;

	use super::{is_valid_splice_fee_rate, splice_out_fee_sats, MAX_SPLICE_FEE_RATE};

	#[test]
	fn splice_fee_rate_must_be_within_floor_and_max() {
		let floor = FEERATE_FLOOR_SATS_PER_KW as u64;
		let max = MAX_SPLICE_FEE_RATE.to_sat_per_kwu();
		assert_eq!(max, 62_500);
		assert!(!is_valid_splice_fee_rate(FeeRate::ZERO));
		assert!(!is_valid_splice_fee_rate(FeeRate::from_sat_per_kwu(floor - 1)));
		assert!(is_valid_splice_fee_rate(FeeRate::from_sat_per_kwu(floor)));
		assert!(is_valid_splice_fee_rate(FeeRate::from_sat_per_kwu(max)));
		assert!(!is_valid_splice_fee_rate(FeeRate::from_sat_per_kwu(max + 1)));
	}

	#[test]
	fn splice_fee_rate_in_sat_per_vb_instead_of_sat_per_kw_is_refused() {
		let floor = FEERATE_FLOOR_SATS_PER_KW as u64;
		assert!(!is_valid_splice_fee_rate(FeeRate::from_sat_per_vb_unchecked(floor)));
	}

	#[test]
	fn splice_out_fee_covers_our_share_of_the_splice_transaction() {
		// We pay for 597 WU of the splice transaction, plus our own output.
		let p2wpkh_output = TxOut {
			value: Amount::from_sat(100_000),
			script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::all_zeros()),
		};
		assert_eq!(p2wpkh_output.weight().to_wu(), 124);
		// 721 WU at 2,500 sat/kW is 1,802.5 sats, and at 253 sat/kW 182.413 sats, rounded up.
		assert_eq!(splice_out_fee_sats(&p2wpkh_output, 2_500), 1_803);
		assert_eq!(splice_out_fee_sats(&p2wpkh_output, 253), 183);

		let p2wsh_output = TxOut {
			value: Amount::from_sat(100_000),
			script_pubkey: ScriptBuf::new_p2wsh(&WScriptHash::all_zeros()),
		};
		assert_eq!(p2wsh_output.weight().to_wu(), 172);
		assert_eq!(splice_out_fee_sats(&p2wsh_output, 2_500), 1_923);
	}
}

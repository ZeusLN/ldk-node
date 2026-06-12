// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::ops::Deref;
use std::time::Duration;

use lightning::io;
use lightning::routing::gossip::{EffectiveCapacity, NetworkGraph};
use lightning::routing::router::{CandidateRouteHop, Path};
use lightning::routing::scoring::{
	ChannelLiquidities, ChannelUsage, ProbabilisticScorer, ScoreLookUp, ScoreUpdate,
};
use lightning::util::logger::Logger as LdkLogger;
use lightning::util::ser::{Writeable, Writer};

const IMPOSSIBLE_PENALTY_MSAT: u64 = u64::MAX / 2;

/// Parameters controlling the bimodal scoring model.
///
/// The bimodal model assumes channel liquidity is distributed according to an exponential
/// two-peak distribution (funds cluster at the endpoints), which is consistent with empirical
/// research on Lightning Network channel balances (Pickhardt & Richter, 2021).
pub struct BimodalScoringParameters {
	/// Scale parameter controlling the sharpness of the bimodal distribution (msat).
	///
	/// Smaller values → funds cluster more sharply at the endpoints.
	/// Default matches LND's `BimodalScaleMsat` = 300,000,000 msat (0.003 BTC).
	pub bimodal_scale_msat: u64,
	/// Base penalty applied per hop regardless of amount (msat).
	pub base_penalty_msat: u64,
	/// Multiplier converting `-ln(probability)` to a msat penalty.
	///
	/// Higher values increase the penalty for low-probability hops, causing the router to more
	/// aggressively avoid channels it believes may lack sufficient liquidity.
	pub liquidity_penalty_multiplier_msat: u64,
}

impl Default for BimodalScoringParameters {
	fn default() -> Self {
		Self {
			bimodal_scale_msat: 300_000_000,
			base_penalty_msat: 500,
			liquidity_penalty_multiplier_msat: 30_000,
		}
	}
}

/// A scorer that uses the bimodal probability model to estimate channel liquidity success
/// probability.
///
/// Wraps a [`ProbabilisticScorer`] for liquidity tracking and external score ingestion, but
/// overrides `channel_penalty_msat` to apply the bimodal CDF formula instead of the uniform
/// distribution assumed by the inner scorer.
///
/// ## Bimodal model
///
/// The probability density is proportional to `exp(-x/s) + exp((x-c)/s) + 1/c`, reflecting the
/// empirical observation that channel funds accumulate at the endpoints. For a given payment
/// amount `a` and liquidity bounds `[lo, hi]`:
///
/// ```text
/// P = (H(hi) - H(a)) / (H(hi) - H(lo))
/// where H(x) = -s·exp(-x/s) + s·exp((x-c)/s) + x/c
/// ```
pub(crate) struct BimodalScorer<G: Deref<Target = NetworkGraph<L>>, L: Deref>
where
	L::Target: LdkLogger,
{
	scorer: ProbabilisticScorer<G, L>,
}

impl<G: Deref<Target = NetworkGraph<L>>, L: Deref> BimodalScorer<G, L>
where
	L::Target: LdkLogger,
{
	pub(crate) fn new(scorer: ProbabilisticScorer<G, L>) -> Self {
		Self { scorer }
	}

	pub(crate) fn set_scores(&mut self, scores: ChannelLiquidities) {
		self.scorer.set_scores(scores);
	}
}

/// Primitive function of the bimodal PDF: H(x) = -s·exp(-x/s) + s·exp((x-c)/s) + x/c
///
/// Used to compute the CDF via integration: P(X ≥ a) = (H(hi) - H(a)) / (H(hi) - H(lo)).
fn bimodal_h(x_msat: f64, capacity_msat: f64, scale_msat: f64) -> f64 {
	let s = scale_msat;
	let c = capacity_msat;
	-s * (-x_msat / s).exp() + s * ((x_msat - c) / s).exp() + x_msat / c
}

/// Compute the conditional success probability P(X ≥ amount | lo ≤ X < hi) under the bimodal
/// model.
///
/// Returns 1.0 if amount ≤ lo, 0.0 if amount ≥ hi, and the bimodal CDF otherwise.
fn bimodal_success_probability(
	amount_msat: u64, lo_msat: u64, hi_msat: u64, capacity_msat: u64, scale_msat: u64,
) -> f64 {
	if amount_msat <= lo_msat {
		return 1.0;
	}
	if amount_msat >= hi_msat {
		return 0.0;
	}

	let cap = capacity_msat as f64;
	let scale = scale_msat as f64;
	let h_hi = bimodal_h(hi_msat as f64, cap, scale);
	let h_lo = bimodal_h(lo_msat as f64, cap, scale);
	let h_amt = bimodal_h(amount_msat as f64, cap, scale);

	let denominator = h_hi - h_lo;
	if denominator <= 0.0 {
		// H is monotonically increasing; this only occurs in degenerate inputs.
		return 0.5;
	}

	((h_hi - h_amt) / denominator).clamp(0.0, 1.0)
}

impl<G: Deref<Target = NetworkGraph<L>>, L: Deref> ScoreLookUp for BimodalScorer<G, L>
where
	L::Target: LdkLogger,
{
	type ScoreParams = BimodalScoringParameters;

	fn channel_penalty_msat(
		&self, candidate: &CandidateRouteHop, usage: ChannelUsage,
		score_params: &BimodalScoringParameters,
	) -> u64 {
		let (scid, target) = match (candidate.globally_unique_short_channel_id(), candidate.target()) {
			(Some(scid), Some(target)) => (scid, target),
			_ => return score_params.base_penalty_msat,
		};

		let capacity_msat = match usage.effective_capacity {
			EffectiveCapacity::ExactLiquidity { liquidity_msat } => {
				if usage.amount_msat > liquidity_msat {
					return IMPOSSIBLE_PENALTY_MSAT;
				}
				return score_params.base_penalty_msat;
			},
			EffectiveCapacity::Total { capacity_msat, .. } => capacity_msat,
			EffectiveCapacity::AdvertisedMaxHTLC { amount_msat } => amount_msat,
			EffectiveCapacity::HintMaxHTLC { amount_msat } => amount_msat,
			EffectiveCapacity::Infinite | EffectiveCapacity::Unknown => {
				return score_params.base_penalty_msat
			},
		};

		if capacity_msat == 0 || score_params.bimodal_scale_msat == 0 {
			return IMPOSSIBLE_PENALTY_MSAT;
		}

		let (lo, hi) = self
			.scorer
			.estimated_channel_liquidity_range(scid, &target)
			.unwrap_or((0, capacity_msat));

		// Defensively clamp bounds to [0, capacity].
		let lo = lo.min(capacity_msat);
		let hi = hi.min(capacity_msat);
		let (lo, hi) = if lo > hi { (0, capacity_msat) } else { (lo, hi) };

		let probability = bimodal_success_probability(
			usage.amount_msat,
			lo,
			hi,
			capacity_msat,
			score_params.bimodal_scale_msat,
		);

		if probability <= 0.0 {
			return IMPOSSIBLE_PENALTY_MSAT;
		}
		if probability >= 1.0 {
			return score_params.base_penalty_msat;
		}

		let liquidity_penalty =
			(score_params.liquidity_penalty_multiplier_msat as f64 * (-probability.ln())) as u64;
		score_params.base_penalty_msat.saturating_add(liquidity_penalty)
	}
}

impl<G: Deref<Target = NetworkGraph<L>>, L: Deref> ScoreUpdate for BimodalScorer<G, L>
where
	L::Target: LdkLogger,
{
	fn payment_path_failed(
		&mut self, path: &Path, short_channel_id: u64, duration_since_epoch: Duration,
	) {
		self.scorer.payment_path_failed(path, short_channel_id, duration_since_epoch);
	}

	fn payment_path_successful(&mut self, path: &Path, duration_since_epoch: Duration) {
		self.scorer.payment_path_successful(path, duration_since_epoch);
	}

	fn probe_failed(
		&mut self, path: &Path, short_channel_id: u64, duration_since_epoch: Duration,
	) {
		self.scorer.probe_failed(path, short_channel_id, duration_since_epoch);
	}

	fn probe_successful(&mut self, path: &Path, duration_since_epoch: Duration) {
		self.scorer.probe_successful(path, duration_since_epoch);
	}

	fn time_passed(&mut self, duration_since_epoch: Duration) {
		self.scorer.time_passed(duration_since_epoch);
	}
}

impl<G: Deref<Target = NetworkGraph<L>>, L: Deref> Writeable for BimodalScorer<G, L>
where
	L::Target: LdkLogger,
{
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.scorer.write(writer)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_bimodal_h_monotone() {
		let cap = 1_000_000_000.0f64;
		let scale = 300_000_000.0f64;
		let h0 = bimodal_h(0.0, cap, scale);
		let h_mid = bimodal_h(cap / 2.0, cap, scale);
		let h_c = bimodal_h(cap, cap, scale);
		assert!(h0 < h_mid, "H should be increasing: H(0)={} < H(c/2)={}", h0, h_mid);
		assert!(h_mid < h_c, "H should be increasing: H(c/2)={} < H(c)={}", h_mid, h_c);
	}

	#[test]
	fn test_probability_boundary_cases() {
		let cap = 1_000_000_000u64;
		let scale = 300_000_000u64;

		// amount <= lo → probability 1.0
		assert_eq!(bimodal_success_probability(100, 200, 800_000_000, cap, scale), 1.0);

		// amount >= hi → probability 0.0
		assert_eq!(bimodal_success_probability(900_000_000, 0, 800_000_000, cap, scale), 0.0);
	}

	#[test]
	fn test_probability_midpoint_is_half() {
		let cap = 1_000_000_000u64;
		let scale = 300_000_000u64;

		// At midpoint of a symmetric prior the probability should be ≈ 0.5.
		let p = bimodal_success_probability(cap / 2, 0, cap, cap, scale);
		assert!((p - 0.5).abs() < 0.05, "midpoint probability should be ~0.5, got {}", p);
	}

	#[test]
	fn test_probability_monotone_in_amount() {
		let cap = 1_000_000_000u64;
		let scale = 300_000_000u64;

		let p1 = bimodal_success_probability(100_000_000, 0, cap, cap, scale);
		let p2 = bimodal_success_probability(500_000_000, 0, cap, cap, scale);
		let p3 = bimodal_success_probability(900_000_000, 0, cap, cap, scale);
		assert!(p1 > p2, "p(0.1c)={} > p(0.5c)={}", p1, p2);
		assert!(p2 > p3, "p(0.5c)={} > p(0.9c)={}", p2, p3);
	}

	#[test]
	fn test_small_payment_high_probability() {
		let cap = 1_000_000_000u64;
		let scale = 300_000_000u64;

		// 1% of capacity should succeed with high probability.
		let p = bimodal_success_probability(10_000_000, 0, cap, cap, scale);
		assert!(p > 0.9, "small payment probability should be > 0.9, got {}", p);
	}

	#[test]
	fn test_large_payment_low_probability() {
		let cap = 1_000_000_000u64;
		let scale = 300_000_000u64;

		// 90% of capacity should have low probability under bimodal prior.
		let p = bimodal_success_probability(900_000_000, 0, cap, cap, scale);
		assert!(p < 0.2, "large payment probability should be < 0.2, got {}", p);
	}

	#[test]
	fn test_constrained_bounds_raise_probability() {
		let cap = 1_000_000_000u64;
		let scale = 300_000_000u64;
		let amount = 400_000_000u64;

		// With lo=300M we know at least 300M is available; probability should be higher.
		let p_prior = bimodal_success_probability(amount, 0, cap, cap, scale);
		let p_informed = bimodal_success_probability(amount, 300_000_000, cap, cap, scale);
		assert!(p_informed > p_prior, "informed p={} should be > prior p={}", p_informed, p_prior);
	}
}

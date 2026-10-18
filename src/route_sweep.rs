// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these choices.

//! Seed-only keys for the `to_remote` outputs of ZEUS Route channels.
//!
//! A ZEUS Route node runs lnrod with a VLS signer (vlsd), not ldk-node's
//! `KeysManager`, so its per-channel payment keys follow VLS's
//! `KeyDerivationStyle::Native` rather than LDK's static payment keys:
//!
//! - `ldk_seed` is the private key of the BIP-32 master built from the
//!   64-byte BIP-39 seed of the customer's 24-word mnemonic, empty
//!   passphrase (zeus-vls `vlsd/src/onboarding.rs`, `derive_ldk_seed`).
//! - `channels_seed = HKDF-SHA256(ikm = ldk_seed, salt = "", info = "peer seed")`.
//! - lnrod numbers channels with a `dbid` counter starting at 1 and vlsd
//!   creates each one as `NewChannel { peer_id: [0; 33], dbid }`, so the VLS
//!   channel id is the 41 bytes `[0; 33] || dbid_le`.
//! - `keys_id = HKDF-SHA256(ikm = channels_seed, salt = channel_id, info = "per-peer seed")`.
//! - The channel keys are 192 bytes of `HKDF-SHA256(ikm = keys_id, salt = "",
//!   info = "c-lightning")`: funding, revocation base, htlc base, payment,
//!   delayed payment base, commitment seed.
//!
//! vlsd uses the payment key as the payment basepoint with static remote
//! keys, so a counterparty force close pays our balance to
//! `P2WPKH(payment_point)`, or for anchor channels to the P2WSH of
//! `<payment_point> OP_CHECKSIGVERIFY 1 OP_CSV`.
//!
//! References in zeus-vls: `vls-core/src/signer/derive.rs` (`NativeKeyDerive`),
//! `vls-core/src/util/crypto_utils.rs` (`hkdf_sha256`), and the parity
//! vectors in `lnrod/src/signer/seed.rs` (zeus-vls #268, #270).

use bitcoin::bip32::Xpriv;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Network, ScriptBuf};

use bip39::Mnemonic;

use lightning::ln::chan_utils::get_countersigner_payment_script;
use lightning::types::features::ChannelTypeFeatures;

use crate::Error;

/// vlsd only creates and restores 24-word mnemonics.
pub(crate) const ROUTE_MNEMONIC_WORDS: usize = 24;

/// How many channel dbids to scan when the caller does not say. Each dbid
/// is two scripts, so this matches the 2,000 scripts of the static payment
/// key scan.
pub(crate) const ROUTE_DEFAULT_MAX_DBID: u32 = 1000;

/// The peer id lnrod's vlsd client sends in every `NewChannel`.
const NEW_CHANNEL_PEER_ID: [u8; 33] = [0u8; 33];

fn hkdf_extract_expand(salt: &[u8], secret: &[u8], info: &[u8], output: &mut [u8]) {
	let mut hmac = HmacEngine::<Sha256>::new(salt);
	hmac.input(secret);
	let prk = Hmac::from_engine(hmac).to_byte_array();

	let mut t = [0u8; 32];
	let mut n: u8 = 0;
	for chunk in output.chunks_mut(32) {
		let mut hmac = HmacEngine::<Sha256>::new(&prk[..]);
		n = n.checked_add(1).expect("HKDF size limit exceeded");
		if n != 1 {
			hmac.input(&t);
		}
		hmac.input(info);
		hmac.input(&[n]);
		t = Hmac::from_engine(hmac).to_byte_array();
		chunk.copy_from_slice(&t);
	}
}

fn hkdf_sha256(secret: &[u8], info: &[u8], salt: &[u8]) -> [u8; 32] {
	let mut out = [0u8; 32];
	hkdf_extract_expand(salt, secret, info, &mut out);
	out
}

/// The 32-byte seed vlsd builds its node from, given the customer's
/// 24-word Route mnemonic.
pub(crate) fn route_ldk_seed(mnemonic: &Mnemonic) -> Result<[u8; 32], Error> {
	if mnemonic.word_count() != ROUTE_MNEMONIC_WORDS {
		return Err(Error::InvalidSecretKey);
	}
	let bip39_seed = mnemonic.to_seed("");
	// The network only changes how an xpriv is serialized, not its key.
	let master =
		Xpriv::new_master(Network::Bitcoin, &bip39_seed).map_err(|_| Error::InvalidSecretKey)?;
	Ok(master.private_key.secret_bytes())
}

/// One Route channel's secrets, in VLS order.
pub(crate) struct RouteChannelKeys {
	pub(crate) funding_key: SecretKey,
	pub(crate) revocation_base_key: SecretKey,
	pub(crate) htlc_base_key: SecretKey,
	pub(crate) payment_key: SecretKey,
	pub(crate) delayed_payment_base_key: SecretKey,
}

/// The keys vlsd derives for lnrod's channel number `dbid`.
pub(crate) fn route_channel_keys(ldk_seed: &[u8; 32], dbid: u64) -> RouteChannelKeys {
	let channels_seed = hkdf_sha256(ldk_seed, b"peer seed", &[]);
	let mut channel_id = [0u8; 33 + 8];
	channel_id[..33].copy_from_slice(&NEW_CHANNEL_PEER_ID);
	channel_id[33..].copy_from_slice(&dbid.to_le_bytes());
	let keys_id = hkdf_sha256(&channels_seed, b"per-peer seed", &channel_id);

	let mut buf = [0u8; 32 * 6];
	hkdf_extract_expand(&[], &keys_id, b"c-lightning", &mut buf);
	// HKDF output is a valid secret key except with negligible probability;
	// vls-core unwraps the same way.
	let key = |i: usize| SecretKey::from_slice(&buf[i * 32..(i + 1) * 32]).expect("valid key");
	RouteChannelKeys {
		funding_key: key(0),
		revocation_base_key: key(1),
		htlc_base_key: key(2),
		payment_key: key(3),
		delayed_payment_base_key: key(4),
	}
}

/// The scripts a counterparty force close of Route channels 1..=max_dbid
/// pays our balance to, each with the key that spends it: P2WPKH for
/// static_remotekey channels and the P2WSH `to_remote` of anchor channels.
pub(crate) fn route_counterparty_closed_spks_with_keys(
	ldk_seed: &[u8; 32], max_dbid: u32,
) -> Vec<(ScriptBuf, SecretKey)> {
	let secp = Secp256k1::new();
	let static_remote_key = ChannelTypeFeatures::only_static_remote_key();
	let mut anchors = ChannelTypeFeatures::only_static_remote_key();
	anchors.set_anchors_zero_fee_htlc_tx_required();

	let mut res = Vec::with_capacity(max_dbid as usize * 2);
	for dbid in 1..=u64::from(max_dbid) {
		let key = route_channel_keys(ldk_seed, dbid).payment_key;
		let point = PublicKey::from_secret_key(&secp, &key);
		res.push((get_countersigner_payment_script(&static_remote_key, &point), key));
		res.push((get_countersigner_payment_script(&anchors, &point), key));
	}
	res
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::hashes::hash160;
	use lightning::ln::chan_utils::get_to_countersigner_keyed_anchor_redeemscript;
	use std::str::FromStr;

	const ALL_ZERO_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon \
		abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
		abandon abandon abandon abandon abandon abandon art";

	/// zeus-vls `lnrod/src/signer/seed.rs` (from `vlsd/src/onboarding.rs`,
	/// zeus-vls #270): the runtime vlsd node_id for the all-zero mnemonic.
	const RUNTIME_NODE_ID_HEX: &str =
		"03b61582f9e910d03139565051dbf4959d4b84b2a5a2a79c3c04f90ed2b7eb254c";

	/// The same source: runtime vlsd holder basepoints for dbid 1..=3, in
	/// the order funding, revocation, payment, delayed_payment, htlc.
	const RUNTIME_CHANNEL_BASEPOINTS_HEX: [[&str; 5]; 3] = [
		[
			"03467cd80ed830c382c85843df11c79cf6fc1f3f04f18c0fadbfff548c7a72fcb8",
			"0372b31ffcb5c2c3161056b5dc8f52edc3d5eb6905bc8e7b34cf72366946030f66",
			"02baae644b7075197f84eaaf70ea4be40b2da1cdb2f7bf63c72e2b669fc7de7b3c",
			"02dd49dc54de505c0677b592b7b45479fd9df8dc45179e91ad39146c2235c76539",
			"035c731b1f3a9adee5e680d778f2951c50d3c11313558e112e81bd108b7fa3395f",
		],
		[
			"038eeaa02f65c8a144e22d73f5fce2e362bdb21bf051a039821f46b7acd74870da",
			"023987b2eca479ea0ffc1e6a430440416694c2f39de1efe3876c3ba165acf750ce",
			"02c265c6b77844c98c8206a0a163559866c14f93a292885cedabc56cf7fa038a05",
			"03609132ade15a27d5e5db8f24de9f338fc70499392e2a879d0c39ad315120595b",
			"03f4bf1d11e897f5ae9e779f249012149211ac8b95a5250a16cfd9a0e98672c990",
		],
		[
			"0242fda2e1a50843f240b37661f91f881e361919e03b00c1aa3f722a619e1b249c",
			"02d610fe592bd386a697074efb5b5b681d67640dde90e934adb95a6520e474de29",
			"0345151c0f0040dd3c6996a31917338b0805db4989dba8d91d6154a732b67b98d2",
			"034ee1a8e6bf47bf1a3ee1bc2e3fb6f38e0226e7f831f37f566bba2c6c9eeab709",
			"0358ce40c9699851160715c8b3d7706a24bc95cab2cd4bcf5eb16290fbab7b6c99",
		],
	];

	fn seed() -> [u8; 32] {
		route_ldk_seed(&Mnemonic::from_str(ALL_ZERO_MNEMONIC).unwrap()).unwrap()
	}

	fn hex(key: &SecretKey) -> String {
		let pk = PublicKey::from_secret_key(&Secp256k1::new(), key);
		pk.serialize().iter().map(|b| format!("{:02x}", b)).collect()
	}

	#[test]
	fn node_id_matches_runtime_vlsd() {
		// Native node key: HKDF(ldk_seed, "nodeid"). Pins ldk_seed itself.
		let node_secret = SecretKey::from_slice(&hkdf_sha256(&seed(), b"nodeid", &[])).unwrap();
		assert_eq!(hex(&node_secret), RUNTIME_NODE_ID_HEX);
	}

	#[test]
	fn channel_basepoints_match_runtime_vlsd() {
		let seed = seed();
		for (i, expected) in RUNTIME_CHANNEL_BASEPOINTS_HEX.iter().enumerate() {
			let k = route_channel_keys(&seed, i as u64 + 1);
			let got = [
				hex(&k.funding_key),
				hex(&k.revocation_base_key),
				hex(&k.payment_key),
				hex(&k.delayed_payment_base_key),
				hex(&k.htlc_base_key),
			];
			assert_eq!(got, expected.map(String::from), "dbid {}", i + 1);
		}
	}

	#[test]
	fn scripts_cover_both_channel_types_for_each_dbid() {
		let seed = seed();
		let spks = route_counterparty_closed_spks_with_keys(&seed, 3);
		assert_eq!(spks.len(), 6);
		let secp = Secp256k1::new();
		for dbid in 1..=3u64 {
			let key = route_channel_keys(&seed, dbid).payment_key;
			let point = PublicKey::from_secret_key(&secp, &key);
			let wpkh = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_raw_hash(
				hash160::Hash::hash(&point.serialize()),
			));
			let anchor = get_to_countersigner_keyed_anchor_redeemscript(&point).to_p2wsh();
			let idx = (dbid as usize - 1) * 2;
			assert_eq!(spks[idx], (wpkh, key));
			assert_eq!(spks[idx + 1], (anchor, key));
		}
		// dbid 0 is never allocated (lnrod's counter starts at 1).
		let dbid0 = route_channel_keys(&seed, 0).payment_key;
		assert!(spks.iter().all(|(_, k)| *k != dbid0));
	}

	#[test]
	fn anchor_script_requires_one_block_csv() {
		let key = route_channel_keys(&seed(), 1).payment_key;
		let point = PublicKey::from_secret_key(&Secp256k1::new(), &key);
		let script = get_to_countersigner_keyed_anchor_redeemscript(&point);
		let asm = script.to_asm_string();
		assert!(asm.ends_with("OP_CHECKSIGVERIFY OP_PUSHNUM_1 OP_CSV"), "{asm}");
	}

	#[test]
	fn rejects_a_12_word_mnemonic() {
		let twelve = Mnemonic::from_str(
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon \
			 abandon abandon about",
		)
		.unwrap();
		assert!(matches!(route_ldk_seed(&twelve), Err(Error::InvalidSecretKey)));
	}
}

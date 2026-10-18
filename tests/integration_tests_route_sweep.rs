// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these choices.

//! `sweep_route_remote_closed_outputs` against a regtest chain: funds sit on the
//! scripts a counterparty force close of ZEUS Route channels pays to, and the
//! node sweeps them knowing only the Route mnemonic.
//!
//! There is no vlsd here, so the outputs are funded directly rather than by a
//! real force close. The scripts come from vlsd's runtime payment basepoints
//! for the all-zero mnemonic (zeus-vls `lnrod/src/signer/seed.rs`, #270), so
//! the test pins the scripts vlsd's channels use, not the derivation in this
//! crate.

mod common;

use std::str::FromStr;

use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Address, Amount, CompressedPublicKey, Network, Transaction};
use common::{
	distribute_funds_unconfirmed, generate_blocks_and_wait, premine_blocks, random_config,
	setup_bitcoind_and_electrsd, setup_node, wait_for_tx, TestChainSource,
};
use ldk_node::bip39::Mnemonic;
use ldk_node::NodeError;
use lightning::ln::chan_utils::get_to_countersigner_keyed_anchor_redeemscript;

const ALL_ZERO_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon \
	abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
	abandon abandon abandon abandon abandon abandon art";

/// vlsd's runtime payment basepoints for the all-zero mnemonic.
const DBID1_PAYMENT_POINT: &str =
	"02baae644b7075197f84eaaf70ea4be40b2da1cdb2f7bf63c72e2b669fc7de7b3c";
const DBID3_PAYMENT_POINT: &str =
	"0345151c0f0040dd3c6996a31917338b0805db4989dba8d91d6154a732b67b98d2";

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn route_remote_closed_outputs_are_swept_with_the_mnemonic_only() {
	let (bitcoind, electrsd) = setup_bitcoind_and_electrsd();
	let chain_source = TestChainSource::Esplora(&electrsd);
	// The node's own seed is unrelated to the Route mnemonic.
	let node = setup_node(&chain_source, random_config(true));

	premine_blocks(&bitcoind.client, &electrsd.client).await;

	// dbid 1 as a static_remotekey channel (P2WPKH), dbid 3 as an anchor
	// channel (P2WSH of `<point> OP_CHECKSIGVERIFY 1 OP_CSV`).
	let point1 = PublicKey::from_str(DBID1_PAYMENT_POINT).unwrap();
	let point3 = PublicKey::from_str(DBID3_PAYMENT_POINT).unwrap();
	let wpkh_addr = Address::p2wpkh(&CompressedPublicKey(point1), Network::Regtest);
	let anchor_addr =
		Address::p2wsh(&get_to_countersigner_keyed_anchor_redeemscript(&point3), Network::Regtest);
	let amount = Amount::from_sat(150_000);
	distribute_funds_unconfirmed(
		&bitcoind.client,
		&electrsd.client,
		vec![wpkh_addr, anchor_addr],
		amount,
	)
	.await;
	// The anchor output needs one confirmation (1 OP_CSV).
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 6).await;

	let sweep_addr = bitcoind.client.new_address().unwrap();
	let mnemonic = Mnemonic::from_str(ALL_ZERO_MNEMONIC).unwrap();

	// Bounded scan: dbid 3 is past the bound, so only dbid 1 is found.
	let hex = node
		.sweep_route_remote_closed_outputs(mnemonic.clone(), &sweep_addr.to_string(), 2, 0, Some(2))
		.unwrap();
	let tx: Transaction = deserialize_hex(&hex).unwrap();
	assert_eq!(tx.input.len(), 1);

	// Full scan finds both outputs and the transaction is valid on chain.
	let hex = node
		.sweep_route_remote_closed_outputs(mnemonic.clone(), &sweep_addr.to_string(), 2, 0, Some(3))
		.unwrap();
	let tx: Transaction = deserialize_hex(&hex).unwrap();
	assert_eq!(tx.input.len(), 2);
	assert_eq!(tx.output.len(), 1);
	assert_eq!(tx.output[0].script_pubkey, sweep_addr.script_pubkey());
	let fee = amount * 2 - tx.output[0].value;
	assert!(fee > Amount::ZERO && fee < Amount::from_sat(2_000), "fee {fee}");
	assert!(tx.input.iter().all(|i| i.sequence.0 == 1));

	let txid: bitcoin::Txid = bitcoind.client.send_raw_transaction(&tx).unwrap().0.parse().unwrap();
	assert_eq!(txid, tx.compute_txid());
	generate_blocks_and_wait(&bitcoind.client, &electrsd.client, 1).await;
	wait_for_tx(&electrsd.client, txid).await;

	// Swept outputs are gone, so a second run finds nothing.
	let res =
		node.sweep_route_remote_closed_outputs(mnemonic, &sweep_addr.to_string(), 2, 0, Some(3));
	assert_eq!(res, Err(NodeError::InsufficientFunds));

	// vlsd only uses 24-word mnemonics.
	let twelve = Mnemonic::from_str(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon \
		 abandon abandon about",
	)
	.unwrap();
	let res =
		node.sweep_route_remote_closed_outputs(twelve, &sweep_addr.to_string(), 2, 0, Some(3));
	assert_eq!(res, Err(NodeError::InvalidSecretKey));

	// The node's own static payment key scan still runs and finds nothing.
	let res = node.sweep_remote_closed_outputs(&sweep_addr.to_string(), 2, 0);
	assert_eq!(res, Err(NodeError::InsufficientFunds));

	node.stop().unwrap();
}

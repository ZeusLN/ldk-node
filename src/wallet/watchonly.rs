// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::sync::Mutex;

use bdk_wallet::{KeychainKind, Wallet as BdkWallet};
use bitcoin::{Address, Network};

use crate::Error;

/// A watch-only on-chain wallet built from public descriptors; it holds no
/// private keys and so can derive addresses and observe funds, but cannot sign.
pub(crate) struct WatchOnlyWallet {
	inner: Mutex<BdkWallet>,
}

impl WatchOnlyWallet {
	pub(crate) fn import(
		external_descriptor: String, internal_descriptor: String, network: Network,
	) -> Result<Self, Error> {
		let wallet = BdkWallet::create(external_descriptor, internal_descriptor)
			.network(network)
			.create_wallet_no_persist()
			.map_err(|_| Error::WalletOperationFailed)?;

		Ok(Self { inner: Mutex::new(wallet) })
	}

	pub(crate) fn new_address(&self) -> Result<Address, Error> {
		let mut locked_wallet = self.inner.lock().unwrap();
		let address_info = locked_wallet.reveal_next_address(KeychainKind::External);
		Ok(address_info.address)
	}

	pub(crate) fn balance(&self) -> u64 {
		self.inner.lock().unwrap().balance().total().to_sat()
	}

	pub(crate) fn list_utxos(&self) -> Result<Vec<crate::WalletUtxo>, Error> {
		let locked_wallet = self.inner.lock().unwrap();
		let network = locked_wallet.network();
		let mut result = Vec::new();

		for utxo in locked_wallet.list_unspent() {
			let address = Address::from_script(&utxo.txout.script_pubkey, network)
				.map(|a| a.to_string())
				.unwrap_or_default();
			result.push(crate::WalletUtxo {
				txid: utxo.outpoint.txid.to_string(),
				vout: utxo.outpoint.vout,
				value_sats: utxo.txout.value.to_sat(),
				address,
				is_spent: utxo.is_spent,
			});
		}

		Ok(result)
	}

	pub(crate) fn list_addresses(&self) -> Vec<Address> {
		let locked_wallet = self.inner.lock().unwrap();
		let last_revealed = match locked_wallet.derivation_index(KeychainKind::External) {
			Some(index) => index,
			None => return Vec::new(),
		};

		(0..=last_revealed)
			.map(|index| locked_wallet.peek_address(KeychainKind::External, index).address)
			.collect()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	// A known BIP84 testnet account (fingerprint 2de67592); its first external
	// (0/0) address is asserted below.
	const EXTERNAL_DESCRIPTOR: &str = "wpkh([2de67592/84'/1'/0']tpubDCUJWjpCfXoCzDwWiHRwsALSWYSMXvHHzQ3q4CoiVgWAHcrvL2C89PUs1wC2QddbaDEvLNaL5PFVFdYm5oBf7DXZWoFK8X4PLXAUA8L9zsV/0/*)";
	const INTERNAL_DESCRIPTOR: &str = "wpkh([2de67592/84'/1'/0']tpubDCUJWjpCfXoCzDwWiHRwsALSWYSMXvHHzQ3q4CoiVgWAHcrvL2C89PUs1wC2QddbaDEvLNaL5PFVFdYm5oBf7DXZWoFK8X4PLXAUA8L9zsV/1/*)";

	#[test]
	fn import_and_derive_first_external_address() {
		let wallet = WatchOnlyWallet::import(
			EXTERNAL_DESCRIPTOR.to_string(),
			INTERNAL_DESCRIPTOR.to_string(),
			Network::Testnet,
		)
		.unwrap();

		let address = wallet.new_address().unwrap();

		assert_eq!(address.to_string(), "tb1q7whne2rauhqkg7pe8dpra6rs5cxgq0429pxn88");
	}

	#[test]
	fn fresh_account_has_zero_balance() {
		let wallet = WatchOnlyWallet::import(
			EXTERNAL_DESCRIPTOR.to_string(),
			INTERNAL_DESCRIPTOR.to_string(),
			Network::Testnet,
		)
		.unwrap();

		assert_eq!(wallet.balance(), 0);
	}

	#[test]
	fn fresh_account_has_no_utxos() {
		let wallet = WatchOnlyWallet::import(
			EXTERNAL_DESCRIPTOR.to_string(),
			INTERNAL_DESCRIPTOR.to_string(),
			Network::Testnet,
		)
		.unwrap();

		assert!(wallet.list_utxos().unwrap().is_empty());
	}

	#[test]
	fn lists_revealed_addresses() {
		let wallet = WatchOnlyWallet::import(
			EXTERNAL_DESCRIPTOR.to_string(),
			INTERNAL_DESCRIPTOR.to_string(),
			Network::Testnet,
		)
		.unwrap();

		assert!(wallet.list_addresses().is_empty());

		let first = wallet.new_address().unwrap();
		let second = wallet.new_address().unwrap();

		assert_eq!(wallet.list_addresses(), vec![first, second]);
	}
}

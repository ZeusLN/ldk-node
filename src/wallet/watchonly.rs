// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::sync::{Arc, Mutex};

use bdk_chain::spk_client::FullScanRequest;
use bdk_wallet::{KeychainKind, PersistedWallet, Update, Wallet as BdkWallet};
use bitcoin::{Address, Network};

use crate::logger::{log_error, LdkLogger, Logger};
use crate::types::DynStore;
use crate::wallet::persist::KVStoreWalletPersister;
use crate::Error;

/// A watch-only on-chain wallet built from public descriptors; it holds no
/// private keys and so can derive addresses and observe funds, but cannot sign.
///
/// Its state is persisted under the wallet's own KVStore secondary namespace,
/// keeping it separate from the node's wallet and from other imported accounts.
pub(crate) struct WatchOnlyWallet {
	inner: Mutex<PersistedWallet<KVStoreWalletPersister>>,
	persister: Mutex<KVStoreWalletPersister>,
	logger: Arc<Logger>,
}

impl WatchOnlyWallet {
	pub(crate) fn import(
		external_descriptor: String, internal_descriptor: String, network: Network,
		kv_store: Arc<DynStore>, secondary_namespace: String, logger: Arc<Logger>,
	) -> Result<Self, Error> {
		let mut persister =
			KVStoreWalletPersister::new(kv_store, secondary_namespace, Arc::clone(&logger));
		let wallet = BdkWallet::create(external_descriptor, internal_descriptor)
			.network(network)
			.create_wallet(&mut persister)
			.map_err(|e| {
				log_error!(logger, "Failed to import watch-only wallet: {}", e);
				Error::WalletOperationFailed
			})?;

		Ok(Self { inner: Mutex::new(wallet), persister: Mutex::new(persister), logger })
	}

	pub(crate) fn new_address(&self) -> Result<Address, Error> {
		let mut locked_wallet = self.inner.lock().unwrap();
		let mut locked_persister = self.persister.lock().unwrap();

		let address_info = locked_wallet.reveal_next_address(KeychainKind::External);
		locked_wallet.persist(&mut locked_persister).map_err(|e| {
			log_error!(self.logger, "Failed to persist watch-only wallet: {}", e);
			Error::PersistenceFailed
		})?;
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

	pub(crate) fn get_full_scan_request(&self) -> FullScanRequest<KeychainKind> {
		self.inner.lock().unwrap().start_full_scan().build()
	}

	pub(crate) fn apply_update(&self, update: impl Into<Update>) -> Result<(), Error> {
		let mut locked_wallet = self.inner.lock().unwrap();
		locked_wallet.apply_update(update).map_err(|e| {
			log_error!(self.logger, "Failed to apply update to watch-only wallet: {}", e);
			Error::WalletOperationFailed
		})?;

		let mut locked_persister = self.persister.lock().unwrap();
		locked_wallet.persist(&mut locked_persister).map_err(|e| {
			log_error!(self.logger, "Failed to persist watch-only wallet: {}", e);
			Error::PersistenceFailed
		})?;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use lightning::util::persist::KVStoreSync;

	use super::*;
	use crate::io::test_utils::InMemoryStore;
	use crate::io::{BDK_WALLET_DESCRIPTOR_KEY, BDK_WALLET_DESCRIPTOR_PRIMARY_NAMESPACE};
	use crate::types::DynStoreWrapper;

	// A known BIP84 testnet account (fingerprint 2de67592); its first external
	// (0/0) address is asserted below.
	const EXTERNAL_DESCRIPTOR: &str = "wpkh([2de67592/84'/1'/0']tpubDCUJWjpCfXoCzDwWiHRwsALSWYSMXvHHzQ3q4CoiVgWAHcrvL2C89PUs1wC2QddbaDEvLNaL5PFVFdYm5oBf7DXZWoFK8X4PLXAUA8L9zsV/0/*)";
	const INTERNAL_DESCRIPTOR: &str = "wpkh([2de67592/84'/1'/0']tpubDCUJWjpCfXoCzDwWiHRwsALSWYSMXvHHzQ3q4CoiVgWAHcrvL2C89PUs1wC2QddbaDEvLNaL5PFVFdYm5oBf7DXZWoFK8X4PLXAUA8L9zsV/1/*)";
	const TEST_NAMESPACE: &str = "testaccount";

	fn test_store() -> Arc<DynStore> {
		Arc::new(DynStoreWrapper(InMemoryStore::new()))
	}

	fn import_test_wallet(store: Arc<DynStore>) -> Result<WatchOnlyWallet, Error> {
		WatchOnlyWallet::import(
			EXTERNAL_DESCRIPTOR.to_string(),
			INTERNAL_DESCRIPTOR.to_string(),
			Network::Testnet,
			store,
			TEST_NAMESPACE.to_string(),
			Arc::new(Logger::new_log_facade()),
		)
	}

	#[test]
	fn import_and_derive_first_external_address() {
		let wallet = import_test_wallet(test_store()).unwrap();

		let address = wallet.new_address().unwrap();

		assert_eq!(address.to_string(), "tb1q7whne2rauhqkg7pe8dpra6rs5cxgq0429pxn88");
	}

	#[test]
	fn fresh_account_has_zero_balance() {
		let wallet = import_test_wallet(test_store()).unwrap();

		assert_eq!(wallet.balance(), 0);
	}

	#[test]
	fn fresh_account_has_no_utxos() {
		let wallet = import_test_wallet(test_store()).unwrap();

		assert!(wallet.list_utxos().unwrap().is_empty());
	}

	#[test]
	fn lists_revealed_addresses() {
		let wallet = import_test_wallet(test_store()).unwrap();

		assert!(wallet.list_addresses().is_empty());

		let first = wallet.new_address().unwrap();
		let second = wallet.new_address().unwrap();

		assert_eq!(wallet.list_addresses(), vec![first, second]);
	}

	#[test]
	fn import_persists_under_own_namespace() {
		let store = test_store();
		let _wallet = import_test_wallet(Arc::clone(&store)).unwrap();

		assert!(KVStoreSync::read(
			&*store,
			BDK_WALLET_DESCRIPTOR_PRIMARY_NAMESPACE,
			TEST_NAMESPACE,
			BDK_WALLET_DESCRIPTOR_KEY,
		)
		.is_ok());
		// The node wallet's (empty) namespace must remain untouched.
		assert!(KVStoreSync::read(
			&*store,
			BDK_WALLET_DESCRIPTOR_PRIMARY_NAMESPACE,
			"",
			BDK_WALLET_DESCRIPTOR_KEY,
		)
		.is_err());
	}

	#[test]
	fn reimport_into_existing_namespace_fails() {
		let store = test_store();
		let _wallet = import_test_wallet(Arc::clone(&store)).unwrap();

		assert!(import_test_wallet(store).is_err());
	}
}

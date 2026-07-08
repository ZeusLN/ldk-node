// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::sync::{Arc, Mutex};

use bdk_chain::spk_client::FullScanRequest;
use bdk_wallet::{KeychainKind, PersistedWallet, Update, Wallet as BdkWallet};
use bitcoin::psbt::Psbt;
use bitcoin::{Address, Amount, FeeRate, Network, OutPoint};

use crate::logger::{log_error, LdkLogger, Logger};
use crate::types::DynStore;
use crate::wallet::persist::KVStoreWalletPersister;
use crate::Error;

/// The maximum number of addresses returned per keychain by a watch-only
/// account preview.
const PREVIEW_MAX_ADDRESSES: u8 = 20;

/// A single output of a watch-only spend: an address to pay and the amount, in
/// satoshis, to send to it.
#[derive(Debug, Clone)]
pub struct PsbtRecipient {
	/// The address to pay.
	pub address: Address,
	/// The amount to send, in satoshis.
	pub amount_sats: u64,
}

/// The first addresses of each keychain derived from a pair of public
/// descriptors, allowing an account to be verified against the originating
/// wallet before it is imported.
#[derive(Debug, Clone)]
pub struct WatchonlyAccountPreview {
	/// The first external (receive) addresses.
	pub external_addresses: Vec<Address>,
	/// The first internal (change) addresses.
	pub internal_addresses: Vec<Address>,
}

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

	/// Derives the first `count` addresses of each keychain from the given
	/// descriptors without persisting or revealing anything.
	pub(crate) fn preview(
		external_descriptor: String, internal_descriptor: String, network: Network, count: u8,
		logger: Arc<Logger>,
	) -> Result<WatchonlyAccountPreview, Error> {
		let wallet = BdkWallet::create(external_descriptor, internal_descriptor)
			.network(network)
			.create_wallet_no_persist()
			.map_err(|e| {
				log_error!(logger, "Failed to preview watch-only account: {}", e);
				Error::WalletOperationFailed
			})?;

		let count = count.clamp(1, PREVIEW_MAX_ADDRESSES) as u32;
		let external_addresses =
			(0..count).map(|i| wallet.peek_address(KeychainKind::External, i).address).collect();
		let internal_addresses =
			(0..count).map(|i| wallet.peek_address(KeychainKind::Internal, i).address).collect();

		Ok(WatchonlyAccountPreview { external_addresses, internal_addresses })
	}

	/// Loads a previously imported wallet from its persisted state, returning
	/// `None` if nothing is persisted under `secondary_namespace`.
	pub(crate) fn load(
		network: Network, kv_store: Arc<DynStore>, secondary_namespace: String, logger: Arc<Logger>,
	) -> Result<Option<Self>, Error> {
		let mut persister =
			KVStoreWalletPersister::new(kv_store, secondary_namespace, Arc::clone(&logger));
		let wallet_opt =
			BdkWallet::load().check_network(network).load_wallet(&mut persister).map_err(|e| {
				log_error!(logger, "Failed to load watch-only wallet: {}", e);
				Error::WalletOperationFailed
			})?;

		Ok(wallet_opt.map(|wallet| Self {
			inner: Mutex::new(wallet),
			persister: Mutex::new(persister),
			logger,
		}))
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

	/// Builds an unsigned PSBT spending from this account to the given
	/// recipients, ready to be signed on an external (hardware) device.
	///
	/// The PSBT carries the metadata a signer needs to identify and verify its
	/// own inputs and change: the account's global xpubs, and — populated by
	/// BDK from the account descriptors — each input's previous output (both the
	/// witness UTXO and the full previous transaction) and the per-input and
	/// per-output BIP 32 key derivations. It is returned unsigned, as a
	/// watch-only wallet holds no private keys.
	///
	/// If `utxos` is empty the wallet selects inputs itself; otherwise exactly
	/// the given outpoints are spent. All recipient addresses must belong to the
	/// account's network.
	pub(crate) fn create_psbt(
		&self, recipients: Vec<PsbtRecipient>, utxos: Vec<OutPoint>, fee_rate: FeeRate,
	) -> Result<Psbt, Error> {
		let mut locked_wallet = self.inner.lock().unwrap();
		let network = locked_wallet.network();

		for recipient in &recipients {
			if !recipient.address.as_unchecked().is_valid_for_network(network) {
				log_error!(
					self.logger,
					"Watch-only recipient address {} is not valid for network {}",
					recipient.address,
					network
				);
				return Err(Error::InvalidAddress);
			}
		}

		let mut tx_builder = locked_wallet.build_tx();
		for recipient in &recipients {
			tx_builder.add_recipient(
				recipient.address.script_pubkey(),
				Amount::from_sat(recipient.amount_sats),
			);
		}
		tx_builder.fee_rate(fee_rate);

		// Add the account's extended public keys to the PSBT so an external
		// signer can recognize the account as its own.
		tx_builder.add_global_xpubs();

		// An empty selection lets BDK choose the inputs; a non-empty one pins the
		// spend to exactly those outpoints.
		if !utxos.is_empty() {
			for outpoint in &utxos {
				tx_builder.add_utxo(*outpoint).map_err(|e| {
					log_error!(self.logger, "Failed to add watch-only UTXO {}: {}", outpoint, e);
					Error::OnchainTxCreationFailed
				})?;
			}
			tx_builder.manually_selected_only();
		}

		let psbt = tx_builder.finish().map_err(|e| {
			log_error!(self.logger, "Failed to build watch-only PSBT: {}", e);
			Error::from(e)
		})?;

		// `finish` reveals the next change address; persist so its index is not
		// reused on the next spend.
		let mut locked_persister = self.persister.lock().unwrap();
		locked_wallet.persist(&mut locked_persister).map_err(|e| {
			log_error!(self.logger, "Failed to persist watch-only wallet: {}", e);
			Error::PersistenceFailed
		})?;

		Ok(psbt)
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

	/// Runs `f` against the inner BDK wallet, used by tests to seed chain and
	/// UTXO state that a live wallet would obtain from an Esplora scan.
	#[cfg(test)]
	fn with_inner_mut<R>(&self, f: impl FnOnce(&mut BdkWallet) -> R) -> R {
		f(&mut self.inner.lock().unwrap())
	}
}

#[cfg(test)]
mod tests {
	use std::str::FromStr;

	use bdk_chain::BlockId;
	use bdk_wallet::test_utils::{insert_checkpoint, receive_output_in_latest_block};
	use bitcoin::hashes::Hash;
	use bitcoin::BlockHash;
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
	// The account's master fingerprint, as it appears in the descriptors above.
	const MASTER_FINGERPRINT: &str = "2de67592";
	// A testnet address outside the account, used as a spend recipient.
	const RECIPIENT_ADDRESS: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

	fn test_store() -> Arc<DynStore> {
		Arc::new(DynStoreWrapper(InMemoryStore::new()))
	}

	fn testnet_fee_rate() -> FeeRate {
		FeeRate::from_sat_per_vb(2).unwrap()
	}

	fn recipient(amount_sats: u64) -> PsbtRecipient {
		let address = Address::from_str(RECIPIENT_ADDRESS).unwrap().assume_checked();
		PsbtRecipient { address, amount_sats }
	}

	// Funds the account with a single confirmed UTXO of `amount_sats`, mimicking
	// what an Esplora scan would apply. Returns the funding outpoint.
	fn fund_account(wallet: &WatchOnlyWallet, amount_sats: u64) -> OutPoint {
		wallet.with_inner_mut(|w| {
			// `receive_output_in_latest_block` requires a non-genesis tip.
			insert_checkpoint(w, BlockId { height: 1_000, hash: BlockHash::all_zeros() });
			receive_output_in_latest_block(w, Amount::from_sat(amount_sats))
		})
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

	fn preview_test_account(count: u8) -> WatchonlyAccountPreview {
		WatchOnlyWallet::preview(
			EXTERNAL_DESCRIPTOR.to_string(),
			INTERNAL_DESCRIPTOR.to_string(),
			Network::Testnet,
			count,
			Arc::new(Logger::new_log_facade()),
		)
		.unwrap()
	}

	#[test]
	fn preview_derives_known_addresses() {
		let preview = preview_test_account(5);

		assert_eq!(preview.external_addresses.len(), 5);
		assert_eq!(preview.internal_addresses.len(), 5);
		assert_eq!(
			preview.external_addresses[0].to_string(),
			"tb1q7whne2rauhqkg7pe8dpra6rs5cxgq0429pxn88"
		);
		assert_ne!(preview.external_addresses[0], preview.internal_addresses[0]);
	}

	#[test]
	fn preview_clamps_address_count() {
		assert_eq!(preview_test_account(0).external_addresses.len(), 1);
		assert_eq!(preview_test_account(255).external_addresses.len(), 20);
	}

	#[test]
	fn preview_matches_imported_account_addresses() {
		let preview = preview_test_account(2);
		let wallet = import_test_wallet(test_store()).unwrap();

		assert_eq!(wallet.new_address().unwrap(), preview.external_addresses[0]);
		assert_eq!(wallet.new_address().unwrap(), preview.external_addresses[1]);
	}

	#[test]
	fn load_without_persisted_state_returns_none() {
		let loaded = WatchOnlyWallet::load(
			Network::Testnet,
			test_store(),
			TEST_NAMESPACE.to_string(),
			Arc::new(Logger::new_log_facade()),
		)
		.unwrap();

		assert!(loaded.is_none());
	}

	#[test]
	fn persisted_account_survives_reload() {
		let store = test_store();

		let (first, second) = {
			let wallet = import_test_wallet(Arc::clone(&store)).unwrap();
			(wallet.new_address().unwrap(), wallet.new_address().unwrap())
		};

		let reloaded = WatchOnlyWallet::load(
			Network::Testnet,
			store,
			TEST_NAMESPACE.to_string(),
			Arc::new(Logger::new_log_facade()),
		)
		.unwrap()
		.unwrap();

		assert_eq!(reloaded.list_addresses(), vec![first.clone(), second.clone()]);

		// Address derivation must continue where it left off, not restart at index 0.
		let third = reloaded.new_address().unwrap();
		assert_ne!(third, first);
		assert_ne!(third, second);
	}

	#[test]
	fn create_psbt_is_unsigned_and_pays_recipient() {
		let wallet = import_test_wallet(test_store()).unwrap();
		fund_account(&wallet, 100_000);

		let psbt = wallet.create_psbt(vec![recipient(50_000)], vec![], testnet_fee_rate()).unwrap();

		// The recipient output must be present at its requested value.
		let recipient_spk = recipient(0).address.script_pubkey();
		let paid = psbt
			.unsigned_tx
			.output
			.iter()
			.find(|o| o.script_pubkey == recipient_spk)
			.expect("recipient output missing");
		assert_eq!(paid.value, Amount::from_sat(50_000));

		// A watch-only wallet cannot sign: no input may carry a signature or a
		// finalized witness/script.
		for input in &psbt.inputs {
			assert!(input.partial_sigs.is_empty());
			assert!(input.final_script_sig.is_none());
			assert!(input.final_script_witness.is_none());
		}
	}

	#[test]
	fn create_psbt_carries_hardware_signing_metadata() {
		let wallet = import_test_wallet(test_store()).unwrap();
		fund_account(&wallet, 100_000);

		let psbt = wallet.create_psbt(vec![recipient(50_000)], vec![], testnet_fee_rate()).unwrap();

		// The account's global xpub lets an external signer recognize the account.
		assert!(!psbt.xpub.is_empty());
		let (fingerprint, _path) = psbt.xpub.values().next().unwrap();
		assert_eq!(fingerprint.to_string(), MASTER_FINGERPRINT);

		// Each input must let the signer verify amounts and identify its key:
		// the witness UTXO, the full previous transaction, and the key derivation.
		for input in &psbt.inputs {
			assert!(input.witness_utxo.is_some());
			assert!(input.non_witness_utxo.is_some());
			assert!(!input.bip32_derivation.is_empty());
		}

		// The change output must be recognizable as self-owned, so it carries a
		// key derivation too; the recipient output does not.
		let recipient_spk = recipient(0).address.script_pubkey();
		let change_output = psbt
			.unsigned_tx
			.output
			.iter()
			.zip(&psbt.outputs)
			.find(|(txout, _)| txout.script_pubkey != recipient_spk)
			.map(|(_, out)| out)
			.expect("change output missing");
		assert!(!change_output.bip32_derivation.is_empty());
	}

	#[test]
	fn create_psbt_change_pays_internal_keychain() {
		let wallet = import_test_wallet(test_store()).unwrap();
		fund_account(&wallet, 100_000);

		let psbt = wallet.create_psbt(vec![recipient(50_000)], vec![], testnet_fee_rate()).unwrap();

		// The first internal (change) address of the account.
		let change_spk = wallet
			.with_inner_mut(|w| w.peek_address(KeychainKind::Internal, 0).address.script_pubkey());
		assert!(psbt.unsigned_tx.output.iter().any(|o| o.script_pubkey == change_spk));
	}

	#[test]
	fn create_psbt_with_manual_selection_spends_only_given_utxos() {
		let wallet = import_test_wallet(test_store()).unwrap();
		let first = fund_account(&wallet, 60_000);
		let _second = fund_account(&wallet, 60_000);

		let psbt =
			wallet.create_psbt(vec![recipient(20_000)], vec![first], testnet_fee_rate()).unwrap();

		let spent: Vec<OutPoint> =
			psbt.unsigned_tx.input.iter().map(|i| i.previous_output).collect();
		assert_eq!(spent, vec![first]);
	}

	#[test]
	fn create_psbt_supports_multiple_recipients() {
		let wallet = import_test_wallet(test_store()).unwrap();
		fund_account(&wallet, 200_000);

		let second_recipient = PsbtRecipient {
			address: Address::from_str("tb1q7whne2rauhqkg7pe8dpra6rs5cxgq0429pxn88")
				.unwrap()
				.assume_checked(),
			amount_sats: 30_000,
		};
		let psbt = wallet
			.create_psbt(
				vec![recipient(50_000), second_recipient.clone()],
				vec![],
				testnet_fee_rate(),
			)
			.unwrap();

		let outputs = &psbt.unsigned_tx.output;
		assert!(outputs.iter().any(|o| o.script_pubkey == recipient(0).address.script_pubkey()
			&& o.value == Amount::from_sat(50_000)));
		assert!(outputs
			.iter()
			.any(|o| o.script_pubkey == second_recipient.address.script_pubkey()
				&& o.value == Amount::from_sat(30_000)));
	}

	#[test]
	fn create_psbt_rejects_unknown_utxo() {
		let wallet = import_test_wallet(test_store()).unwrap();
		fund_account(&wallet, 100_000);

		let unknown = OutPoint { txid: bitcoin::Txid::all_zeros(), vout: 0 };
		let result = wallet.create_psbt(vec![recipient(50_000)], vec![unknown], testnet_fee_rate());

		assert!(matches!(result, Err(Error::OnchainTxCreationFailed)));
	}

	#[test]
	fn create_psbt_with_insufficient_funds_errors() {
		let wallet = import_test_wallet(test_store()).unwrap();
		fund_account(&wallet, 10_000);

		let result = wallet.create_psbt(vec![recipient(1_000_000)], vec![], testnet_fee_rate());

		assert!(matches!(result, Err(Error::InsufficientFunds)));
	}

	#[test]
	fn create_psbt_rejects_wrong_network_recipient() {
		let wallet = import_test_wallet(test_store()).unwrap();
		fund_account(&wallet, 100_000);

		// A mainnet address does not belong to this testnet account.
		let mainnet_recipient = PsbtRecipient {
			address: Address::from_str("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
				.unwrap()
				.assume_checked(),
			amount_sats: 50_000,
		};
		let result = wallet.create_psbt(vec![mainnet_recipient], vec![], testnet_fee_rate());

		assert!(matches!(result, Err(Error::InvalidAddress)));
	}
}

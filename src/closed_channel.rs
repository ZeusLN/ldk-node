// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin::OutPoint;
use bitcoin::secp256k1::PublicKey;
use lightning::events::ClosureReason;
use lightning::ln::msgs::DecodeError;
use lightning::ln::types::ChannelId;
use lightning::util::ser::{Readable, Writeable};
use lightning::{_init_and_read_len_prefixed_tlv_fields, write_tlv_fields};

use crate::data_store::{StorableObject, StorableObjectId, StorableObjectUpdate};
use crate::hex_utils;
use crate::types::UserChannelId;

/// Details of a closed channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosedChannelDetails {
	/// The channel's ID.
	pub channel_id: ChannelId,
	/// The local `user_channel_id` of this channel.
	pub user_channel_id: UserChannelId,
	/// The node ID of the channel's counterparty.
	pub counterparty_node_id: Option<PublicKey>,
	/// The channel's funding transaction output, if known.
	pub funding_txo: Option<OutPoint>,
	/// The capacity of the channel in satoshis.
	pub channel_capacity_sats: Option<u64>,
	/// An upper bound on the local balance in millisatoshis before the channel was closed.
	pub last_local_balance_msat: Option<u64>,
	/// The reason the channel was closed.
	pub closure_reason: Option<ClosureReason>,
	/// The timestamp, in seconds since start of the UNIX epoch, when the channel was closed.
	pub closed_at_timestamp: u64,
}

impl Writeable for ClosedChannelDetails {
	fn write<W: lightning::util::ser::Writer>(
		&self, writer: &mut W,
	) -> Result<(), lightning::io::Error> {
		write_tlv_fields!(writer, {
			(0, self.channel_id, required),
			(2, self.user_channel_id, required),
			(4, self.counterparty_node_id, option),
			(6, self.funding_txo, option),
			(8, self.channel_capacity_sats, option),
			(10, self.last_local_balance_msat, option),
			(12, self.closure_reason, option),
			(14, self.closed_at_timestamp, required)
		});
		Ok(())
	}
}

impl Readable for ClosedChannelDetails {
	fn read<R: lightning::io::Read>(
		reader: &mut R,
	) -> Result<ClosedChannelDetails, DecodeError> {
		let unix_time_secs = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or(Duration::from_secs(0))
			.as_secs();
		_init_and_read_len_prefixed_tlv_fields!(reader, {
			(0, channel_id, required),
			(2, user_channel_id, required),
			(4, counterparty_node_id, option),
			(6, funding_txo, option),
			(8, channel_capacity_sats, option),
			(10, last_local_balance_msat, option),
			(12, closure_reason, upgradable_option),
			(14, closed_at_timestamp, (default_value, unix_time_secs))
		});

		let channel_id: ChannelId = channel_id.0.ok_or(DecodeError::InvalidValue)?;
		let user_channel_id: UserChannelId =
			user_channel_id.0.ok_or(DecodeError::InvalidValue)?;
		let closed_at_timestamp: u64 =
			closed_at_timestamp.0.ok_or(DecodeError::InvalidValue)?;

		Ok(ClosedChannelDetails {
			channel_id,
			user_channel_id,
			counterparty_node_id,
			funding_txo,
			channel_capacity_sats,
			last_local_balance_msat,
			closure_reason,
			closed_at_timestamp,
		})
	}
}

impl StorableObjectId for ChannelId {
	fn encode_to_hex_str(&self) -> String {
		hex_utils::to_string(&self.0)
	}
}

/// Update type for closed channel details. Closed channels are insert-only,
/// so updates are essentially no-ops.
#[derive(Clone, Debug)]
pub struct ClosedChannelDetailsUpdate {
	channel_id: ChannelId,
}

impl StorableObjectUpdate<ClosedChannelDetails> for ClosedChannelDetailsUpdate {
	fn id(&self) -> ChannelId {
		self.channel_id
	}
}

impl StorableObject for ClosedChannelDetails {
	type Id = ChannelId;
	type Update = ClosedChannelDetailsUpdate;

	fn id(&self) -> Self::Id {
		self.channel_id
	}

	fn update(&mut self, _update: &Self::Update) -> bool {
		// Closed channel records are insert-only; updates are no-ops.
		false
	}

	fn to_update(&self) -> Self::Update {
		ClosedChannelDetailsUpdate { channel_id: self.channel_id }
	}
}

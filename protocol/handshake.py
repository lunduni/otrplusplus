"""Session establishment (asynchronous AKE).

Implements a prekey-based handshake similar to X3DH:

Initiator computes:
	DH1 = DH(EK_A, IK_B)
	DH2 = DH(EK_A, SPK_B)
	DH3 = DH(EK_A, OPK_B)  (optional)
	SK  = HKDF(DH1 || DH2 || DH3)

Receiver can reconstruct SK upon receiving the first message carrying EK_A_pub
and the chosen OPK id (if any).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from crypto.encryption import hkdf_sha256, kdf_root
from crypto.keys import SignedPreKey, x25519_public_from_bytes
from crypto.signatures import public_from_bytes as ed25519_public_from_bytes
from crypto.signatures import verify as ed25519_verify
from utils.conversions import b64d, b64e


@dataclass
class ReceiverPrekeys:
	user_id: str
	identity_dh_public: X25519PublicKey
	identity_sig_public: Any  # Ed25519PublicKey
	signed_prekey_id: str
	signed_prekey_public: X25519PublicKey
	signed_prekey_signature: bytes
	signed_prekey_timestamp: int
	one_time_prekey_id: Optional[str]
	one_time_prekey_public: Optional[X25519PublicKey]


def parse_receiver_prekeys(prekeys_response: dict[str, Any]) -> ReceiverPrekeys:
	"""Parse GET /prekeys/{user_id} response into typed keys."""
	if "prekeys" in prekeys_response:
		prekeys = prekeys_response["prekeys"]
	else:
		prekeys = prekeys_response

	user_id = str(prekeys["user_id"])
	ik = prekeys["identity_key"]
	spk = prekeys["signed_prekey"]
	opk = prekeys.get("one_time_prekey")

	identity_dh_pub = x25519_public_from_bytes(b64d(ik["dh"]))
	identity_sig_pub = ed25519_public_from_bytes(b64d(ik["sig"]))

	spk_pub = x25519_public_from_bytes(b64d(spk["public"]))
	spk_sig = b64d(spk["signature"])
	spk_ts = int(spk["timestamp"])
	spk_id = str(spk.get("id", ""))

	opk_id: Optional[str] = None
	opk_pub: Optional[X25519PublicKey] = None
	if opk is not None:
		opk_id = str(opk["id"])
		opk_pub = x25519_public_from_bytes(b64d(opk["public"]))

	return ReceiverPrekeys(
		user_id=user_id,
		identity_dh_public=identity_dh_pub,
		identity_sig_public=identity_sig_pub,
		signed_prekey_id=spk_id,
		signed_prekey_public=spk_pub,
		signed_prekey_signature=spk_sig,
		signed_prekey_timestamp=spk_ts,
		one_time_prekey_id=opk_id,
		one_time_prekey_public=opk_pub,
	)


def _derive_session_id(root_key: bytes) -> str:
	sid = hkdf_sha256(root_key, salt=None, info=b"OTR++/session_id", length=16)
	return b64e(sid)


def initiate_session(sender: Any, receiver_prekeys: dict[str, Any]):
	"""Initiate a session with receiver prekeys fetched from the server.

	Returns: (session_state, handshake_header_fields)
	"""

	# local import to avoid circular imports
	# we got into trouble trying to import at the top level
	from protocol.messaging import SessionState
	from crypto.keys import EphemeralKey

	rp = parse_receiver_prekeys(receiver_prekeys)

	spk_msg = SignedPreKey._signature_message(rp.signed_prekey_public, rp.signed_prekey_timestamp)
	if not ed25519_verify(rp.identity_sig_public, spk_msg, rp.signed_prekey_signature):
		raise ValueError("invalid signed prekey signature")


	# Generate an ephemeral key pair for this session. 
	# This will be included in the first message and used for DH key agreement.
	ek_a = EphemeralKey.generate()

	# Perform the DH computations as per X3DH:
	dh1 = ek_a.dh_private.exchange(rp.identity_dh_public)
	dh2 = ek_a.dh_private.exchange(rp.signed_prekey_public)
	# DH3 is optional and only performed if the receiver has an unused OPK. 
	# The initiator can still proceed without it, but including it provides better forward secrecy.
	if rp.one_time_prekey_public is not None:
		dh3 = ek_a.dh_private.exchange(rp.one_time_prekey_public)
		used_opk_id = rp.one_time_prekey_id
	else:
		dh3 = b""
		used_opk_id = None

	# Derive the initial root key and chain keys from the DH outputs using HKDF.
	root0 = hkdf_sha256(dh1 + dh2 + dh3, salt=None, info=b"OTR++/x3dh", length=32)
	session_id = _derive_session_id(root0)

	# The initiator's sending chain key is derived from the root key 
	# and the DH with the receiver's signed prekey.
	dh_remote = rp.signed_prekey_public
	root_key, sending_chain_key = kdf_root(root0, ek_a.dh_private.exchange(dh_remote))

	state = SessionState(
		message_counter=0,
		session_id=session_id,
		root_key=root_key,
		chain_key=sending_chain_key,
		receiving_chain_key=None,
		send_counter=0,
		recv_counter=0,
		previous_keys={},
		dh_self=ek_a.dh_private,
		dh_remote=dh_remote,
		role="initiator",
		dh_rotate_interval=sender.dh_rotate_interval,
	)

	header = {
		"sender_id": sender.user_id,
		"receiver_id": rp.user_id,
		"handshake": True,
		"spk_id": rp.signed_prekey_id,
		"spk_timestamp": rp.signed_prekey_timestamp,
		"opk_id": used_opk_id,
	}
	return state, header


def accept_session(receiver: Any, header: dict[str, Any], sender_ephemeral_pub_b64: str):
	"""Derive a session state for the receiver from the initial message."""

	from protocol.messaging import SessionState

	sender_ephemeral_pub = x25519_public_from_bytes(b64d(sender_ephemeral_pub_b64))

	opk_id = header.get("opk_id")
	spk_id = header.get("spk_id")

	ik_b_priv = receiver.key_store.identity.dh_private
	spk = receiver.key_store.signed_prekey
	if spk_id and str(spk.id) != str(spk_id):
		# The initiator specified a signed prekey ID that doesn't match the receiver's current one.
		# This could happen if the receiver rotated their signed prekey after the initiator fetched
		# Any ideas on how to handle this case, Hadar/Paul? 
		pass

	dh1 = ik_b_priv.exchange(sender_ephemeral_pub)
	dh2 = spk.dh_private.exchange(sender_ephemeral_pub)

	dh3 = b""
	if opk_id:
		try:
			opk = receiver.key_store.consume_one_time_prekey(str(opk_id))
			dh3 = opk.dh_private.exchange(sender_ephemeral_pub)
		except Exception:
			dh3 = b""

	root0 = hkdf_sha256(dh1 + dh2 + dh3, salt=None, info=b"OTR++/x3dh", length=32)
	session_id = _derive_session_id(root0)

	dh_remote = sender_ephemeral_pub
	root_key, receiving_chain_key = kdf_root(root0, spk.dh_private.exchange(dh_remote))

	state = SessionState(
		message_counter=0,
		session_id=session_id,
		root_key=root_key,
		chain_key=None,
		receiving_chain_key=receiving_chain_key,
		send_counter=0,
		recv_counter=0,
		previous_keys={},
		dh_self=spk.dh_private,
		dh_remote=dh_remote,
		role="responder",
		dh_rotate_interval=receiver.dh_rotate_interval,
	)
	return state


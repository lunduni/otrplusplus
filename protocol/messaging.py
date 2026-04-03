"""Message construction/parsing and continuous key evolution.

This module implements:
- Message structure (serialization + authenticated bytes)
- Symmetric ratchet (chain key per direction)
- DH ratchet (periodic ephemeral rotation)
- Integration with adaptive deniability (MAC/signature rules)
"""

from __future__ import annotations

import hmac as stdlib_hmac
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
	Ed25519PrivateKey,
	Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
	X25519PrivateKey,
	X25519PublicKey,
)

from crypto.encryption import decrypt, encrypt, hkdf_sha256, hmac_sha256, kdf_chain, kdf_root
from crypto.keys import x25519_public_bytes, x25519_public_from_bytes
from crypto.signatures import sign as ed25519_sign
from crypto.signatures import verify as ed25519_verify
from protocol.deniability import (
	DENIABLE,
	VERIFIABLE,
	DeniabilityState,
	collect_revealable_mac_keys,
	queue_mac_key,
)
from utils.conversions import b64d, b64e, json_dumps_canonical


def _aad_payload(header: dict[str, Any], mode_flag: int, session_id: str, counter: int, ephemeral_pub: str | None) -> bytes:
	return json_dumps_canonical(
		{
			"header": header,
			"mode_flag": int(mode_flag),
			"session_id": session_id,
			"counter": int(counter),
			"ephemeral_pub": ephemeral_pub,
		}
	)


@dataclass
class Message:
	header: dict[str, Any]
	mode_flag: int
	session_id: str
	counter: int
	ephemeral_pub: Optional[str]
	ciphertext: str
	mac: Optional[str] = None
	signature: Optional[str] = None
	revealed_mac_keys: Optional[List[str]] = None

	def to_dict(self) -> dict[str, Any]:
		return {
			"header": self.header,
			"mode_flag": int(self.mode_flag),
			"session_id": self.session_id,
			"counter": int(self.counter),
			"ephemeral_pub": self.ephemeral_pub,
			"ciphertext": self.ciphertext,
			"mac": self.mac,
			"signature": self.signature,
			"revealed_mac_keys": self.revealed_mac_keys,
		}

	@staticmethod
	def from_dict(d: dict[str, Any]) -> "Message":
		if not isinstance(d, dict):
			raise TypeError("message must be a dict")
		return Message(
			header=dict(d.get("header") or {}),
			mode_flag=int(d.get("mode_flag")),
			session_id=str(d.get("session_id")),
			counter=int(d.get("counter")),
			ephemeral_pub=d.get("ephemeral_pub"),
			ciphertext=str(d.get("ciphertext")),
			mac=d.get("mac"),
			signature=d.get("signature"),
			revealed_mac_keys=d.get("revealed_mac_keys"),
		)

	def aad_bytes(self) -> bytes:
		# AAD is the data authenticated by the MAC/signature. 
		# It includes all fields except the MAC/signature themselves.
		return _aad_payload(self.header, self.mode_flag, self.session_id, self.counter, self.ephemeral_pub)

	def auth_bytes(self) -> bytes:
		"""Canonical bytes authenticated by MAC/signature (excludes mac/signature fields)."""
		return json_dumps_canonical(
			{
				"header": self.header,
				"mode_flag": int(self.mode_flag),
				"session_id": self.session_id,
				"counter": int(self.counter),
				"ephemeral_pub": self.ephemeral_pub,
				"ciphertext": self.ciphertext,
				"revealed_mac_keys": self.revealed_mac_keys,
			}
		)


@dataclass
class SessionState:
	root_key: bytes
	chain_key: Optional[bytes]
	message_counter: int
	previous_keys: Dict[Tuple[str, int], bytes]

	session_id: str
	receiving_chain_key: Optional[bytes]
	send_counter: int
	recv_counter: int
	dh_self: X25519PrivateKey
	dh_remote: X25519PublicKey
	role: str
	dh_rotate_interval: int = 5
	outgoing_index: int = 0
	deniability: DeniabilityState = field(default_factory=DeniabilityState)
	peer_sig_public: Optional[Ed25519PublicKey] = None
	peer_id: Optional[str] = None

	def __post_init__(self) -> None:
		if self.chain_key is None and self.role == "initiator":
			raise ValueError("initiator must start with a sending chain_key")
		if self.receiving_chain_key is None and self.role == "responder":
			raise ValueError("responder must start with a receiving_chain_key")

	@property
	def current_ephemeral(self) -> X25519PrivateKey:
		return self.dh_self


def _derive_message_keys(message_key: bytes) -> Tuple[bytes, bytes]:
	enc_key = hkdf_sha256(message_key, salt=None, info=b"OTR++/msg_enc", length=32)
	mac_key = hkdf_sha256(message_key, salt=None, info=b"OTR++/msg_mac", length=32)
	return enc_key, mac_key


def _maybe_rotate_dh_for_send(session: SessionState) -> bool:
	if session.chain_key is None:
		return True
	if session.dh_rotate_interval <= 0:
		return False
	return session.send_counter > 0 and (session.send_counter % session.dh_rotate_interval == 0)


def _ratchet_send(session: SessionState) -> None:
	session.dh_self = X25519PrivateKey.generate()
	dh_secret = session.dh_self.exchange(session.dh_remote)
	session.root_key, session.chain_key = kdf_root(session.root_key, dh_secret)
	session.send_counter = 0
	session.message_counter = session.send_counter


def _ratchet_receive(session: SessionState, new_remote: X25519PublicKey) -> None:
	session.dh_remote = new_remote
	dh_secret = session.dh_self.exchange(session.dh_remote)
	session.root_key, session.receiving_chain_key = kdf_root(session.root_key, dh_secret)
	session.recv_counter = 0


def _remote_pub_b64(pub: X25519PublicKey) -> str:
	return b64e(x25519_public_bytes(pub))


def construct_outgoing_message(
	*,
	sender_id: str,
	receiver_id: str,
	session: SessionState,
	plaintext: str,
	mode: int,
	signing_private_key: Ed25519PrivateKey,
	header_extra: Optional[dict[str, Any]] = None,
) -> Message:
	if _maybe_rotate_dh_for_send(session):
		print("[KEY ROTATION]")
		_ratchet_send(session)

	if session.chain_key is None:
		raise ValueError("missing sending chain_key")

	header: dict[str, Any] = {"sender_id": sender_id, "receiver_id": receiver_id}
	if header_extra:
		header.update(header_extra)

	ephemeral_pub_b64 = b64e(x25519_public_bytes(session.dh_self.public_key()))
	counter = session.send_counter

	message_key, next_chain_key = kdf_chain(session.chain_key)
	print("[KEY ROTATION]")
	enc_key, mac_key = _derive_message_keys(message_key)
	nonce = hkdf_sha256(message_key, salt=None, info=b"OTR++/msg_nonce", length=12)

	aad = _aad_payload(header, mode, session.session_id, counter, ephemeral_pub_b64)
	ct = encrypt(enc_key, plaintext.encode("utf-8"), aad=aad, nonce=nonce)
	msg = Message(
		header=header,
		mode_flag=int(mode),
		session_id=session.session_id,
		counter=counter,
		ephemeral_pub=ephemeral_pub_b64,
		ciphertext=b64e(ct),
		mac=None,
		signature=None,
		revealed_mac_keys=None,
	)

	session.outgoing_index += 1
	if mode == DENIABLE:
		print("[MODE: DENIABLE]")
		reveal = collect_revealable_mac_keys(session.deniability, current_index=session.outgoing_index)
		queue_mac_key(session.deniability, message_index=session.outgoing_index, mac_key=mac_key)
		msg.revealed_mac_keys = [b64e(k) for k in reveal] if reveal else []
		msg.mac = b64e(hmac_sha256(mac_key, msg.auth_bytes()))
		print("[MAC GENERATED]")
		if reveal:
			print("[MAC KEY DISCLOSED]")
	elif mode == VERIFIABLE:
		print("[MODE: VERIFIABLE]")
		msg.revealed_mac_keys = None
		msg.signature = b64e(ed25519_sign(signing_private_key, msg.auth_bytes()))
	else:
		raise ValueError("unknown mode")

	session.chain_key = next_chain_key
	session.send_counter += 1
	session.message_counter = session.send_counter
	return msg


def process_incoming_message(
	*,
	receiver_id: str,
	session: SessionState,
	message_dict: dict[str, Any],
	peer_sig_public: Optional[Ed25519PublicKey] = None,
) -> str:
	msg = Message.from_dict(message_dict)
	if msg.session_id != session.session_id:
		raise ValueError("session_id mismatch")
	if msg.header.get("receiver_id") != receiver_id:
		raise ValueError("wrong receiver")

	if msg.ephemeral_pub is None:
		raise ValueError("missing ephemeral_pub")

	remote_pub = x25519_public_from_bytes(b64d(msg.ephemeral_pub))
	if _remote_pub_b64(remote_pub) != _remote_pub_b64(session.dh_remote):
		print("[KEY ROTATION]")
		_ratchet_receive(session, remote_pub)

	if session.receiving_chain_key is None:
		raise ValueError("missing receiving chain_key")

	chain_id = _remote_pub_b64(session.dh_remote)
	if msg.counter < session.recv_counter:
		# This is a message from an old sending chain (before a DH ratchet). 
		# We should have the message key cached in previous_keys.
		key = session.previous_keys.get((chain_id, msg.counter))
		if key is None:
			raise ValueError("replayed/unknown counter")
		message_key = key
	else:
		# Advance the receiving chain to derive the message key. 
		# This will also update the session state to reflect the new recv_counter and previous_keys.
		while session.recv_counter < msg.counter:
			mk, ck_next = kdf_chain(session.receiving_chain_key)
			session.previous_keys[(chain_id, session.recv_counter)] = mk
			session.receiving_chain_key = ck_next
			session.recv_counter += 1
		message_key, session.receiving_chain_key = kdf_chain(session.receiving_chain_key)
		session.recv_counter += 1

	print("[KEY ROTATION]")

	enc_key, mac_key = _derive_message_keys(message_key)

	aad = msg.aad_bytes()
	pt = decrypt(enc_key, b64d(msg.ciphertext), aad=aad)

	if msg.mode_flag == DENIABLE:
		if msg.signature is not None:
			raise ValueError("signature present in deniable message")
		if msg.mac is None:
			raise ValueError("missing mac")
		expected = hmac_sha256(mac_key, msg.auth_bytes())
		if not stdlib_hmac.compare_digest(expected, b64d(msg.mac)):
			raise ValueError("invalid mac")
		print("[MAC VERIFIED]")
		if msg.revealed_mac_keys:
			print("[MAC KEY DISCLOSED]")
	elif msg.mode_flag == VERIFIABLE:
		if msg.mac is not None:
			raise ValueError("mac present in verifiable message")
		if msg.revealed_mac_keys not in (None, []):
			raise ValueError("mac keys disclosed in verifiable message")
		if msg.signature is None:
			raise ValueError("missing signature")
		pub = peer_sig_public or session.peer_sig_public
		if pub is None:
			raise ValueError("missing peer signature public key")
		if not ed25519_verify(pub, msg.auth_bytes(), b64d(msg.signature)):
			raise ValueError("invalid signature")
		print("[SIGNATURE VERIFIED]")
	else:
		raise ValueError("unknown mode")

	return pt.decode("utf-8")


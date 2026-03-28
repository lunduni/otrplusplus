"""Key management for OTR++.

Implements:
- Identity keys (DH + signing)
- Signed prekeys (DH keypair signed by identity signing key)
- One-time prekeys (DH keypairs)
- Ephemeral keys (DH keypairs) used for session init and ratcheting
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
	Ed25519PrivateKey,
	Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
	X25519PrivateKey,
	X25519PublicKey,
)

from crypto.signatures import public_bytes as ed25519_public_bytes
from crypto.signatures import sign as ed25519_sign
from crypto.signatures import verify as ed25519_verify
from utils.conversions import b64e, int_to_bytes, utc_timestamp


def x25519_public_bytes(public_key: X25519PublicKey) -> bytes:
	return public_key.public_bytes(
		encoding=serialization.Encoding.Raw,
		format=serialization.PublicFormat.Raw,
	)


def x25519_private_bytes(private_key: X25519PrivateKey) -> bytes:
	return private_key.private_bytes(
		encoding=serialization.Encoding.Raw,
		format=serialization.PrivateFormat.Raw,
		encryption_algorithm=serialization.NoEncryption(),
	)


def x25519_public_from_bytes(data: bytes) -> X25519PublicKey:
	return X25519PublicKey.from_public_bytes(bytes(data))


@dataclass(frozen=True)
class IdentityKeyPair:
	"""Long-term identity keys.

	- dh_*: X25519 for Diffie-Hellman
	- sig_*: Ed25519 for signatures
	"""

	dh_private: X25519PrivateKey
	dh_public: X25519PublicKey
	sig_private: Ed25519PrivateKey
	sig_public: Ed25519PublicKey

	@staticmethod
	def generate() -> "IdentityKeyPair":
		dh_priv = X25519PrivateKey.generate()
		sig_priv = Ed25519PrivateKey.generate()
		return IdentityKeyPair(
			dh_private=dh_priv,
			dh_public=dh_priv.public_key(),
			sig_private=sig_priv,
			sig_public=sig_priv.public_key(),
		)

	def public_bundle(self) -> dict:
		return {
			"dh": b64e(x25519_public_bytes(self.dh_public)),
			"sig": b64e(ed25519_public_bytes(self.sig_public)),
		}


@dataclass
class SignedPreKey:
	id: str
	dh_private: X25519PrivateKey
	dh_public: X25519PublicKey
	signature: bytes
	timestamp: int

	@staticmethod
	def generate(identity: IdentityKeyPair, *, timestamp: Optional[int] = None) -> "SignedPreKey":
		ts = utc_timestamp() if timestamp is None else int(timestamp)
		dh_priv = X25519PrivateKey.generate()
		dh_pub = dh_priv.public_key()
		msg = SignedPreKey._signature_message(dh_pub, ts)
		sig = ed25519_sign(identity.sig_private, msg)
		return SignedPreKey(
			id=str(uuid4()),
			dh_private=dh_priv,
			dh_public=dh_pub,
			signature=sig,
			timestamp=ts,
		)

	@staticmethod
	def _signature_message(dh_public: X25519PublicKey, timestamp: int) -> bytes:
		return b"OTR++-AD/SPK" + x25519_public_bytes(dh_public) + int_to_bytes(timestamp)

	def verify(self, identity_sig_public: Ed25519PublicKey) -> bool:
		msg = SignedPreKey._signature_message(self.dh_public, self.timestamp)
		return ed25519_verify(identity_sig_public, msg, self.signature)

	def public_bundle(self) -> dict:
		return {
			"id": self.id,
			"public": b64e(x25519_public_bytes(self.dh_public)),
			"signature": b64e(self.signature),
			"timestamp": self.timestamp,
		}


@dataclass
class OneTimePreKey:
	id: str
	dh_private: X25519PrivateKey
	dh_public: X25519PublicKey
	used: bool = False

	@staticmethod
	def generate() -> "OneTimePreKey":
		dh_priv = X25519PrivateKey.generate()
		return OneTimePreKey(
			id=str(uuid4()),
			dh_private=dh_priv,
			dh_public=dh_priv.public_key(),
			used=False,
		)

	def public_bundle(self) -> dict:
		return {"id": self.id, "public": b64e(x25519_public_bytes(self.dh_public))}


@dataclass(frozen=True)
class EphemeralKey:
	dh_private: X25519PrivateKey
	dh_public: X25519PublicKey

	@staticmethod
	def generate() -> "EphemeralKey":
		dh_priv = X25519PrivateKey.generate()
		return EphemeralKey(dh_private=dh_priv, dh_public=dh_priv.public_key())


class KeyStore:
	"""Local key store (in-memory) with rotation and deletion semantics."""

	def __init__(self) -> None:
		self.identity: IdentityKeyPair = IdentityKeyPair.generate()
		self.signed_prekey: SignedPreKey = SignedPreKey.generate(self.identity)
		self._one_time_prekeys: Dict[str, OneTimePreKey] = {}

	def generate_one_time_prekeys(self, count: int = 10) -> List[OneTimePreKey]:
		if count <= 0:
			raise ValueError("count must be positive")
		opks = [OneTimePreKey.generate() for _ in range(count)]
		for k in opks:
			self._one_time_prekeys[k.id] = k
		return opks

	def list_one_time_prekeys(self, *, include_used: bool = False) -> List[OneTimePreKey]:
		if include_used:
			return list(self._one_time_prekeys.values())
		return [k for k in self._one_time_prekeys.values() if not k.used]

	def get_one_time_prekey(self, opk_id: str) -> OneTimePreKey:
		if opk_id not in self._one_time_prekeys:
			raise KeyError("unknown opk_id")
		return self._one_time_prekeys[opk_id]

	def consume_one_time_prekey(self, opk_id: str) -> OneTimePreKey:
		"""Mark OPK as used and remove it from the store (best-effort secure deletion)."""
		opk = self.get_one_time_prekey(opk_id)
		opk.used = True

		_ = x25519_private_bytes(opk.dh_private)
		del self._one_time_prekeys[opk_id]
		return opk

	def rotate_signed_prekey(self) -> SignedPreKey:
		self.signed_prekey = SignedPreKey.generate(self.identity)
		return self.signed_prekey

	def public_prekey_bundle(self, user_id: str) -> dict:
		return {
			"user_id": user_id,
			"identity_key": self.identity.public_bundle(),
			"signed_prekey": self.signed_prekey.public_bundle(),
			"one_time_prekeys": [k.public_bundle() for k in self.list_one_time_prekeys()],
		}


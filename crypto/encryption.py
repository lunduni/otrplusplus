"""Symmetric encryption, HKDF, and HMAC utilities.

Algorithms (per spec):
- AES-256-GCM for authenticated encryption
- HKDF(SHA-256) for key derivation
- HMAC-SHA256 for MACs (deniable mode)
"""

from __future__ import annotations

import os
from typing import Tuple

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


AES_GCM_NONCE_SIZE = 12
AES_256_KEY_SIZE = 32
SHA256_SIZE = 32


def hkdf_sha256(
	input_material: bytes,
	*,
	salt: bytes | None = None,
	info: bytes = b"",
	length: int = AES_256_KEY_SIZE,
) -> bytes:
	'''Derive bytes(keys) from input material using HKDF with SHA-256.'''
	if not isinstance(input_material, (bytes, bytearray, memoryview)):
		raise TypeError("input_material must be bytes")
	if salt is not None and not isinstance(salt, (bytes, bytearray, memoryview)):
		raise TypeError("salt must be bytes or None")
	if not isinstance(info, (bytes, bytearray, memoryview)):
		raise TypeError("info must be bytes")
	if length <= 0:
		raise ValueError("length must be positive")

	hkdf = HKDF(
		algorithm=hashes.SHA256(),
		length=length,
		salt=None if salt is None else bytes(salt),
		info=bytes(info),
	)
	# HKDF derives keys as bytes from the input material.
	return hkdf.derive(bytes(input_material))


def hmac_sha256(key: bytes, data: bytes) -> bytes:
	"""Compute HMAC-SHA256 of data using the given key. Returns the raw 32-byte tag."""
	if not isinstance(key, (bytes, bytearray, memoryview)):
		raise TypeError("key must be bytes")
	if not isinstance(data, (bytes, bytearray, memoryview)):
		raise TypeError("data must be bytes")
	h = hmac.HMAC(bytes(key), hashes.SHA256())
	h.update(bytes(data))
	return h.finalize()


def kdf_root(root_key: bytes, dh_secret: bytes) -> Tuple[bytes, bytes]:
	"""Derive a new root key and a new chain key from a DH shared secret.
	Useful(used) for both session initialization and ratcheting.
	"""
	out = hkdf_sha256(
		dh_secret,
		salt=root_key,
		info=b"OTR++/kdf_root",
		length=64,
	)
	# Split the 64-byte output into two 32-byte keys: new root key and new chain key.
	return out[:32], out[32:]


def kdf_chain(chain_key: bytes) -> Tuple[bytes, bytes]:
	"""Derive (message_key, next_chain_key) from current chain key."""
	out = hkdf_sha256(
		chain_key,
		salt=None,
		info=b"OTR++/kdf_chain",
		length=64,
	)
	# Split the 64-byte output into two 32-byte keys: message key and next chain key.
	return out[:32], out[32:]


def derive_key(input_material: bytes) -> bytes:
	"""Derive a 32-byte symmetric key from arbitrary input material."""
	return hkdf_sha256(input_material, salt=None, info=b"OTR++/derive_key", length=32)


def encrypt(key: bytes, plaintext: bytes, *, aad: bytes = b"", nonce: bytes | None = None) -> bytes:
	"""Encrypt with AES-256-GCM.
	aad is optional additional authenticated data (not encrypted but included in the tag).
	Returns: nonce || ciphertext || tag
	"""
	if len(key) != AES_256_KEY_SIZE:
		raise ValueError("AES-256-GCM key must be 32 bytes")
	if not isinstance(plaintext, (bytes, bytearray, memoryview)):
		raise TypeError("plaintext must be bytes")
	if not isinstance(aad, (bytes, bytearray, memoryview)):
		raise TypeError("aad must be bytes")

	if nonce is None:
		nonce = os.urandom(AES_GCM_NONCE_SIZE)
	else:
		if not isinstance(nonce, (bytes, bytearray, memoryview)):
			raise TypeError("nonce must be bytes")
		nonce = bytes(nonce)
		if len(nonce) != AES_GCM_NONCE_SIZE:
			raise ValueError("nonce must be 12 bytes")
	aesgcm = AESGCM(bytes(key))
	ct = aesgcm.encrypt(nonce, bytes(plaintext), bytes(aad))
	return nonce + ct


def decrypt(key: bytes, ciphertext: bytes, *, aad: bytes = b"") -> bytes:
	if len(key) != AES_256_KEY_SIZE:
		raise ValueError("AES-256-GCM key must be 32 bytes")
	if not isinstance(ciphertext, (bytes, bytearray, memoryview)):
		raise TypeError("ciphertext must be bytes")
	if not isinstance(aad, (bytes, bytearray, memoryview)):
		raise TypeError("aad must be bytes")

	data = bytes(ciphertext)
	if len(data) < AES_GCM_NONCE_SIZE + 16:
		raise ValueError("ciphertext too short")
	nonce = data[:AES_GCM_NONCE_SIZE]
	ct = data[AES_GCM_NONCE_SIZE:]
	aesgcm = AESGCM(bytes(key))
	return aesgcm.decrypt(nonce, ct, bytes(aad))


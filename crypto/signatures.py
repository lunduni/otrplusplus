"""Ed25519 signing and verification.
Ed25519 is used for both identity signatures and message authentication in OTR++.
Ed25519: Is the protocol used for Digital Signatures. It proves who you a user is.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
	Ed25519PrivateKey,
	Ed25519PublicKey,
)


def sign(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
	"""Sign a message with the given private key."""
	if not isinstance(message, (bytes, bytearray, memoryview)):
		raise TypeError("message must be bytes")
	return private_key.sign(bytes(message))


def verify(public_key: Ed25519PublicKey, message: bytes, signature: bytes) -> bool:
	"""Verify a signature for a given message and public key."""
	if not isinstance(message, (bytes, bytearray, memoryview)):
		raise TypeError("message must be bytes")
	if not isinstance(signature, (bytes, bytearray, memoryview)):
		raise TypeError("signature must be bytes")
	try:
		public_key.verify(bytes(signature), bytes(message))
		return True
	except InvalidSignature:
		return False


def public_bytes(public_key: Ed25519PublicKey) -> bytes:
	"""Get the raw bytes of an Ed25519 public key for serialization."""
	return public_key.public_bytes(
		encoding=serialization.Encoding.Raw,
		format=serialization.PublicFormat.Raw,
	)


def private_bytes(private_key: Ed25519PrivateKey) -> bytes:
	"""Get the raw bytes of an Ed25519 private key for serialization."""
	return private_key.private_bytes(
		encoding=serialization.Encoding.Raw,
		format=serialization.PrivateFormat.Raw,
		encryption_algorithm=serialization.NoEncryption(),
	)


def public_from_bytes(data: bytes) -> Ed25519PublicKey:
	"""Construct an Ed25519PublicKey from raw bytes."""
	if not isinstance(data, (bytes, bytearray, memoryview)):
		raise TypeError("data must be bytes")
	return Ed25519PublicKey.from_public_bytes(bytes(data))


def private_from_bytes(data: bytes) -> Ed25519PrivateKey:
	"""Construct an Ed25519PrivateKey from raw bytes."""
	if not isinstance(data, (bytes, bytearray, memoryview)):
		raise TypeError("data must be bytes")
	return Ed25519PrivateKey.from_private_bytes(bytes(data))


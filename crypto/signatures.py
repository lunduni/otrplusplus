"""Ed25519 signing and verification."""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
	Ed25519PrivateKey,
	Ed25519PublicKey,
)


def sign(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
	if not isinstance(message, (bytes, bytearray, memoryview)):
		raise TypeError("message must be bytes")
	return private_key.sign(bytes(message))


def verify(public_key: Ed25519PublicKey, message: bytes, signature: bytes) -> bool:
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
	return public_key.public_bytes(
		encoding=serialization.Encoding.Raw,
		format=serialization.PublicFormat.Raw,
	)


def private_bytes(private_key: Ed25519PrivateKey) -> bytes:
	return private_key.private_bytes(
		encoding=serialization.Encoding.Raw,
		format=serialization.PrivateFormat.Raw,
		encryption_algorithm=serialization.NoEncryption(),
	)


def public_from_bytes(data: bytes) -> Ed25519PublicKey:
	if not isinstance(data, (bytes, bytearray, memoryview)):
		raise TypeError("data must be bytes")
	return Ed25519PublicKey.from_public_bytes(bytes(data))


def private_from_bytes(data: bytes) -> Ed25519PrivateKey:
	if not isinstance(data, (bytes, bytearray, memoryview)):
		raise TypeError("data must be bytes")
	return Ed25519PrivateKey.from_private_bytes(bytes(data))


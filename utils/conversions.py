"""Encoding/decoding helpers.

The protocol needs deterministic serialization for MAC/signatures and safe
transport encoding for binary keys and ciphertexts.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any


def b64e(data: bytes) -> str:
	"""URL-safe base64 encoding without padding."""
	if not isinstance(data, (bytes, bytearray, memoryview)):
		raise TypeError("b64e expects bytes")
	return base64.urlsafe_b64encode(bytes(data)).decode("ascii").rstrip("=")


def b64d(data: str) -> bytes:
	"""Decode URL-safe base64 that may be missing padding."""
	if not isinstance(data, str):
		raise TypeError("b64d expects str")
	s = data.strip()
	if not s:
		return b""
	pad_len = (-len(s)) % 4
	s += "=" * pad_len
	try:
		return base64.urlsafe_b64decode(s.encode("ascii"))
	except Exception as exc:
		raise ValueError("invalid base64") from exc


def json_dumps_canonical(obj: Any) -> bytes:
	"""Deterministic JSON encoding for cryptographic authentication."""
	return json.dumps(
		obj,
		sort_keys=True,
		separators=(",", ":"),
		ensure_ascii=False,
	).encode("utf-8")


def utc_timestamp() -> int:
	return int(time.time())


def int_to_bytes(n: int, length: int = 8) -> bytes:
	if not isinstance(n, int) or n < 0:
		raise ValueError("n must be a non-negative int")
	return n.to_bytes(length, "big")


def require_fields(d: dict[str, Any], fields: list[str]) -> None:
	missing = [f for f in fields if f not in d]
	if missing:
		raise ValueError(f"missing required fields: {missing}")


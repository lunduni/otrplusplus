"""Adaptive deniability engine.

Modes:
- DENIABLE: authenticate with HMAC-SHA256 and later reveal MAC keys
- VERIFIABLE: authenticate with Ed25519 signature (no MAC key disclosure)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple


DENIABLE = 0
VERIFIABLE = 1


@dataclass
class DeniabilityState:
	"""Tracks MAC keys pending disclosure."""

	reveal_interval: int = 3
	pending_mac_keys: List[Tuple[int, bytes]] = field(default_factory=list)


def queue_mac_key(state: DeniabilityState, *, message_index: int, mac_key: bytes) -> None:
	state.pending_mac_keys.append((int(message_index), bytes(mac_key)))


def collect_revealable_mac_keys(state: DeniabilityState, *, current_index: int) -> List[bytes]:
	"""Return MAC keys eligible for disclosure at this point.

	Keys are eligible when they are at least `reveal_interval` messages old.
	"""

	now = int(current_index)
	reveal: List[bytes] = []
	keep: List[Tuple[int, bytes]] = []
	for idx, key in state.pending_mac_keys:
		if now - idx >= state.reveal_interval:
			reveal.append(key)
		else:
			keep.append((idx, key))
	state.pending_mac_keys = keep
	return reveal


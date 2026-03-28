"""User-facing client and session controller for OTR++."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional

from crypto.keys import KeyStore
from protocol.deniability import DENIABLE, VERIFIABLE
from protocol.handshake import accept_session, initiate_session, parse_receiver_prekeys
from protocol.messaging import Message, SessionState, construct_outgoing_message, process_incoming_message


@dataclass
class PrekeyServerClient:
	base_url: str

	def _url(self, path: str) -> str:
		return self.base_url.rstrip("/") + path

	def _request(self, method: str, path: str, payload: Optional[dict[str, Any]] = None) -> dict[str, Any]:
		data = None
		headers = {"Accept": "application/json"}
		if payload is not None:
			data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
			headers["Content-Type"] = "application/json"
		req = urllib.request.Request(self._url(path), data=data, headers=headers, method=method)
		try:
			with urllib.request.urlopen(req, timeout=5) as resp:
				raw = resp.read()
		except urllib.error.HTTPError as exc:
			raw = exc.read()
			try:
				err = json.loads(raw.decode("utf-8"))
			except Exception:
				raise RuntimeError(f"server error: {exc.code}") from exc
			raise RuntimeError(err.get("error") or f"server error: {exc.code}") from exc
		except urllib.error.URLError as exc:
			raise RuntimeError("unable to reach prekey server") from exc

		try:
			obj = json.loads(raw.decode("utf-8"))
		except Exception as exc:
			raise RuntimeError("invalid server response") from exc
		if not isinstance(obj, dict):
			raise RuntimeError("invalid server response")
		if obj.get("ok") is not True:
			raise RuntimeError(obj.get("error") or "server error")
		return obj

	def upload_prekeys(self, bundle: dict[str, Any]) -> None:
		self._request("POST", "/prekeys", bundle)

	def fetch_prekeys(self, user_id: str) -> dict[str, Any]:
		return self._request("GET", f"/prekeys/{urllib.parse.quote(user_id)}")

	def mark_one_time_prekey_used(self, opk_id: str) -> None:
		self._request("DELETE", f"/prekeys/{urllib.parse.quote(opk_id)}")


class Client:
	def __init__(
		self,
		*,
		user_id: str,
		server_url: str,
		one_time_prekeys: int = 10,
		mac_reveal_interval: int = 3,
		dh_rotate_interval: int = 5,
	) -> None:
		self.user_id = user_id
		self.server = PrekeyServerClient(server_url)
		self.key_store = KeyStore()
		self.key_store.generate_one_time_prekeys(one_time_prekeys)
		self.mac_reveal_interval = int(mac_reveal_interval)
		self.dh_rotate_interval = int(dh_rotate_interval)

		self._sessions: Dict[str, SessionState] = {}
		self._pending_headers: Dict[str, dict[str, Any]] = {}

	def publish_prekeys(self) -> None:
		self.server.upload_prekeys(self.key_store.public_prekey_bundle(self.user_id))

	def start_session(self, peer_id: str) -> SessionState:
		prekeys_resp = self.server.fetch_prekeys(peer_id)
		rp = parse_receiver_prekeys(prekeys_resp)
		session, header = initiate_session(self, prekeys_resp)
		session.peer_id = peer_id
		session.peer_sig_public = rp.identity_sig_public
		session.deniability.reveal_interval = self.mac_reveal_interval
		self._sessions[peer_id] = session
		self._pending_headers[peer_id] = header
		return session

	def send_message(self, *, peer_id: str, text: str, mode: int) -> dict[str, Any]:
		if mode not in (DENIABLE, VERIFIABLE):
			raise ValueError("invalid mode")
		if peer_id not in self._sessions:
			self.start_session(peer_id)

		session = self._sessions[peer_id]
		header_extra = self._pending_headers.pop(peer_id, None)

		msg = construct_outgoing_message(
			sender_id=self.user_id,
			receiver_id=peer_id,
			session=session,
			plaintext=text,
			mode=mode,
			signing_private_key=self.key_store.identity.sig_private,
			header_extra=header_extra,
		)

		if header_extra and header_extra.get("opk_id"):
			try:
				self.server.mark_one_time_prekey_used(str(header_extra["opk_id"]))
			except Exception:
				pass

		return msg.to_dict()

	def receive_message(self, message_dict: dict[str, Any]) -> str:
		msg = Message.from_dict(message_dict)
		sender_id = str(msg.header.get("sender_id"))
		if not sender_id:
			raise ValueError("missing sender_id")

		if sender_id not in self._sessions:
			session = accept_session(self, msg.header, msg.ephemeral_pub)
			try:
				prekeys_resp = self.server.fetch_prekeys(sender_id)
				rp = parse_receiver_prekeys(prekeys_resp)
				session.peer_sig_public = rp.identity_sig_public
			except Exception:
				session.peer_sig_public = None
			session.peer_id = sender_id
			session.deniability.reveal_interval = self.mac_reveal_interval
			self._sessions[sender_id] = session

		session = self._sessions[sender_id]
		plaintext = process_incoming_message(
			receiver_id=self.user_id,
			session=session,
			message_dict=message_dict,
			peer_sig_public=session.peer_sig_public,
		)
		return plaintext


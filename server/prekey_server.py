"""Prekey distribution service.

Implements a minimal HTTP API:
- GET    /prekeys/{user_id}
- POST   /prekeys
- DELETE /prekeys/{opk_id}

Server stores PUBLIC keys only.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple
from urllib.parse import unquote, urlparse

from utils.conversions import require_fields, utc_timestamp


@dataclass
class _UserPrekeyRecord:
	identity_key: dict
	signed_prekey: dict
	one_time_prekeys: dict[str, dict]


class PrekeyServerStore:
	"""In-memory store for public prekeys."""

	def __init__(self) -> None:
		self._lock = threading.Lock()
		self._users: Dict[str, _UserPrekeyRecord] = {}
		self._opk_to_user: Dict[str, str] = {}

	def upload_prekeys(self, bundle: dict[str, Any]) -> None:
		require_fields(bundle, ["user_id", "identity_key", "signed_prekey"])
		user_id = str(bundle["user_id"])
		identity_key = bundle["identity_key"]
		signed_prekey = bundle["signed_prekey"]
		one_time_prekeys = bundle.get("one_time_prekeys", [])

		if not isinstance(identity_key, dict) or not isinstance(signed_prekey, dict):
			raise ValueError("identity_key and signed_prekey must be objects")

		with self._lock:
			record = self._users.get(user_id)
			if record is None:
				record = _UserPrekeyRecord(
					identity_key=identity_key,
					signed_prekey=signed_prekey,
					one_time_prekeys={},
				)
				self._users[user_id] = record
			else:
				record.identity_key = identity_key
				record.signed_prekey = signed_prekey

			if one_time_prekeys is not None:
				if not isinstance(one_time_prekeys, list):
					raise ValueError("one_time_prekeys must be a list")
				for opk in one_time_prekeys:
					if not isinstance(opk, dict):
						continue
					if "id" not in opk or "public" not in opk:
						continue
					opk_id = str(opk["id"])
					record.one_time_prekeys[opk_id] = {
						"id": opk_id,
						"public": opk["public"],
						"used": False,
						"uploaded_at": utc_timestamp(),
					}
					self._opk_to_user[opk_id] = user_id

	def get_prekeys(self, user_id: str) -> dict[str, Any]:
		with self._lock:
			if user_id not in self._users:
				raise KeyError("unknown user")
			record = self._users[user_id]

			selected_opk: Optional[dict[str, Any]] = None
			for opk in record.one_time_prekeys.values():
				if not opk.get("used"):
					selected_opk = {"id": opk["id"], "public": opk["public"]}
					break

			return {
				"user_id": user_id,
				"identity_key": record.identity_key,
				"signed_prekey": record.signed_prekey,
				"one_time_prekey": selected_opk,
			}

	def mark_opk_used(self, opk_id: str) -> bool:
		with self._lock:
			user_id = self._opk_to_user.get(opk_id)
			if user_id is None:
				return False
			record = self._users.get(user_id)
			if record is None:
				return False
			opk = record.one_time_prekeys.get(opk_id)
			if opk is None:
				return False
			opk["used"] = True
			opk["used_at"] = utc_timestamp()
			return True


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
	data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
	handler.send_response(status)
	handler.send_header("Content-Type", "application/json")
	handler.send_header("Content-Length", str(len(data)))
	handler.end_headers()
	handler.wfile.write(data)


class _PrekeyHandler(BaseHTTPRequestHandler):
	store: PrekeyServerStore

	def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
		return

	def _read_json(self) -> Tuple[Optional[dict[str, Any]], Optional[str]]:
		length = int(self.headers.get("Content-Length", "0"))
		if length <= 0:
			return None, "missing body"
		body = self.rfile.read(length)
		try:
			obj = json.loads(body.decode("utf-8"))
		except Exception:
			return None, "invalid json"
		if not isinstance(obj, dict):
			return None, "json must be object"
		return obj, None

	def do_POST(self) -> None:  # noqa: N802
		parsed = urlparse(self.path)
		if parsed.path != "/prekeys":
			_json_response(self, 404, {"ok": False, "error": "not found"})
			return
		obj, err = self._read_json()
		if err is not None:
			_json_response(self, 400, {"ok": False, "error": err})
			return
		try:
			self.store.upload_prekeys(obj)
		except Exception as exc:
			_json_response(self, 400, {"ok": False, "error": str(exc)})
			return
		_json_response(self, 200, {"ok": True})

	def do_GET(self) -> None:  # noqa: N802
		parsed = urlparse(self.path)
		if not parsed.path.startswith("/prekeys/"):
			_json_response(self, 404, {"ok": False, "error": "not found"})
			return
		user_id = unquote(parsed.path[len("/prekeys/") :])
		if not user_id:
			_json_response(self, 400, {"ok": False, "error": "missing user_id"})
			return
		try:
			payload = self.store.get_prekeys(user_id)
		except KeyError:
			_json_response(self, 404, {"ok": False, "error": "unknown user"})
			return
		_json_response(self, 200, {"ok": True, "prekeys": payload})

	def do_DELETE(self) -> None:  # noqa: N802
		parsed = urlparse(self.path)
		if not parsed.path.startswith("/prekeys/"):
			_json_response(self, 404, {"ok": False, "error": "not found"})
			return
		opk_id = unquote(parsed.path[len("/prekeys/") :])
		if not opk_id:
			_json_response(self, 400, {"ok": False, "error": "missing opk_id"})
			return
		ok = self.store.mark_opk_used(opk_id)
		if not ok:
			_json_response(self, 404, {"ok": False, "error": "unknown opk_id"})
			return
		_json_response(self, 200, {"ok": True})


def run_prekey_server(
	*,
	host: str = "127.0.0.1",
	port: int = 8080,
	store: Optional[PrekeyServerStore] = None,
) -> ThreadingHTTPServer:
	"""Run a Threading HTTP server. Returns the server instance."""

	srv_store = PrekeyServerStore() if store is None else store

	class Handler(_PrekeyHandler):
		store = srv_store

	httpd = ThreadingHTTPServer((host, port), Handler)
	httpd.serve_forever()
	return httpd


def start_prekey_server_in_thread(
	*,
	host: str = "127.0.0.1",
	port: int = 8080,
	store: Optional[PrekeyServerStore] = None,
	daemon: bool = True,
) -> Tuple[threading.Thread, PrekeyServerStore]:
	srv_store = PrekeyServerStore() if store is None else store

	def _run() -> None:
		run_prekey_server(host=host, port=port, store=srv_store)

	t = threading.Thread(target=_run, daemon=daemon)
	t.start()
	return t, srv_store


if __name__ == "__main__":
	run_prekey_server()


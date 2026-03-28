"""CLI demo for OTR++.

Run from repo root:
	python -m client.demo_chat
"""

from __future__ import annotations

import json
import os
import socket
import sys
import time


def _ensure_project_root_on_path() -> None:
	here = os.path.abspath(os.path.dirname(__file__))
	root = os.path.dirname(here)
	if root not in sys.path:
		sys.path.insert(0, root)


_ensure_project_root_on_path()

from client.client import Client  # noqa: E402
from protocol.deniability import DENIABLE, VERIFIABLE  # noqa: E402
from server.prekey_server import start_prekey_server_in_thread  # noqa: E402


def _pick_free_port() -> int:
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.bind(("127.0.0.1", 0))
		return int(s.getsockname()[1])


def main() -> None:
	host = "127.0.0.1"
	port = _pick_free_port()

	start_prekey_server_in_thread(host=host, port=port)
	server_url = f"http://{host}:{port}"

	alice = Client(user_id="alice", server_url=server_url, mac_reveal_interval=3, dh_rotate_interval=4)
	bob = Client(user_id="bob", server_url=server_url, mac_reveal_interval=3, dh_rotate_interval=4)

	alice.publish_prekeys()
	bob.publish_prekeys()

	time.sleep(0.1)

	print("OTR++-AD Demo")
	print("Server:", server_url)
	print()

	while True:
		print("Choose message mode:")
		print("[1] Deniable Message")
		print("[2] Verifiable Message")
		print("[q] Quit")
		choice = input("> ").strip().lower()
		if choice in {"q", "quit", "exit"}:
			break
		if choice not in {"1", "2"}:
			print("Invalid choice.\n")
			continue

		mode = DENIABLE if choice == "1" else VERIFIABLE
		text = input("Message text: ").rstrip("\n")

		msg_dict = alice.send_message(peer_id="bob", text=text, mode=mode)

		print("\nRaw message structure:")
		print(json.dumps(msg_dict, indent=2, ensure_ascii=False))
		print("Mode used:", "DENIABLE" if mode == DENIABLE else "VERIFIABLE")

		try:
			received = bob.receive_message(msg_dict)
			print("Bob received:", received)
		except Exception as exc:
			print("Bob rejected message:", str(exc))

		print()


if __name__ == "__main__":
	main()


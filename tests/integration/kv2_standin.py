"""A minimal HashiCorp Vault KV-v2 stand-in for the real ``hvac`` client.

The container-backed suites drive a real Vault on ``:8200``; this stand-in lets
the key-reuse end-to-end tests run the real ``envdrift`` CLI (and so the real
``hvac`` client inside it) without containers. It serves only what envdrift's
``HashiCorpVaultClient`` calls: the token lookup that ``is_authenticated()``
performs and the KV-v2 ``data`` endpoint (read, create/update). Secrets live in
memory, so a test can seed a vault key and read back what the CLI pushed.

The vault itself is the only thing faked: encryption, decryption and every key
file stay with the real ``dotenvx`` binary and the real CLI.
"""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

TOKEN = "standin-" + "root-token"  # a fake token for a local stand-in


class KV2StandIn:
    """Serve a token-checked KV-v2 mount on ``127.0.0.1`` from a daemon thread."""

    def __init__(self, *, token: str = TOKEN, mount: str = "secret") -> None:
        self.token = token
        self.mount = mount
        self._data: dict[str, dict[str, Any]] = {}
        self._versions: dict[str, int] = {}
        self._lock = threading.Lock()
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler_class())
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        """The ``http://127.0.0.1:<port>`` address to put in ``[vault.hashicorp]``."""
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def put(self, path: str, data: dict[str, Any]) -> None:
        """Store ``data`` at ``path`` as a new version."""
        with self._lock:
            self._data[path] = dict(data)
            self._versions[path] = self._versions.get(path, 0) + 1

    def get(self, path: str) -> dict[str, Any] | None:
        """Return the stored data at ``path``, or ``None``."""
        with self._lock:
            stored = self._data.get(path)
            return dict(stored) if stored is not None else None

    def __enter__(self) -> KV2StandIn:
        self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    def version(self, path: str) -> int:
        """The version number of the data stored at ``path``."""
        with self._lock:
            return self._versions[path]

    def _handler_class(self) -> type[BaseHTTPRequestHandler]:
        """A handler class bound to this stand-in (the server makes one per request)."""
        standin = self

        class Handler(_KV2Handler):
            pass

        Handler.standin = standin
        return Handler


class _KV2Handler(BaseHTTPRequestHandler):
    """The token lookup and the KV-v2 ``data`` endpoint, for ``standin``."""

    standin: KV2StandIn

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _reply(self, status: int, body: dict[str, Any]) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _secret_path(self) -> str | None:
        prefix = f"/v1/{self.standin.mount}/data/"
        path = urlparse(self.path).path
        return path[len(prefix) :] if path.startswith(prefix) else None

    def _authorized(self) -> bool:
        if self.headers.get("X-Vault-Token") == self.standin.token:
            return True
        self._reply(403, {"errors": ["permission denied"]})
        return False

    def do_GET(self) -> None:
        if not self._authorized():
            return
        if urlparse(self.path).path == "/v1/auth/token/lookup-self":
            self._reply(200, {"data": {"id": self.standin.token, "policies": ["root"]}})
            return
        name = self._secret_path()
        stored = self.standin.get(name) if name else None
        if name is None or stored is None:
            self._reply(404, {"errors": []})
            return
        metadata = {
            "version": self.standin.version(name),
            "created_time": datetime.now(UTC).isoformat(),
            "deletion_time": "",
            "destroyed": False,
            "custom_metadata": None,
        }
        self._reply(200, {"data": {"data": stored, "metadata": metadata}})

    def _write(self) -> None:
        if not self._authorized():
            return
        name = self._secret_path()
        if name is None:
            self._reply(404, {"errors": []})
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        self.standin.put(name, body.get("data", {}))
        created = datetime.now(UTC).isoformat()
        self._reply(200, {"data": {"version": self.standin.version(name), "created_time": created}})

    def do_POST(self) -> None:
        self._write()

    def do_PUT(self) -> None:
        self._write()

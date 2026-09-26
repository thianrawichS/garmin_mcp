"""Keep Garmin OAuth tokens alive on hosts whose disk is wiped on restart.

Why this exists
---------------
Garmin's DI OAuth access token lives about 24 hours. Every refresh returns a
*new* refresh token and invalidates the previous one. garminconnect writes the
refreshed pair to ``garmin_tokens.json`` - but on a host with an ephemeral
filesystem (Render's free tier spins down after 15 idle minutes, and every
deploy starts from a clean disk) that file is lost. The next start then replays
the original, already-spent refresh token (for example from
``GARMIN_TOKENS_B64``) and login fails, roughly a day after every manual
re-auth.

What it does
------------
* Mirrors the token file to a durable key-value store (Upstash Redis, over its
  REST API) every time garminconnect writes it.
* On startup, keeps whichever copy - local file or store - holds the newest
  access token, so a restart resumes from the latest refresh.
* If a refresh fails at runtime, adopts newer tokens from the store (e.g. ones
  pushed with ``garmin-mcp-auth --push-to-store``) without a restart.
* Serialises token refreshes across threads. garminconnect 0.3.2 has no lock
  around its refresh, so parallel tool calls near expiry could each spend the
  same single-use refresh token.

The store is enabled only when ``UPSTASH_REDIS_REST_URL`` and
``UPSTASH_REDIS_REST_TOKEN`` are set. ``GARMIN_TOKENS_STORE_KEY`` picks the key
(default ``garmin-mcp:tokens``) - use one key per Garmin account.
"""

from __future__ import annotations

import base64
import contextlib
import json
import math
import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Mapping

import requests

DEFAULT_STORE_KEY = "garmin-mcp:tokens"
TOKEN_FILE_NAME = "garmin_tokens.json"


class TokenStoreError(RuntimeError):
    """The token store could not be read or written."""


def _log(message: str) -> None:
    """Write one status line to the real stderr.

    ``sys.__stderr__`` because init_api() swaps ``sys.stderr`` for a StringIO
    while logging in, and these lines should still reach the host's logs.
    Token values are never logged.
    """
    stream = sys.__stderr__ or sys.stderr
    with contextlib.suppress(Exception):
        print(f"[token-store] {message}", file=stream, flush=True)


def _fmt(timestamp: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(timestamp))


# --------------------------------------------------------------------------
# Token file helpers
# --------------------------------------------------------------------------


def _jwt_exp(token: Any) -> float:
    """Return the ``exp`` claim of an unverified JWT, or 0.0 if unavailable."""
    if not token or not isinstance(token, str):
        return 0.0
    parts = token.split(".")
    if len(parts) < 2:
        return 0.0
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
        raw = payload.get("exp")
        if isinstance(raw, bool):
            return 0.0
        exp = float(raw)
    except Exception:
        return 0.0
    return exp if math.isfinite(exp) and exp > 0 else 0.0


def token_freshness(token_json: str | None) -> float:
    """Expiry time of the access token in a ``garmin_tokens.json`` payload.

    Every access token lives the same ~24h, so a later expiry means a more
    recently issued (or refreshed) token. Returns 0.0 for anything unusable,
    including payloads without a refresh token.
    """
    if not token_json:
        return 0.0
    try:
        data = json.loads(token_json)
    except (TypeError, ValueError):
        return 0.0
    if not isinstance(data, dict) or not data.get("di_refresh_token"):
        return 0.0
    return _jwt_exp(data.get("di_token"))


def token_file(token_path: str) -> Path:
    """Where garminconnect keeps the token JSON for a given tokenstore path."""
    path = Path(token_path).expanduser()
    if path.is_dir() or not path.name.endswith(".json"):
        path = path / TOKEN_FILE_NAME
    return path


def _write_private(path: Path, text: str) -> None:
    """Atomically write ``text`` to ``path`` with owner-only permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(path.parent, 0o700)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        with contextlib.suppress(OSError):
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


# --------------------------------------------------------------------------
# Upstash Redis REST client (one key)
# --------------------------------------------------------------------------


class UpstashStore:
    """Reads and writes one key in Upstash Redis through its REST API."""

    def __init__(
        self,
        url: str,
        token: str,
        key: str = DEFAULT_STORE_KEY,
        timeout: float = 5.0,
        attempts: int = 2,
    ) -> None:
        self.url = url.rstrip("/")
        self._token = token
        self.key = key
        self.timeout = timeout
        self.attempts = max(1, attempts)

    def __repr__(self) -> str:  # never include the REST token
        return f"UpstashStore(url={self.url!r}, key={self.key!r})"

    def _command(self, *args: str) -> Any:
        last_error: TokenStoreError | None = None
        for attempt in range(self.attempts):
            if attempt:
                time.sleep(0.5)
            try:
                resp = requests.post(
                    self.url,
                    json=list(args),
                    headers={"Authorization": f"Bearer {self._token}"},
                    timeout=self.timeout,
                )
            except requests.RequestException as exc:
                last_error = TokenStoreError(
                    f"cannot reach the token store ({exc.__class__.__name__})"
                )
                continue
            if resp.status_code >= 500:
                last_error = TokenStoreError(
                    f"token store returned HTTP {resp.status_code}"
                )
                continue
            try:
                body = resp.json()
            except ValueError:
                body = None
            if resp.status_code != 200 or not isinstance(body, dict) or "error" in body:
                detail = body.get("error") if isinstance(body, dict) else None
                suffix = f": {detail}" if detail else ""
                raise TokenStoreError(
                    f"token store rejected {args[0]} (HTTP {resp.status_code}{suffix})"
                )
            return body.get("result")
        assert last_error is not None
        raise last_error

    def get(self) -> str | None:
        result = self._command("GET", self.key)
        return result if isinstance(result, str) else None

    def set(self, value: str) -> None:
        self._command("SET", self.key, value)


def _clean(value: str | None) -> str:
    """Trim whitespace and one layer of quotes (values copied from a .env)."""
    value = (value or "").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1].strip()
    return value


def store_from_env(environ: Mapping[str, str] | None = None) -> UpstashStore | None:
    """Build the store from environment variables, or None if not configured."""
    env = os.environ if environ is None else environ
    url = _clean(env.get("UPSTASH_REDIS_REST_URL"))
    token = _clean(env.get("UPSTASH_REDIS_REST_TOKEN"))
    if not url and not token:
        return None
    if not url or not token:
        _log(
            "UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN must both be set; "
            "token store disabled."
        )
        return None
    key = _clean(env.get("GARMIN_TOKENS_STORE_KEY")) or DEFAULT_STORE_KEY
    return UpstashStore(url, token, key)


# --------------------------------------------------------------------------
# Startup reconciliation
# --------------------------------------------------------------------------


def sync_from_store(token_path: str, store: UpstashStore) -> str:
    """Reconcile the local token file with the store before login.

    Keeps whichever copy has the newest access token:

    * store newer - overwrite the local file (the usual case after a restart,
      when the local file is the stale ``GARMIN_TOKENS_B64`` snapshot);
    * local newer - push it to the store (first run, or a fresh manual
      re-auth deployed through ``GARMIN_TOKENS_B64``).

    Never raises: if the store is unreachable, login proceeds with the local
    file. Returns a short status string for logs and tests.
    """
    path = token_file(token_path)
    try:
        local = path.read_text(encoding="utf-8") if path.is_file() else None
    except OSError:
        local = None

    try:
        remote = store.get()
    except Exception as exc:  # never let the store break login
        _log(f"could not read tokens from the store ({exc}); using local tokens.")
        return "store-unavailable"

    local_exp = token_freshness(local)
    remote_exp = token_freshness(remote)

    if remote_exp > local_exp:
        try:
            _write_private(path, remote)  # type: ignore[arg-type]
        except OSError as exc:
            _log(f"could not write {path}: {exc}")
            return "write-failed"
        _log(
            f"restored tokens from the store (key '{store.key}', access token "
            f"valid until {_fmt(remote_exp)})."
        )
        return "restored"

    if local_exp > remote_exp:
        try:
            store.set(local)  # type: ignore[arg-type]
        except Exception as exc:  # never let the store break login
            _log(f"could not save local tokens to the store: {exc}")
            return "store-unavailable"
        _log(f"saved local tokens to the store (key '{store.key}').")
        return "pushed"

    if local_exp == 0:
        _log("no usable Garmin tokens locally or in the store.")
        return "empty"
    return "in-sync"


# --------------------------------------------------------------------------
# garminconnect hooks
# --------------------------------------------------------------------------

_install_lock = threading.Lock()
_refresh_lock = threading.RLock()
_state: dict[str, Any] = {
    "store": None,
    "installed": False,
    "orig_dump": None,
    "orig_refresh": None,
}


def _mirror_to_store(client: Any) -> None:
    store = _state["store"]
    if store is None:
        return
    try:
        payload = client.dumps()
    except Exception:
        return
    exp = token_freshness(payload)
    if exp <= 0:
        return
    try:
        store.set(payload)
    except Exception as exc:  # never let the store break login
        _log(f"could not save refreshed tokens to the store: {exc}")
        return
    _log(f"saved new tokens to the store (access token valid until {_fmt(exp)}).")


def _dump_and_mirror(self: Any, path: str) -> None:
    """Replacement for Client.dump: write the file as before, then mirror it."""
    _state["orig_dump"](self, path)
    _mirror_to_store(self)


def _adopt_newer_from_store(client: Any) -> bool:
    """After a failed refresh, switch to newer tokens from the store if any."""
    store = _state["store"]
    if store is None:
        return False
    try:
        remote = store.get()
    except Exception as exc:  # never let the store break login
        _log(f"token refresh failed and the store is unreachable: {exc}")
        return False
    if token_freshness(remote) <= token_freshness(client.dumps()):
        _log(
            "token refresh failed and the store has nothing newer. "
            "Re-authenticate with: garmin-mcp-auth --force-reauth --push-to-store"
        )
        return False
    try:
        client.loads(remote)
    except Exception:
        _log("token refresh failed and the tokens in the store are unreadable.")
        return False
    path = getattr(client, "_tokenstore_path", None)
    if path:
        with contextlib.suppress(Exception):
            _state["orig_dump"](client, path)  # local copy only; already in store
    _log("token refresh failed; switched to newer tokens from the store.")
    return True


def _serialised_refresh(self: Any) -> None:
    """Replacement for Client._refresh_session.

    Runs one refresh at a time, skips a refresh another thread already did,
    and falls back to the store when a refresh fails.
    """
    original = _state["orig_refresh"]

    if getattr(self, "_token_lock", None) is not None:
        # Newer garminconnect releases lock refreshes themselves. Stacking a
        # second lock on top could deadlock, so only add the store fallback.
        before = self.di_token
        original(self)
        if before and self.di_token == before:
            _adopt_newer_from_store(self)
        return

    seen = self.di_token
    with _refresh_lock:
        if seen and self.di_token != seen:
            return  # another thread refreshed while this one waited
        original(self)
        # A successful refresh always issues a new access token, so an
        # unchanged one means the (swallowed) refresh failed.
        if seen and self.di_token == seen:
            _adopt_newer_from_store(self)


def install(store: UpstashStore | None) -> bool:
    """Hook garminconnect's Client so token writes also reach ``store``.

    Idempotent - a later call only swaps the store. With ``store=None`` only
    the refresh serialisation is active. Returns False if the library's
    internals don't look as expected (nothing is patched then).
    """
    from garminconnect.client import Client

    with _install_lock:
        _state["store"] = store
        if _state["installed"]:
            return True
        orig_dump = getattr(Client, "dump", None)
        orig_refresh = getattr(Client, "_refresh_session", None)
        if not callable(orig_dump) or not callable(orig_refresh):
            _log("unexpected garminconnect version; token persistence not installed.")
            return False
        _state.update(orig_dump=orig_dump, orig_refresh=orig_refresh, installed=True)
        Client.dump = _dump_and_mirror
        Client._refresh_session = _serialised_refresh
        return True


def uninstall() -> None:
    """Restore garminconnect's original methods (used by tests)."""
    from garminconnect.client import Client

    with _install_lock:
        if _state["installed"]:
            Client.dump = _state["orig_dump"]
            Client._refresh_session = _state["orig_refresh"]
        _state.update(store=None, installed=False, orig_dump=None, orig_refresh=None)

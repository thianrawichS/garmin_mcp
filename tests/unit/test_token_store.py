"""Tests for token_store: keeping Garmin tokens alive across restarts.

The simulation tests run garminconnect's real Client against a fake Garmin
backend that behaves like the DI OAuth service: access tokens last 24h and
every refresh issues a new refresh token while invalidating the old one.
"""

import base64
import json
import os
import stat
import threading
import time
from unittest.mock import Mock, patch

import pytest
import requests
from garminconnect import (
    Garmin,
    GarminConnectAuthenticationError,
    GarminConnectConnectionError,
)
from garminconnect.client import Client

from garmin_mcp import token_store
from garmin_mcp.token_store import TokenStoreError, UpstashStore

STORE_URL = "https://fake-store.upstash.io"
STORE_TOKEN = "secret-rest-token"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body
        self.text = json.dumps(body)
        self.content = self.text.encode()

    @property
    def ok(self):
        return self.status_code < 400

    def json(self):
        return self._body


class FakeUpstash:
    """Stands in for requests.post against the Upstash REST API."""

    def __init__(self):
        self.data = {}
        self.mode = "up"  # up | down | error500 | unauthorized
        self.calls = []

    def __call__(self, url, json=None, headers=None, timeout=None):
        self.calls.append(list(json or []))
        if self.mode == "down":
            raise requests.ConnectionError("store unreachable")
        if self.mode == "error500":
            return FakeResponse(500, {"error": "internal"})
        if url != STORE_URL or (headers or {}).get("Authorization") != f"Bearer {STORE_TOKEN}":
            return FakeResponse(401, {"error": "Unauthorized"})
        if self.mode == "unauthorized":
            return FakeResponse(401, {"error": "Unauthorized"})
        command = json[0].upper()
        if command == "GET":
            return FakeResponse(200, {"result": self.data.get(json[1])})
        if command == "SET":
            self.data[json[1]] = json[2]
            return FakeResponse(200, {"result": "OK"})
        return FakeResponse(400, {"error": f"ERR unknown command {command}"})


class FakeClock:
    def __init__(self):
        self.now = 1_900_000_000.0

    def time(self):
        return self.now

    def advance(self, hours):
        self.now += hours * 3600


def _b64(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def make_jwt(payload):
    return f"{_b64({'alg': 'none'})}.{_b64(payload)}.sig"


def token_json(exp, refresh="rt-x"):
    return json.dumps(
        {
            "di_token": make_jwt({"exp": exp, "client_id": "CID"}),
            "di_refresh_token": refresh,
            "di_client_id": "CID",
        }
    )


class FakeGarminBackend:
    """Garmin's DI OAuth + Connect API, as far as token handling goes."""

    CLIENT_ID = "GARMIN_CONNECT_MOBILE_ANDROID_DI_2025Q2"

    def __init__(self, clock, refresh_latency=0.0):
        self.clock = clock
        self.refresh_latency = refresh_latency
        self.valid_refresh_tokens = set()
        self.access_tokens = {}  # token -> expiry
        self.refresh_calls = 0
        self.failed_refreshes = 0
        self._counter = 0
        self._lock = threading.Lock()

    def issue(self):
        with self._lock:
            self._counter += 1
            n = self._counter
            exp = self.clock.time() + 86400
            access = make_jwt({"exp": exp, "client_id": self.CLIENT_ID, "n": n})
            refresh = f"rt-{n}"
            self.access_tokens[access] = exp
            self.valid_refresh_tokens.add(refresh)
        return {"di_token": access, "di_refresh_token": refresh, "di_client_id": self.CLIENT_ID}

    def fresh_login(self):
        """What `garmin-mcp-auth` saves: a brand-new token lineage."""
        return json.dumps(self.issue())

    def http_post(self, _client, url, **kwargs):
        data = kwargs.get("data") or {}
        assert data.get("grant_type") == "refresh_token", url
        if self.refresh_latency:
            threading.Event().wait(self.refresh_latency)
        with self._lock:
            self.refresh_calls += 1
            spent = data.get("refresh_token")
            valid = spent in self.valid_refresh_tokens
            # Single use: the presented refresh token dies either way.
            self.valid_refresh_tokens.discard(spent)
            if not valid:
                self.failed_refreshes += 1
        if not valid:
            return FakeResponse(400, {"error": "invalid_grant"})
        tokens = self.issue()
        return FakeResponse(
            200,
            {
                "access_token": tokens["di_token"],
                "refresh_token": tokens["di_refresh_token"],
                "expires_in": 86400,
            },
        )

    def api_session(self, _client):
        backend = self

        class Session:
            def request(self, method, url, headers=None, **kwargs):
                bearer = (headers or {}).get("Authorization", "").replace("Bearer ", "", 1)
                exp = backend.access_tokens.get(bearer)
                if exp is None or backend.clock.time() >= exp:
                    return FakeResponse(401, {"message": "Unauthorized"})
                if url.endswith("/userprofile-service/socialProfile"):
                    return FakeResponse(200, {"displayName": "tester", "fullName": "Test User"})
                if url.endswith("/userprofile-service/userprofile/user-settings"):
                    return FakeResponse(200, {"userData": {"measurementSystem": "metric"}})
                return FakeResponse(200, {"ok": True})

        return Session()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clean_install():
    token_store.uninstall()
    yield
    token_store.uninstall()


@pytest.fixture
def upstash(monkeypatch):
    fake = FakeUpstash()
    monkeypatch.setattr(token_store.requests, "post", fake)
    monkeypatch.setattr(token_store.time, "sleep", lambda _s: None)
    return fake


@pytest.fixture
def store(upstash):
    return UpstashStore(STORE_URL, STORE_TOKEN, key="garmin-mcp:tokens")


@pytest.fixture
def clock(monkeypatch):
    fake = FakeClock()
    monkeypatch.setattr(time, "time", fake.time)
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    return fake


@pytest.fixture
def backend(monkeypatch, clock):
    fake = FakeGarminBackend(clock)
    monkeypatch.setattr(Client, "_http_post", lambda self, url, **kw: fake.http_post(self, url, **kw))
    monkeypatch.setattr(Client, "_fresh_api_session", lambda self: fake.api_session(self))
    return fake


def start_container(tmp_path, name, snapshot, store=None):
    """One Render start: clean disk, entrypoint restores the env snapshot, login."""
    token_dir = tmp_path / name
    token_dir.mkdir()
    (token_dir / "garmin_tokens.json").write_text(snapshot)
    token_store.install(store)
    if store is not None:
        token_store.sync_from_store(str(token_dir), store)
    garmin = Garmin()
    garmin.login(str(token_dir))
    return garmin


# ---------------------------------------------------------------------------
# The bug, and the fix, end to end
# ---------------------------------------------------------------------------


class TestRestartCycle:
    def test_replaying_the_snapshot_fails_after_the_first_refresh(self, tmp_path, backend, clock):
        """Reproduces the reported problem: re-auth needed about daily."""
        snapshot = backend.fresh_login()  # garmin-mcp-auth -> GARMIN_TOKENS_B64

        first = start_container(tmp_path, "c1", snapshot)
        assert first.client.connectapi("/x") == {"ok": True}

        clock.advance(24)  # next day: access token expired, refresh spends rt-1
        assert first.client.connectapi("/x") == {"ok": True}

        clock.advance(1)  # idle spin-down, next request cold-starts from the snapshot
        with pytest.raises((GarminConnectAuthenticationError, GarminConnectConnectionError)):
            start_container(tmp_path, "c2", snapshot)
        assert backend.failed_refreshes > 0

    def test_store_keeps_the_session_alive_across_restarts(self, tmp_path, backend, clock, store):
        snapshot = backend.fresh_login()

        first = start_container(tmp_path, "c1", snapshot, store)
        assert token_store.token_freshness(store.get()) > 0  # seeded from the snapshot
        assert first.client.connectapi("/x") == {"ok": True}

        # A month of daily use, each day on a fresh container that is only
        # ever given the original (long spent) snapshot.
        for day in range(2, 32):
            clock.advance(25)
            container = start_container(tmp_path, f"c{day}", snapshot, store)
            assert container.client.connectapi("/x") == {"ok": True}

        assert backend.failed_refreshes == 0
        assert backend.refresh_calls >= 30

    def test_restored_token_file_is_owner_only(self, tmp_path, backend, clock, store):
        snapshot = backend.fresh_login()
        first = start_container(tmp_path, "c1", snapshot, store)
        clock.advance(24)
        first.client.connectapi("/x")  # refresh -> newer tokens in the store
        clock.advance(1)

        assert token_store.sync_from_store(str(tmp_path / "c1"), store) == "in-sync"
        (tmp_path / "c2").mkdir()
        (tmp_path / "c2" / "garmin_tokens.json").write_text(snapshot)
        assert token_store.sync_from_store(str(tmp_path / "c2"), store) == "restored"

        mode = stat.S_IMODE(os.stat(tmp_path / "c2" / "garmin_tokens.json").st_mode)
        assert mode == 0o600

    def test_new_snapshot_after_manual_reauth_wins_over_the_store(self, tmp_path, backend, clock, store):
        old = backend.fresh_login()
        start_container(tmp_path, "c1", old, store).client.connectapi("/x")

        backend.valid_refresh_tokens.clear()  # e.g. password change kills the session
        clock.advance(30)
        new_snapshot = backend.fresh_login()  # user re-auths and updates GARMIN_TOKENS_B64

        container = start_container(tmp_path, "c2", new_snapshot, store)
        assert container.client.connectapi("/x") == {"ok": True}
        assert json.loads(store.get())["di_refresh_token"] == json.loads(new_snapshot)["di_refresh_token"]


class TestRuntimeRecovery:
    def test_failed_refresh_adopts_newer_tokens_pushed_to_the_store(self, tmp_path, backend, clock, store):
        server = start_container(tmp_path, "c1", backend.fresh_login(), store)

        backend.valid_refresh_tokens.clear()  # the server's session dies
        clock.advance(2)
        store.set(backend.fresh_login())  # garmin-mcp-auth --push-to-store
        clock.advance(23)  # server's access token now expired

        assert server.client.connectapi("/x") == {"ok": True}  # no restart needed
        local = (tmp_path / "c1" / "garmin_tokens.json").read_text()
        assert json.loads(local) == json.loads(store.get())

    def test_failed_refresh_without_newer_tokens_still_fails(self, tmp_path, backend, clock, store):
        server = start_container(tmp_path, "c1", backend.fresh_login(), store)
        backend.valid_refresh_tokens.clear()
        clock.advance(25)
        with pytest.raises(GarminConnectConnectionError):
            server.client.connectapi("/x")


class TestConcurrentRefresh:
    def _race(self, client, threads=8):
        barrier = threading.Barrier(threads)
        results, errors = [], []

        def call():
            barrier.wait()
            try:
                results.append(client.connectapi("/x"))
            except Exception as exc:  # pragma: no cover - reported below
                errors.append(exc)

        workers = [threading.Thread(target=call) for _ in range(threads)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(10)
        return results, errors

    def test_parallel_tool_calls_spend_the_refresh_token_once(self, tmp_path, backend, clock, store):
        backend.refresh_latency = 0.2
        server = start_container(tmp_path, "c1", backend.fresh_login(), store)
        clock.advance(23.9)  # inside the 15-minute proactive-refresh window

        results, errors = self._race(server.client)

        assert not errors
        assert results == [{"ok": True}] * 8
        assert backend.refresh_calls == 1
        assert backend.failed_refreshes == 0

    def test_without_the_lock_parallel_calls_reuse_the_refresh_token(self, tmp_path, backend, clock):
        """Documents the race in garminconnect 0.3.2 that install() closes."""
        if getattr(Client(), "_token_lock", None) is not None:
            pytest.skip("this garminconnect version serialises refreshes itself")
        backend.refresh_latency = 0.2
        snapshot = backend.fresh_login()
        token_dir = tmp_path / "raw"
        token_dir.mkdir()
        (token_dir / "garmin_tokens.json").write_text(snapshot)
        garmin = Garmin()
        garmin.login(str(token_dir))  # library as shipped, nothing installed
        clock.advance(23.9)

        self._race(garmin.client)

        assert backend.refresh_calls > 1
        assert backend.failed_refreshes >= 1


# ---------------------------------------------------------------------------
# Startup reconciliation
# ---------------------------------------------------------------------------


class TestSyncFromStore:
    def test_store_newer_overwrites_local(self, tmp_path, store):
        (tmp_path / "garmin_tokens.json").write_text(token_json(1000, "old"))
        store.set(token_json(2000, "new"))

        assert token_store.sync_from_store(str(tmp_path), store) == "restored"
        assert json.loads((tmp_path / "garmin_tokens.json").read_text())["di_refresh_token"] == "new"

    def test_local_newer_is_pushed(self, tmp_path, store):
        (tmp_path / "garmin_tokens.json").write_text(token_json(2000, "new"))
        store.set(token_json(1000, "old"))

        assert token_store.sync_from_store(str(tmp_path), store) == "pushed"
        assert json.loads(store.get())["di_refresh_token"] == "new"

    def test_empty_store_is_seeded(self, tmp_path, store):
        (tmp_path / "garmin_tokens.json").write_text(token_json(2000))
        assert token_store.sync_from_store(str(tmp_path), store) == "pushed"
        assert store.get() is not None

    def test_missing_local_dir_is_created_from_store(self, tmp_path, store):
        store.set(token_json(2000, "from-store"))
        token_dir = tmp_path / "not-yet"

        assert token_store.sync_from_store(str(token_dir), store) == "restored"
        assert json.loads((token_dir / "garmin_tokens.json").read_text())["di_refresh_token"] == "from-store"

    def test_unreachable_store_leaves_local_untouched(self, tmp_path, store, upstash):
        original = token_json(1000, "local")
        (tmp_path / "garmin_tokens.json").write_text(original)
        upstash.mode = "down"

        assert token_store.sync_from_store(str(tmp_path), store) == "store-unavailable"
        assert (tmp_path / "garmin_tokens.json").read_text() == original

    def test_nothing_anywhere(self, tmp_path, store):
        assert token_store.sync_from_store(str(tmp_path), store) == "empty"

    def test_same_tokens_do_nothing(self, tmp_path, store, upstash):
        payload = token_json(2000)
        (tmp_path / "garmin_tokens.json").write_text(payload)
        store.set(payload)
        upstash.calls.clear()

        assert token_store.sync_from_store(str(tmp_path), store) == "in-sync"
        assert upstash.calls == [["GET", "garmin-mcp:tokens"]]

    def test_garbage_in_store_is_ignored(self, tmp_path, store):
        (tmp_path / "garmin_tokens.json").write_text(token_json(1000, "local"))
        store.set("not json at all")

        assert token_store.sync_from_store(str(tmp_path), store) == "pushed"


class TestTokenFreshness:
    def test_reads_access_token_expiry(self):
        assert token_store.token_freshness(token_json(1234)) == 1234

    @pytest.mark.parametrize(
        "payload",
        [
            None,
            "",
            "{",
            "[]",
            json.dumps({"di_token": make_jwt({"exp": 5})}),  # no refresh token
            json.dumps({"di_token": "not-a-jwt", "di_refresh_token": "r"}),
            json.dumps({"di_token": make_jwt({"exp": "soon"}), "di_refresh_token": "r"}),
            json.dumps({"di_token": make_jwt({"exp": True}), "di_refresh_token": "r"}),
        ],
    )
    def test_unusable_payloads_score_zero(self, payload):
        assert token_store.token_freshness(payload) == 0.0


# ---------------------------------------------------------------------------
# Upstash client and configuration
# ---------------------------------------------------------------------------


class TestUpstashStore:
    def test_round_trip_uses_json_commands_and_bearer_token(self, store, upstash):
        store.set('{"a": "quoted \\" value"}')
        assert store.get() == '{"a": "quoted \\" value"}'
        assert upstash.calls[0] == ["SET", "garmin-mcp:tokens", '{"a": "quoted \\" value"}']

    def test_missing_key_is_none(self, store):
        assert store.get() is None

    def test_bad_credentials_fail_without_retry(self, store, upstash):
        upstash.mode = "unauthorized"
        with pytest.raises(TokenStoreError, match="401"):
            store.get()
        assert len(upstash.calls) == 1

    def test_server_errors_are_retried(self, store, upstash):
        upstash.mode = "error500"
        with pytest.raises(TokenStoreError, match="500"):
            store.set("x")
        assert len(upstash.calls) == 2

    def test_connection_errors_are_retried(self, store, upstash):
        upstash.mode = "down"
        with pytest.raises(TokenStoreError, match="cannot reach"):
            store.get()
        assert len(upstash.calls) == 2

    def test_repr_hides_the_rest_token(self, store):
        assert STORE_TOKEN not in repr(store)


class TestStoreFromEnv:
    def test_not_configured(self):
        assert token_store.store_from_env({}) is None

    def test_half_configured_is_disabled(self, capsys):
        assert token_store.store_from_env({"UPSTASH_REDIS_REST_URL": STORE_URL}) is None

    def test_values_pasted_with_quotes_are_cleaned(self):
        store = token_store.store_from_env(
            {
                "UPSTASH_REDIS_REST_URL": f'"{STORE_URL}/"',
                "UPSTASH_REDIS_REST_TOKEN": f"'{STORE_TOKEN}'",
            }
        )
        assert store.url == STORE_URL
        assert store._token == STORE_TOKEN
        assert store.key == "garmin-mcp:tokens"

    def test_custom_key_per_account(self):
        store = token_store.store_from_env(
            {
                "UPSTASH_REDIS_REST_URL": STORE_URL,
                "UPSTASH_REDIS_REST_TOKEN": STORE_TOKEN,
                "GARMIN_TOKENS_STORE_KEY": "garmin-mcp:tokens:mom",
            }
        )
        assert store.key == "garmin-mcp:tokens:mom"


# ---------------------------------------------------------------------------
# Wiring: init_api and the auth CLI
# ---------------------------------------------------------------------------


class TestInitApiWiring:
    def test_syncs_from_store_before_login(self, monkeypatch, upstash):
        import garmin_mcp

        order = []
        monkeypatch.setenv("UPSTASH_REDIS_REST_URL", STORE_URL)
        monkeypatch.setenv("UPSTASH_REDIS_REST_TOKEN", STORE_TOKEN)
        monkeypatch.setattr(
            garmin_mcp.token_store, "sync_from_store", lambda path, store: order.append(("sync", path))
        )
        fake_garmin = Mock()
        fake_garmin.login.side_effect = lambda path: order.append(("login", path))
        monkeypatch.setattr(garmin_mcp, "Garmin", lambda **_kw: fake_garmin)

        assert garmin_mcp.init_api(None, None) is fake_garmin
        assert [step for step, _ in order] == ["sync", "login"]
        assert order[0][1] == order[1][1] == garmin_mcp.tokenstore

    def test_without_store_config_nothing_is_synced(self, monkeypatch):
        import garmin_mcp

        monkeypatch.delenv("UPSTASH_REDIS_REST_URL", raising=False)
        monkeypatch.delenv("UPSTASH_REDIS_REST_TOKEN", raising=False)
        sync = Mock()
        monkeypatch.setattr(garmin_mcp.token_store, "sync_from_store", sync)
        monkeypatch.setattr(garmin_mcp, "Garmin", lambda **_kw: Mock())

        garmin_mcp.init_api(None, None)
        sync.assert_not_called()


class TestAuthCliPush:
    @pytest.fixture
    def store_env(self, monkeypatch, upstash):
        monkeypatch.setenv("UPSTASH_REDIS_REST_URL", STORE_URL)
        monkeypatch.setenv("UPSTASH_REDIS_REST_TOKEN", STORE_TOKEN)
        monkeypatch.delenv("GARMIN_TOKENS_STORE_KEY", raising=False)
        return upstash

    def test_push_saves_the_token_file(self, tmp_path, store_env):
        from garmin_mcp.auth_cli import push_tokens_to_store

        payload = token_json(2000, "pushed")
        (tmp_path / "garmin_tokens.json").write_text(payload)

        assert push_tokens_to_store(str(tmp_path)) is True
        assert store_env.data["garmin-mcp:tokens"] == payload

    def test_push_requires_store_config(self, tmp_path, monkeypatch):
        from garmin_mcp.auth_cli import push_tokens_to_store

        monkeypatch.delenv("UPSTASH_REDIS_REST_URL", raising=False)
        monkeypatch.delenv("UPSTASH_REDIS_REST_TOKEN", raising=False)
        (tmp_path / "garmin_tokens.json").write_text(token_json(2000))

        assert push_tokens_to_store(str(tmp_path)) is False

    def test_push_refuses_unusable_tokens(self, tmp_path, store_env):
        from garmin_mcp.auth_cli import push_tokens_to_store

        (tmp_path / "garmin_tokens.json").write_text("{}")
        assert push_tokens_to_store(str(tmp_path)) is False
        assert store_env.data == {}

    @patch("garmin_mcp.auth_cli.push_tokens_to_store", return_value=True)
    @patch("garmin_mcp.auth_cli.authenticate", return_value=True)
    def test_flag_pushes_after_successful_auth(self, mock_auth, mock_push):
        from garmin_mcp.auth_cli import main

        with patch("sys.argv", ["garmin-mcp-auth", "--token-path", "/t", "--push-to-store"]):
            with pytest.raises(SystemExit) as exc:
                main()
        assert exc.value.code == 0
        mock_push.assert_called_once()
        assert "/t" in mock_push.call_args[0][0]

    @patch("garmin_mcp.auth_cli.push_tokens_to_store")
    @patch("garmin_mcp.auth_cli.authenticate", return_value=False)
    def test_flag_skips_push_when_auth_fails(self, mock_auth, mock_push):
        from garmin_mcp.auth_cli import main

        with patch("sys.argv", ["garmin-mcp-auth", "--push-to-store"]):
            with pytest.raises(SystemExit) as exc:
                main()
        assert exc.value.code == 1
        mock_push.assert_not_called()

    @patch("garmin_mcp.auth_cli.push_tokens_to_store")
    @patch("garmin_mcp.auth_cli.authenticate", return_value=True)
    def test_no_flag_no_push(self, mock_auth, mock_push):
        from garmin_mcp.auth_cli import main

        with patch("sys.argv", ["garmin-mcp-auth"]):
            with pytest.raises(SystemExit):
                main()
        mock_push.assert_not_called()


class TestInstall:
    def test_install_is_idempotent_and_reversible(self, store):
        original_dump = Client.dump
        original_refresh = Client._refresh_session

        assert token_store.install(store) is True
        assert token_store.install(None) is True  # swaps the store only
        assert Client.dump is not original_dump

        token_store.uninstall()
        assert Client.dump is original_dump
        assert Client._refresh_session is original_refresh

    def test_dump_still_writes_when_store_is_down(self, tmp_path, store, upstash):
        token_store.install(store)
        upstash.mode = "down"
        client = Client()
        client.loads(token_json(time.time() + 3600))

        client.dump(str(tmp_path))  # must not raise
        assert (tmp_path / "garmin_tokens.json").exists()

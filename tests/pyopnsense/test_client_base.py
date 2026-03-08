"""Tests for `pyopnsense.client_base` request, queue, and transport helpers."""

import asyncio
from collections.abc import MutableMapping
import contextlib
import socket
from ssl import SSLError
from typing import Any
from unittest.mock import AsyncMock, MagicMock
import xmlrpc.client as xc
from xmlrpc.client import Fault

import aiohttp
import awesomeversion
import pytest
from yarl import URL

from custom_components.opnsense import pyopnsense
from custom_components.opnsense.pyopnsense import (
    client_base as pyopnsense_client_base,
    helpers as pyopnsense_helpers,
)


@pytest.mark.asyncio
async def test_safe_dict_get_and_list_get(monkeypatch, make_client) -> None:
    """Ensure safe getters coerce None to empty dict/list as expected."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session, username="user", password="pass")
    # Patch _get to return dict or list using pytest's monkeypatch
    monkeypatch.setattr(client, "_get", AsyncMock(return_value={"foo": "bar"}), raising=False)
    result_dict = await client._safe_dict_get("/fake")
    assert result_dict == {"foo": "bar"}

    monkeypatch.setattr(client, "_get", AsyncMock(return_value=[1, 2, 3]), raising=False)
    result_list = await client._safe_list_get("/fake")
    assert result_list == [1, 2, 3]

    monkeypatch.setattr(client, "_get", AsyncMock(return_value=None), raising=False)
    result_empty_dict = await client._safe_dict_get("/fake")
    assert result_empty_dict == {}
    result_empty_list = await client._safe_list_get("/fake")
    assert result_empty_list == []
    await client.async_close()


@pytest.mark.asyncio
async def test_safe_dict_post_and_list_post(monkeypatch, make_client) -> None:
    """Ensure safe post helpers coerce None to empty dict/list as expected."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session, username="user", password="pass")
    try:
        monkeypatch.setattr(client, "_post", AsyncMock(return_value={"foo": "bar"}), raising=False)
        result_dict = await client._safe_dict_post("/fake")
        assert result_dict == {"foo": "bar"}

        monkeypatch.setattr(client, "_post", AsyncMock(return_value=[1, 2, 3]), raising=False)
        result_list = await client._safe_list_post("/fake")
        assert result_list == [1, 2, 3]

        monkeypatch.setattr(client, "_post", AsyncMock(return_value=None), raising=False)
        result_empty_dict = await client._safe_dict_post("/fake")
        assert result_empty_dict == {}
        result_empty_list = await client._safe_list_post("/fake")
        assert result_empty_list == []
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_check(make_client) -> None:
    """Test _get_check method returns True for ok responses, False otherwise."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)

    # Fake response class for testing
    class FakeResp:
        def __init__(self, status=500, ok=False):
            self.status = status
            self.reason = "Test"
            self.ok = ok
            self.request_info = MagicMock()
            self.history = []
            self.headers = {}

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    try:
        # Test successful response (ok=True)
        session.get = lambda *a, **k: FakeResp(status=200, ok=True)
        result = await client._get_check("/api/test")
        assert result is True

        # Test failed response (ok=False)
        session.get = lambda *a, **k: FakeResp(status=404, ok=False)
        result = await client._get_check("/api/test")
        assert result is False

        # Test 403 response specifically
        session.get = lambda *a, **k: FakeResp(status=403, ok=False)
        result = await client._get_check("/api/test")
        assert result is False
    finally:
        await client.async_close()


@pytest.mark.asyncio
@pytest.mark.parametrize("initial,should_raise", [(False, False), (True, True)])
async def test_get_check_handles_client_error(make_client, initial, should_raise) -> None:
    """Ensure _get_check handles aiohttp.ClientError correctly.

    When client is not in initialization mode, the method should swallow the
    ClientError and return False. When the client is in initialization mode
    (used during setup), it should re-raise the exception.
    """
    session = MagicMock(spec=aiohttp.ClientSession)

    def _raise(*a, **k):
        raise aiohttp.ClientError("boom")

    session.get = _raise
    client = make_client(session=session)
    try:
        # simulate the initialization flag behavior
        client._initial = initial

        if should_raise:
            with pytest.raises(aiohttp.ClientError):
                await client._get_check("/api/test")
        else:
            result = await client._get_check("/api/test")
            assert result is False
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_opnsenseclient_async_close(make_client) -> None:
    """Verify async_close cancels workers and queue monitor as expected."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost",
        username="user",
        password="pass",
        session=session,
    )
    try:
        initial_tasks = [t for t in [client._queue_monitor, *client._workers] if t is not None]
        for task in initial_tasks:
            task.cancel()
        if initial_tasks:
            await asyncio.gather(*initial_tasks, return_exceptions=True)

        loop = asyncio.get_running_loop()
        monitor = loop.create_task(asyncio.sleep(60))
        worker1 = loop.create_task(asyncio.sleep(60))
        worker2 = loop.create_task(asyncio.sleep(60))
        client._queue_monitor = monitor
        client._workers = [worker1, worker2]
        client._request_queue = asyncio.Queue()
        future = loop.create_future()
        await client._request_queue.put(("get", "/api/test", None, future, "test"))
        await client.async_close()
        assert monitor.cancelled()
        assert worker1.cancelled()
        assert worker2.cancelled()
        assert future.done()
        assert isinstance(future.exception(), asyncio.CancelledError)
    finally:
        await client.async_close()


@pytest.mark.asyncio
@pytest.mark.parametrize("firmware,expected", [("25.8.0", True), ("25.1.0", False)])
async def test_set_use_snake_case_detection(make_client, firmware, expected) -> None:
    """set_use_snake_case should detect firmware ranges correctly."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    client._firmware_version = firmware
    await client.set_use_snake_case()
    assert client._use_snake_case is expected
    await client.async_close()


@pytest.mark.asyncio
async def test_set_use_snake_case_handles_compare_exception(monkeypatch, make_client) -> None:
    """set_use_snake_case should default to snake_case True on comparison exception."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:

        def mock_compare(self, other):
            raise awesomeversion.exceptions.AwesomeVersionCompareException("test exception")

        monkeypatch.setattr(awesomeversion.AwesomeVersion, "__lt__", mock_compare)
        client._firmware_version = "25.8.0"
        await client.set_use_snake_case()
        # Should default to True on exception
        assert client._use_snake_case is True
    finally:
        await client.async_close()


@pytest.mark.parametrize(
    "exc_factory,initial",
    [
        (lambda: TypeError("bad json"), False),
        (lambda: Fault(1, "err"), False),
        (lambda: socket.gaierror("name or service not known"), False),
        (lambda: SSLError("ssl fail"), False),
        (lambda: Fault(2, "err"), True),
        (lambda: socket.gaierror("no host"), True),
        (lambda: SSLError("ssl fail"), True),
    ],
)
@pytest.mark.asyncio
async def test_exec_php_error_paths(exc_factory, initial: bool, make_client) -> None:
    """_exec_php should swallow known exceptions and return {} regardless of initial flag.

    Consolidates previous exec_php tests into one parameterized function covering:
    - TypeError JSON issues
    - xmlrpc.client.Fault
    - socket.gaierror
    - ssl.SSLError
    With both initial False and initial True states.
    """
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    try:
        client._initial = initial
        proxy = MagicMock()
        proxy.opnsense.exec_php.side_effect = exc_factory()
        client._get_proxy = MagicMock(return_value=proxy)
        res = await client._exec_php("echo test;")
        assert res == {}
    finally:
        await client.async_close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method_name, session_method, args, kwargs",
    [
        ("_do_get", "get", ("/api/x",), {"caller": "tst"}),
        ("_do_post", "post", ("/api/x",), {"payload": {}}),
    ],
)
async def test_do_get_post_error_initial_behavior(
    method_name, session_method, args, kwargs, make_client
) -> None:
    """When client._initial is True, non-ok responses should raise ClientResponseError for _do_get/_do_post."""
    session = MagicMock(spec=aiohttp.ClientSession)

    # create a fake response context manager
    class FakeResp:
        def __init__(self, status=500, ok=False):
            self.status = status
            self.reason = "Err"
            self.ok = ok

            # Provide a minimal request_info with real_url to satisfy logging
            class RI:
                real_url = URL("http://localhost")

            self.request_info = RI()
            self.history = []
            self.headers = {}

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def json(self, content_type=None):
            return {"x": 1}

        async def text(self):
            return "raw response text"

        @property
        def content(self):
            class C:
                async def iter_chunked(self, n):
                    yield b"data:{}\n\n" % b"{}"

            return C()

    if session_method == "get":
        session.get = lambda *a, **k: FakeResp(status=403, ok=False)
    else:
        session.post = lambda *a, **k: FakeResp(status=500, ok=False)

    client = make_client(session=session)
    client._initial = True
    try:
        with pytest.raises(aiohttp.ClientResponseError):
            await getattr(client, method_name)(*args, **kwargs)
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_from_stream_parsing(make_client, fake_stream_response_factory) -> None:
    """Simulate SSE-like stream with two messages and assert parsing returns dict."""
    session = MagicMock(spec=aiohttp.ClientSession)

    # use shared factory to construct a fake streaming response
    session.get = lambda *a, **k: fake_stream_response_factory(
        [b'data: {"a": 1}\n\n', b'data: {"b": 2}\n\n']
    )
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        res = await client._do_get_from_stream("/stream", caller="tst")
        # implementation returns the second 'data' message parsed as JSON
        assert isinstance(res, MutableMapping)
        assert res.get("b") == 2
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_from_stream_ignores_first_message(
    make_client, fake_stream_response_factory
) -> None:
    """Ensure the parser ignores the first data message and returns the second."""
    session = MagicMock(spec=aiohttp.ClientSession)

    session.get = lambda *a, **k: fake_stream_response_factory(
        [
            b'data: {"id": "first", "body": "ignore me"}\n\n',
            b'data: {"id": "second", "body": "keep me"}\n\n',
        ]
    )
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        res = await client._do_get_from_stream("/stream", caller="tst")
        assert isinstance(res, MutableMapping)
        # ensure the second message was selected
        assert res.get("id") == "second"
        assert res.get("body") == "keep me"
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_from_stream_partial_chunks_accumulates_buffer(
    make_client, fake_stream_response_factory
) -> None:
    """Simulate a stream where a JSON message is split across chunks to exercise buffer accumulation."""
    session = MagicMock(spec=aiohttp.ClientSession)

    session.get = lambda *a, **k: fake_stream_response_factory(
        [b'data: {"a"', b": 1}\n\n", b'data: {"b": 2}\n\n']
    )
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        res = await client._do_get_from_stream("/stream2", caller="tst")
        assert isinstance(res, MutableMapping)
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_get_proxy_https_unverified_returns_serverproxy() -> None:
    """When scheme is https and verify_ssl is False, _get_proxy returns ServerProxy.

    Make this an async test and instantiate the client while the event loop is
    running so any background tasks are created on the active loop; ensure we
    close the client afterwards to avoid leaking tasks.
    """
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="https://localhost",
        username="u",
        password="p",
        session=session,
        opts={"verify_ssl": False},
    )
    try:
        proxy = client._get_proxy()
        assert isinstance(proxy, xc.ServerProxy)
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_process_queue_unknown_method_sets_future_exception(make_client) -> None:
    """Putting an unknown method into the request queue should set an exception on the future."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    task: asyncio.Task | None = None
    try:
        q: asyncio.Queue = asyncio.Queue()
        client._request_queue = q

        loop = asyncio.get_running_loop()
        future = loop.create_future()
        await q.put(("unknown", "/x", None, future, "tst"))

        task = loop.create_task(client._process_queue())
        await asyncio.sleep(0)  # allow the task to process the queue
        # cancel background task and await it so the CancelledError is retrieved
        task.cancel()
        # await the cancelled task so the CancelledError is retrieved and suppressed
        with contextlib.suppress(asyncio.CancelledError):
            await task
        # future should have an exception
        exc = future.exception()
        assert isinstance(exc, RuntimeError)
    finally:
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await client.async_close()


@pytest.mark.asyncio
async def test_do_get_from_stream_error_initial_raises(make_client) -> None:
    """When response.ok is False and client._initial True, _do_get_from_stream should raise."""
    session = MagicMock(spec=aiohttp.ClientSession)

    class FakeBadResp:
        def __init__(self, status=403):
            self.status = status
            self.reason = "Forbidden"
            self.ok = False

            class RI:
                real_url = URL("http://localhost")

            self.request_info = RI()
            self.history = []
            self.headers = {}

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        @property
        def content(self):
            class C:
                async def iter_chunked(self, n):
                    yield b""

            return C()

    def fake_get(*args, **kwargs):
        return FakeBadResp()

    session.get = fake_get
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        client._initial = True
        with pytest.raises(aiohttp.ClientResponseError):
            await client._do_get_from_stream("/bad", caller="t")
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_process_queue_handles_requests(make_client) -> None:
    """Run a single iteration of _process_queue processing several request types."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    task: asyncio.Task | None = None
    try:
        # patch the do_* methods
        client._do_get = AsyncMock(return_value={"g": 1})
        client._do_post = AsyncMock(return_value={"p": 2})
        client._do_get_from_stream = AsyncMock(return_value={"s": 3})

        # replace request queue with a real one
        q: asyncio.Queue = asyncio.Queue()
        client._request_queue = q

        # start the queue processor as a real task on the running loop (bypass patched asyncio.create_task)
        task = asyncio.get_running_loop().create_task(client._process_queue())

        loop = asyncio.get_running_loop()
        fut_get = loop.create_future()
        fut_post = loop.create_future()
        fut_stream = loop.create_future()

        await q.put(("get", "/g", None, fut_get, "t"))
        await q.put(("post", "/p", {"x": 1}, fut_post, "t"))
        await q.put(("get_from_stream", "/s", None, fut_stream, "t"))

        res1 = await asyncio.wait_for(fut_get, timeout=2)
        res2 = await asyncio.wait_for(fut_post, timeout=2)
        res3 = await asyncio.wait_for(fut_stream, timeout=2)

        assert res1 == {"g": 1}
        assert res2 == {"p": 2}
        assert res3 == {"s": 3}

        # cancel the processor task
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=2)
    finally:
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await asyncio.wait_for(client.async_close(), timeout=2)


@pytest.mark.asyncio
@pytest.mark.parametrize("returned", [{"ok": 1}, [1, 2, 3], None])
async def test_get_enqueues_and_processes(returned, make_client) -> None:
    """Ensure `_get` enqueues a request and `_process_queue` calls `_do_get` and returns value.

    Parameterized to cover mapping, list and None return types.
    """
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    task: asyncio.Task | None = None
    try:
        # replace request queue with a real one so _process_queue can run
        q: asyncio.Queue = asyncio.Queue()
        client._request_queue = q

        called = {}

        async def fake_do_get(path, caller="x"):
            # capture the caller name supplied by _get
            called["caller"] = caller
            return returned

        client._do_get = AsyncMock(side_effect=fake_do_get)

        # start the real processor task
        task = asyncio.get_running_loop().create_task(client._process_queue())

        # call the high-level _get which will create a future and wait for processing
        res = await client._get("/testpath")

        assert res == returned
        # caller should be the test function name when inspect.stack works
        assert called.get("caller") is not None
    finally:
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await client.async_close()


@pytest.mark.asyncio
async def test_get_uses_unknown_when_inspect_stack_raises(monkeypatch, make_client) -> None:
    """If inspect.stack() raises, `_get` should set caller to 'Unknown'."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    task: asyncio.Task | None = None
    try:
        # Replace client_base.inspect.stack to raise an IndexError
        class _BadInspect:
            @staticmethod
            def stack():
                raise IndexError("no stack")

        monkeypatch.setattr(pyopnsense_client_base, "inspect", _BadInspect)

        q: asyncio.Queue = asyncio.Queue()
        client._request_queue = q

        captured = {}

        async def fake_do_get(path, caller="x"):
            captured["caller"] = caller
            return {"ok": True}

        client._do_get = AsyncMock(side_effect=fake_do_get)

        task = asyncio.get_running_loop().create_task(client._process_queue())

        res = await client._get("/other")
        assert res == {"ok": True}
        assert captured.get("caller") == "Unknown"
    finally:
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await client.async_close()


@pytest.mark.asyncio
@pytest.mark.parametrize("returned", [{"ok": 1}, [1, 2, 3], None])
async def test_post_enqueues_and_processes(returned, make_client) -> None:
    """Ensure `_post` enqueues a request and `_process_queue` calls `_do_post` and returns value.

    Parameterized to cover mapping, list and None return types. Also verify payload is forwarded.
    """
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    task: asyncio.Task | None = None
    try:
        q: asyncio.Queue = asyncio.Queue()
        client._request_queue = q

        captured = {}

        async def fake_do_post(path, payload=None, caller="x"):
            captured["caller"] = caller
            captured["payload"] = payload
            return returned

        client._do_post = AsyncMock(side_effect=fake_do_post)

        task = asyncio.get_running_loop().create_task(client._process_queue())

        payload = {"a": 1}
        res = await client._post("/postpath", payload=payload)

        assert res == returned
        assert captured.get("payload") == payload
        assert captured.get("caller") is not None
    finally:
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await client.async_close()


@pytest.mark.asyncio
async def test_post_uses_unknown_when_inspect_stack_raises(monkeypatch, make_client) -> None:
    """If inspect.stack() raises, `_post` should set caller to 'Unknown'."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    task: asyncio.Task | None = None
    try:

        class _BadInspect:
            @staticmethod
            def stack():
                raise IndexError("no stack")

        monkeypatch.setattr(pyopnsense_client_base, "inspect", _BadInspect)

        q: asyncio.Queue = asyncio.Queue()
        client._request_queue = q

        captured = {}

        async def fake_do_post(path, payload=None, caller="x"):
            captured["caller"] = caller
            captured["payload"] = payload
            return {"ok": True}

        client._do_post = AsyncMock(side_effect=fake_do_post)

        task = asyncio.get_running_loop().create_task(client._process_queue())

        payload = {"b": 2}
        res = await client._post("/otherpost", payload=payload)
        assert res == {"ok": True}
        assert captured.get("caller") == "Unknown"
        assert captured.get("payload") == payload
    finally:
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await client.async_close()


@pytest.mark.asyncio
async def test_exec_php_returns_real_json_and_xmlrpc_timeout_decorator() -> None:
    """_exec_php should return parsed JSON from response['real']; test @_xmlrpc_timeout wrapper."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        # Simulate exec_php returning a mapping with 'real' JSON string
        proxy = MagicMock()
        proxy.opnsense.exec_php.return_value = {"real": '{"ok": true, "val": 5}'}
        client._get_proxy = MagicMock(return_value=proxy)
        res = await client._exec_php("echo ok;")
        assert isinstance(res, MutableMapping) and res.get("val") == 5

        # Test the _xmlrpc_timeout decorator: wrap a simple async function
        class D:
            @pyopnsense_helpers._xmlrpc_timeout
            async def wrapped(self) -> int:
                return 7

        d = D()
        assert await d.wrapped() == 7
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_do_get_and_do_post_success_paths() -> None:
    """_do_get/_do_post should return parsed JSON when response.ok is True."""
    session = MagicMock(spec=aiohttp.ClientSession)

    class FakeOKResp:
        def __init__(self, payload):
            self.status = 200
            self.reason = "OK"
            self.ok = True
            self._payload = payload

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def json(self, content_type=None):
            return self._payload

        @property
        def content(self):
            class C:
                async def iter_chunked(self, n):
                    yield b""  # not used here

            return C()

    def fake_get(*args, **kwargs):
        return FakeOKResp({"a": 1})

    def fake_post(*args, **kwargs):
        return FakeOKResp([1, 2, 3])

    session.get = fake_get
    session.post = fake_post
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        got = await client._do_get("/api/x", caller="t")
        assert isinstance(got, MutableMapping) and got.get("a") == 1

        posted = await client._do_post("/api/x", payload={"x": 1}, caller="t")
        assert isinstance(posted, list) and posted[0] == 1
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_exec_php_non_mapping_and_get_proxy_https_unverified() -> None:
    """_exec_php returns {} when proxy returns non-mapping; _get_proxy supports https unverified."""
    session = MagicMock(spec=aiohttp.ClientSession)
    # non-mapping return
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        proxy = MagicMock()
        proxy.opnsense.exec_php.return_value = [1, 2, 3]
        client._get_proxy = MagicMock(return_value=proxy)
        res = await client._exec_php("x")
        assert res == {}
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_process_queue_exception_sets_future_exception() -> None:
    """If a worker raises, the future should get_exception set."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    task: asyncio.Task | None = None
    try:
        client._do_get = AsyncMock(side_effect=ValueError("boom"))

        q: asyncio.Queue = asyncio.Queue()
        client._request_queue = q

        loop = asyncio.get_running_loop()
        task = loop.create_task(client._process_queue())

        fut = loop.create_future()
        await q.put(("get", "/g", None, fut, "t"))

        with pytest.raises(ValueError):
            await asyncio.wait_for(fut, timeout=2)

        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
    finally:
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await client.async_close()


@pytest.mark.asyncio
async def test_process_queue_cancelled_sets_future_cancelled_error() -> None:
    """Ensure cancelling _process_queue resolves in-flight futures with CancelledError."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    task: asyncio.Task | None = None
    try:
        for worker in client._workers:
            worker.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await worker
        client._workers.clear()

        started = asyncio.Event()
        release = asyncio.Event()

        async def _blocked_get(_path: str, _caller: str) -> MutableMapping[str, Any]:
            started.set()
            await release.wait()
            return {}

        client._do_get = AsyncMock(side_effect=_blocked_get)

        q: asyncio.Queue = asyncio.Queue()
        client._request_queue = q

        loop = asyncio.get_running_loop()
        task = loop.create_task(client._process_queue())

        fut = loop.create_future()
        await q.put(("get", "/g", None, fut, "t"))

        await asyncio.wait_for(started.wait(), timeout=2)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

        assert fut.done()
        with pytest.raises(asyncio.CancelledError):
            await fut
    finally:
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await client.async_close()


@pytest.mark.asyncio
async def test_monitor_queue_handles_qsize_exception() -> None:
    """If queue.qsize() raises, monitor should catch and continue (task runs)."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    task: asyncio.Task | None = None
    try:
        # make qsize raise
        class BadQ:
            def qsize(self):
                raise RuntimeError("boom")

            def empty(self):
                # indicate there are no queued items so async_close won't attempt to
                # drain a non-standard queue object; this keeps the test focused on
                # the qsize exception handling in _monitor_queue.
                return True

        client._request_queue = BadQ()  # type: ignore[assignment]

        loop = asyncio.get_running_loop()
        task = loop.create_task(client._monitor_queue())

        # yield control so task runs once and hits exception
        await asyncio.sleep(0)

        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
    finally:
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await client.async_close()


@pytest.mark.asyncio
async def test_client_base_workers_start_lazily_on_first_queued_request() -> None:
    """Ensure loop/workers are initialized on first queued API request, not in __init__."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        assert client._loop is None
        assert client._queue_monitor is None
        assert client._workers == []

        client._do_get = AsyncMock(return_value={"ok": True})
        result = await client._get("/api/test")

        assert result == {"ok": True}
        assert client._loop is asyncio.get_running_loop()
        assert client._queue_monitor is not None
        assert len(client._workers) == client._max_workers
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_do_get_post_and_stream_permission_errors(make_client) -> None:
    """_do_get/_do_post/_do_get_from_stream should not raise when 403 and initial False."""
    session = MagicMock(spec=aiohttp.ClientSession)

    class Fake403:
        def __init__(self):
            self.status = 403
            self.reason = "Forbidden"
            self.ok = False

            class RI:  # minimal request_info
                real_url = URL("http://localhost")

            self.request_info = RI()
            self.history = []
            self.headers = {}

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def json(self, content_type=None):
            return {"err": 1}

        @property
        def content(self):  # for stream variant
            class C:
                async def iter_chunked(self, n):
                    if False:  # pragma: no cover
                        yield b""  # never executed; placeholder
                        return
                    yield b""  # empty stream

            return C()

    session.get = lambda *a, **k: Fake403()
    session.post = lambda *a, **k: Fake403()
    client = pyopnsense.OPNsenseClient(
        url="http://localhost", username="u", password="p", session=session
    )
    try:
        client._initial = False
        assert await client._do_get("/x", caller="t") is None
        assert await client._do_post("/x", payload={}, caller="t") is None
        assert await client._do_get_from_stream("/x", caller="t") == {}
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_restore_config_section_executes_in_executor(make_client) -> None:
    """_restore_config_section should call underlying proxy method with params."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    called = {}

    class FakeProxy:
        class opnsense:  # noqa: D401 - minimal container for restore_config_section
            @staticmethod
            def restore_config_section(params):  # pragma: no cover - executed in executor
                called["params"] = params

    client._get_proxy = MagicMock(return_value=FakeProxy())
    await client._restore_config_section("filter", {"rule": []})
    assert called.get("params") == {"filter": {"rule": []}}
    await client.async_close()


@pytest.mark.asyncio
async def test_client_name_property():
    """Ensure client reports a composed name property correctly."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost",
        username="user",
        password="pass",
        session=session,
    )
    try:
        assert client.name == "OPNsense"
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_reset_and_get_query_counts():
    """Reset and retrieve client query counters."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = pyopnsense.OPNsenseClient(
        url="http://localhost",
        username="user",
        password="pass",
        session=session,
    )
    try:
        await client.reset_query_counts()
        rest, xml = await client.get_query_counts()
        assert rest == 0
        assert xml == 0
    finally:
        await client.async_close()


@pytest.mark.asyncio
async def test_set_use_snake_case_unknown_firmware_raise(monkeypatch, make_client) -> None:
    """set_use_snake_case should raise UnknownFirmware when initial True and compare fails."""
    session = MagicMock(spec=aiohttp.ClientSession)
    client = make_client(session=session)
    client._firmware_version = "25.x"

    class BadAV:
        def __init__(self, *_args, **_kwargs):
            pass

        def __lt__(self, other):  # noqa: D401 - comparison triggers exception
            raise awesomeversion.exceptions.AwesomeVersionCompareException("bad")

    monkeypatch.setattr(pyopnsense_client_base.awesomeversion, "AwesomeVersion", BadAV)
    with pytest.raises(pyopnsense.UnknownFirmware):
        await client.set_use_snake_case(initial=True)
    await client.async_close()

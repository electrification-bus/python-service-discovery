"""Unit tests for mdns_async, with fakes (no network)."""

import asyncio

import pytest

pytest.importorskip("zeroconf")

from test_mdns import (  # noqa: E402
    FAST,
    IDENT,
    FakeZeroconf,
    _broker,
    _patch_browse,
    os_name,  # noqa: F401 (fixture)
)

from ebus_service_discovery import mdns_async  # noqa: E402
from ebus_service_discovery.ebus import HttpService, RetrySchedule  # noqa: E402

# --- mdns_async -------------------------------------------------------------------


class FakeAsyncZeroconf:
    def __init__(self):
        self.zeroconf = FakeZeroconf(start_loop=False)
        self.closed = False

    async def async_close(self):  # pragma: no cover - must never be called
        self.closed = True


def test_async_requires_caller_owned_instance():
    with pytest.raises(TypeError, match="AsyncZeroconf"):
        mdns_async.Advertiser(IDENT, None)
    with pytest.raises(TypeError):
        asyncio.run(mdns_async.browse(None, "_ebus._tcp"))


@pytest.mark.usefixtures("os_name")
def test_async_advertiser():
    aiozc = FakeAsyncZeroconf()

    async def run():
        async with mdns_async.Advertiser(IDENT, aiozc, http=HttpService(port=80)) as adv:
            assert adv.server == "host-1.local."
            assert len(aiozc.zeroconf.registered) == 3
        return adv

    adv = asyncio.run(run())
    assert not adv.running
    assert aiozc.zeroconf.registered == {}
    assert not aiozc.closed and not aiozc.zeroconf.closed


def test_async_find_broker(monkeypatch):
    calls = _patch_browse(monkeypatch, mdns_async, [[], [_broker("_secure-mqtt._tcp")]])
    aiozc = FakeAsyncZeroconf()
    ep = asyncio.run(mdns_async.find_broker(aiozc, schedule=FAST))
    assert ep.host == "broker-1.local" and ep.use_tls
    assert len(calls) == 2
    assert calls[0][0] is aiozc


def test_async_find_broker_configured_only(monkeypatch):
    calls = _patch_browse(monkeypatch, mdns_async, [])
    ep = asyncio.run(
        mdns_async.find_broker(FakeAsyncZeroconf(), "configured-only", "mqtt://c.local")
    )
    assert ep.host == "c.local" and calls == []


def test_async_find_broker_stop(monkeypatch):
    _patch_browse(monkeypatch, mdns_async, [])

    async def run():
        stop = asyncio.Event()
        asyncio.get_running_loop().call_later(0.1, stop.set)
        slow = RetrySchedule(fast_interval=30, slow_interval=30)
        return await mdns_async.find_broker(FakeAsyncZeroconf(), stop=stop, schedule=slow)

    assert asyncio.run(run()) is None

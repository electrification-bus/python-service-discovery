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
from ebus_service_discovery.ebus import BrokerService, HttpService, RetrySchedule  # noqa: E402

# --- mdns_async -------------------------------------------------------------------


class FakeAsyncZeroconf:
    def __init__(self, **kw):
        self.zeroconf = FakeZeroconf(start_loop=False, **kw)
        self.closed = False

    async def async_close(self):  # pragma: no cover - must never be called
        self.closed = True


def test_async_functions_require_caller_owned_instance():
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


@pytest.mark.usefixtures("os_name")
def test_async_advertiser_brokers():
    aiozc = FakeAsyncZeroconf()

    async def run():
        async with mdns_async.Advertiser(IDENT, aiozc, brokers=BrokerService()):
            names = sorted(aiozc.zeroconf.registered)
            info = aiozc.zeroconf.registered["dev-1._secure-mqtt._tcp.local."]
            assert info.server == "host-1.local." and info.addresses == []
        return names

    assert asyncio.run(run()) == [
        "dev-1._device-info._tcp.local.",
        "dev-1._ebus._tcp.local.",
        "dev-1._secure-mqtt._tcp.local.",
    ]
    assert aiozc.zeroconf.registered == {}


async def _cancel_start_once(aiozc, registered_count):
    adv = mdns_async.Advertiser(IDENT, aiozc)
    task = asyncio.ensure_future(adv.start())
    while len(aiozc.zeroconf.registered) < registered_count:
        await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await adv.stop()
    return adv


@pytest.mark.usefixtures("os_name")
def test_cancelled_start_during_announcements_withdraws_services():
    aiozc = FakeAsyncZeroconf(hold_broadcast=True)
    adv = asyncio.run(_cancel_start_once(aiozc, 2))
    assert not adv.running
    assert aiozc.zeroconf.registered == {}
    assert len(aiozc.zeroconf.unregistered) == 2


@pytest.mark.usefixtures("os_name")
def test_cancelled_start_during_probing_withdraws_services():
    aiozc = FakeAsyncZeroconf(probing={"dev-1._device-info._tcp.local."})
    adv = asyncio.run(_cancel_start_once(aiozc, 1))
    assert not adv.running
    assert aiozc.zeroconf.registered == {}
    assert aiozc.zeroconf.unregistered == ["dev-1._ebus._tcp.local."]


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


def test_async_find_broker_fallback_does_not_take_other_broker(monkeypatch):
    other = _broker("_secure-mqtt._tcp", server="broker-2.local")
    _patch_browse(monkeypatch, mdns_async, [[other], [other], [other]])
    mode, url = "discovery-with-fallback", "mqtts://broker-1.local"
    ep = asyncio.run(mdns_async.find_broker(FakeAsyncZeroconf(), mode, url, schedule=FAST))
    assert ep.host == "broker-1.local"
    _patch_browse(monkeypatch, mdns_async, [[other]])
    ep = asyncio.run(
        mdns_async.find_broker(FakeAsyncZeroconf(), mode, url, schedule=FAST, allow_unmatched=True)
    )
    assert ep.host == "broker-2.local"


def test_async_find_broker_stop(monkeypatch):
    _patch_browse(monkeypatch, mdns_async, [])

    async def run():
        stop = asyncio.Event()
        asyncio.get_running_loop().call_later(0.1, stop.set)
        slow = RetrySchedule(fast_interval=30, slow_interval=30)
        return await mdns_async.find_broker(FakeAsyncZeroconf(), stop=stop, schedule=slow)

    assert asyncio.run(run()) is None

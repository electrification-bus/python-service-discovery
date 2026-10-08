"""Unit tests for the zeroconf-backed modules, with fakes (no network)."""

import asyncio
import concurrent.futures
import inspect
import ipaddress
import logging
import threading

import pytest

pytest.importorskip("zeroconf")

from zeroconf import (  # noqa: E402
    DNSAddress,
    DNSPointer,
    NonUniqueNameException,
    ServiceInfo,
    ServiceStateChange,
)

from ebus_service_discovery import (  # noqa: E402
    Address,
    ServiceInstance,
    _mdns_core,
    mdns,
)
from ebus_service_discovery.ebus import (  # noqa: E402
    BrokerMode,
    HttpService,
    Identity,
    RetrySchedule,
)

IDENT = Identity(
    device_ids=["dev-1"],
    roles=["device"],
    manufacturer="Example",
    model="EX-1",
    serial_number="sn-0001",
)
FAST = RetrySchedule(fast_interval=0, slow_interval=0, max_attempts=6)


def _broker(stype, server="broker-1.local", port=8883, txt=None):
    return ServiceInstance(
        service_type=stype,
        instance_name=server.split(".")[0],
        server=server,
        port=port,
        addresses=(Address.parse("192.0.2.10"),),
        txt=txt or {},
    )


# --- names --------------------------------------------------------------------


@pytest.mark.parametrize(
    "given,fq,bare",
    [
        ("_ebus._tcp", "_ebus._tcp.local.", "_ebus._tcp"),
        ("_ebus._tcp.local.", "_ebus._tcp.local.", "_ebus._tcp"),
        ("_ebus._tcp.local", "_ebus._tcp.local.", "_ebus._tcp"),
    ],
)
def test_type_names(given, fq, bare):
    assert _mdns_core.fq_type(given) == fq
    assert _mdns_core.bare_type(given) == bare


def test_instance_candidates():
    names = _mdns_core.instance_candidates("host")
    assert names[:3] == ["host", "host-2", "host-3"]
    assert names[-1] == "host-99"
    assert len(names) == 99


# --- ServiceInfo -> ServiceInstance -----------------------------------------------


def test_info_to_instance():
    info = ServiceInfo(
        "_secure-mqtt._tcp.local.",
        "Broker One._secure-mqtt._tcp.local.",
        port=8883,
        properties={b"Broker": b"broker-1.local", b"flag": None},
        server="broker-1.local.",
        parsed_addresses=["192.0.2.10", "2001:db8::10"],
    )
    inst = _mdns_core.info_to_instance(info, "_secure-mqtt._tcp")
    assert inst.service_type == "_secure-mqtt._tcp"
    assert inst.instance_name == "Broker One"
    assert inst.server == "broker-1.local"
    assert inst.port == 8883
    assert {a.address for a in inst.addresses} == {"192.0.2.10", "2001:db8::10"}
    assert inst.txt == {"broker": "broker-1.local", "flag": ""}
    assert inst.interface is None


# --- async_browse with a fake browser -------------------------------------------


class _FakeInfo(ServiceInfo):
    resolvable: set = set()

    async def async_request(self, zc, timeout, *a, **kw):
        return self.name in self.resolvable


def _fake_info_factory(full, name):
    return _FakeInfo(
        full,
        name,
        port=1883,
        properties={b"txtvers": b"1"},
        server="host-1.local.",
        parsed_addresses=["192.0.2.20"],
    )


def test_async_browse_resolves_and_drops_removed(monkeypatch):
    full = "_mqtt._tcp.local."
    events = [
        (f"a.{full}", ServiceStateChange.Added),
        (f"b.{full}", ServiceStateChange.Added),
        (f"c.{full}", ServiceStateChange.Added),
        (f"b.{full}", ServiceStateChange.Removed),
    ]

    class FakeBrowser:
        cancelled = False

        def __init__(self, zc, type_, handlers):
            assert type_ == full
            for name, change in events:
                handlers[0](zeroconf=zc, service_type=type_, name=name, state_change=change)

        async def async_cancel(self):
            FakeBrowser.cancelled = True

    monkeypatch.setattr(_mdns_core, "AsyncServiceBrowser", FakeBrowser)
    monkeypatch.setattr(_mdns_core, "AsyncServiceInfo", _fake_info_factory)
    monkeypatch.setattr(_FakeInfo, "resolvable", {f"a.{full}"})
    out = asyncio.run(_mdns_core.async_browse(object(), "_mqtt._tcp", 0.01))
    assert [i.instance_name for i in out] == ["a"]
    assert out[0].service_type == "_mqtt._tcp"
    assert FakeBrowser.cancelled


def test_async_browse_returns_within_timeout_despite_unresolved(monkeypatch):
    full = "_mqtt._tcp.local."

    class SlowInfo(_FakeInfo):
        async def async_request(self, zc, timeout, *a, **kw):
            await asyncio.sleep(timeout / 1000)  # never answered: waits its whole budget
            return False

    class FakeBrowser:
        def __init__(self, zc, type_, handlers):
            handlers[0](
                zeroconf=zc,
                service_type=type_,
                name=f"slow.{full}",
                state_change=ServiceStateChange.Added,
            )

        async def async_cancel(self):
            pass

    monkeypatch.setattr(_mdns_core, "AsyncServiceBrowser", FakeBrowser)
    monkeypatch.setattr(
        _mdns_core, "AsyncServiceInfo", lambda f, n: SlowInfo(f, n, server="host-1.local.")
    )

    async def run():
        loop = asyncio.get_running_loop()
        start = loop.time()
        out = await _mdns_core.async_browse(object(), "_mqtt._tcp", 0.3)
        return out, loop.time() - start

    out, elapsed = asyncio.run(run())
    assert out == []
    assert elapsed < 0.45


# --- BrokerSearch (mode and retry decisions) -------------------------------------


def test_search_configured_only_needs_url_or_cfg():
    with pytest.raises(ValueError, match="configured-only"):
        _mdns_core.BrokerSearch("configured-only", None, None)
    s = _mdns_core.BrokerSearch("configured-only", None, {"host": "b.local", "use_tls": True})
    assert not s.needs_browse
    assert (s.configured.host, s.configured.port, s.configured.use_tls) == ("b.local", 8883, True)


def test_search_url_wins_over_cfg():
    s = _mdns_core.BrokerSearch(None, "mqtt://u.local:1999", {"host": "cfg.local"})
    assert s.mode is BrokerMode.DISCOVERY_ONLY
    assert (s.configured.host, s.configured.port) == ("u.local", 1999)
    assert s.browse_types == (
        "_secure-mqtt._tcp",
        "_mqtt-wss._tcp",
        "_mqtt-ws._tcp",
        "_mqtt._tcp",
    )


def test_search_decide_prefers_secure_and_reports_websocket(caplog):
    s = _mdns_core.BrokerSearch("discovery-only", None, None)
    found = [
        _broker("_mqtt._tcp", port=1883),
        _broker("_secure-mqtt._tcp", txt={"broker": "broker-1.local"}),
        _broker("_mqtt-wss._tcp", server="ws-only.local", port=9002),
    ]
    with caplog.at_level(logging.INFO):
        done, ep = s.decide(found, 0)
    assert done and ep.service_type == "_secure-mqtt._tcp" and ep.port == 8883
    assert "brokerTransportNotAccepted,url=wss://ws-only.local:9002" in caplog.text


def test_search_websocket_only_is_not_selected():
    s = _mdns_core.BrokerSearch("discovery-only", None, None)
    assert s.decide([_broker("_mqtt-ws._tcp", port=9001)], 0) == (False, None)


def test_search_fallback_after_fast_attempts():
    s = _mdns_core.BrokerSearch("discovery-with-fallback", "mqtts://conf.local", None)
    assert s.decide([], 0) == (False, None)
    assert s.decide([], 1) == (False, None)
    done, ep = s.decide([], 2)
    assert done and ep.host == "conf.local"


def test_search_fallback_when_max_attempts_is_below_fast_attempts():
    s = _mdns_core.BrokerSearch(
        "discovery-with-fallback", "mqtt://192.0.2.1", None, fast_attempts=3, max_attempts=2
    )
    assert s.decide([], 0) == (False, None)
    done, ep = s.decide([], 1)
    assert done and ep.host == "192.0.2.1"


@pytest.mark.parametrize(
    "url,base_cfg",
    [
        ("mqtts://conf.local", None),
        (None, {"host": "conf.local", "use_tls": True}),
        (None, {"use_tls": True}),  # discovery-only: no host, TLS still configured
    ],
)
def test_search_with_tls_configured_accepts_only_secure(url, base_cfg):
    s = _mdns_core.BrokerSearch("discovery-with-fallback", url, base_cfg)
    assert s.accept == ("_secure-mqtt._tcp",)
    plain = _broker("_mqtt._tcp", server="broker-2.local", port=1883)
    assert s.decide([plain], 0) == (False, None)


def test_search_without_tls_accepts_plain_and_explicit_accept_wins():
    s = _mdns_core.BrokerSearch("discovery-only", "mqtt://conf.local", {"host": "x"})
    assert s.accept == ("_secure-mqtt._tcp", "_mqtt._tcp")
    s = _mdns_core.BrokerSearch(None, "mqtts://conf.local", None, accept=["_mqtt._tcp"])
    assert s.accept == ("_mqtt._tcp",)


def test_search_fallback_waits_for_configured_then_falls_back(caplog):
    s = _mdns_core.BrokerSearch("discovery-with-fallback", "mqtts://conf.local", None)
    other = _broker("_secure-mqtt._tcp", server="other.local")
    with caplog.at_level(logging.INFO):
        assert s.decide([other], 0) == (False, None)
        assert s.decide([other], 1) == (False, None)
        done, ep = s.decide([other], 2)
    assert done and ep is s.configured
    assert "brokerNotChosen,url=mqtts://other.local:8883" in caplog.text
    assert "brokerDiscovered" not in caplog.text


def test_search_fallback_takes_configured_when_it_appears():
    s = _mdns_core.BrokerSearch("discovery-with-fallback", "mqtts://192.0.2.10", None)
    other = ServiceInstance(
        service_type="_secure-mqtt._tcp",
        instance_name="other",
        server="other.local",
        port=8883,
        addresses=(Address.parse("192.0.2.11"),),
    )
    assert s.decide([other], 0) == (False, None)
    conf = _broker("_secure-mqtt._tcp", server="conf.local", port=18883)  # at 192.0.2.10
    done, ep = s.decide([other, conf], 1)
    assert done and (ep.host, ep.port, ep.server) == ("192.0.2.10", 18883, "conf.local")


def test_search_fallback_allow_unmatched_takes_other():
    s = _mdns_core.BrokerSearch(
        "discovery-with-fallback", "mqtts://conf.local", None, allow_unmatched=True
    )
    done, ep = s.decide([_broker("_secure-mqtt._tcp", server="other.local")], 0)
    assert done and ep.host == "other.local"


def test_search_discovery_only_ignores_configured_host():
    s = _mdns_core.BrokerSearch("discovery-only", "mqtts://conf.local", None)
    done, ep = s.decide([_broker("_secure-mqtt._tcp", server="other.local")], 0)
    assert done and ep.host == "other.local"


def test_search_configured_only_never_decides_on_discovery():
    s = _mdns_core.BrokerSearch("configured-only", "mqtts://conf.local", None)
    assert not s.needs_browse and s.configured.host == "conf.local"


def test_search_fallback_without_configured_keeps_browsing():
    s = _mdns_core.BrokerSearch("discovery-with-fallback", None, None)
    assert s.decide([], 10) == (False, None)


# --- mdns.find_broker (sync) ---------------------------------------------------


def _patch_browse(monkeypatch, module, results):
    calls = []

    def fake(*args, **kw):
        calls.append(args)
        return results.pop(0) if results else []

    async def afake(*args, **kw):
        return fake(*args, **kw)

    is_async = inspect.iscoroutinefunction(module.browse_many)
    monkeypatch.setattr(module, "browse_many", afake if is_async else fake)
    return calls


def test_find_broker_configured_only_never_browses(monkeypatch):
    calls = _patch_browse(monkeypatch, mdns, [])
    ep = mdns.find_broker("configured-only", "mqtts://conf.local", zc=object())
    assert ep.host == "conf.local" and calls == []


def test_find_broker_retries_until_found(monkeypatch):
    calls = _patch_browse(
        monkeypatch, mdns, [[], [], [], [_broker("_mqtt._tcp", server="b.local", port=0)]]
    )
    ep = mdns.find_broker(zc=object(), schedule=FAST, browse_timeout=0.5)
    assert len(calls) == 4
    assert calls[0][1] == 0.5
    assert (ep.host, ep.port, ep.use_tls) == ("b.local", 1883, False)


def test_find_broker_gives_up_after_max_attempts(monkeypatch):
    calls = _patch_browse(monkeypatch, mdns, [])
    assert mdns.find_broker("discovery-only", zc=object(), schedule=FAST) is None
    assert len(calls) == 6


def test_find_broker_fallback(monkeypatch):
    _patch_browse(monkeypatch, mdns, [])
    ep = mdns.find_broker(
        "discovery-with-fallback",
        base_cfg={"host": "cfg.local", "port": 1884},
        zc=object(),
        schedule=FAST,
    )
    assert (ep.host, ep.port) == ("cfg.local", 1884)


def test_find_broker_fallback_with_short_schedule(monkeypatch):
    calls = _patch_browse(monkeypatch, mdns, [])
    short = RetrySchedule(fast_interval=0, slow_interval=0, max_attempts=2)
    ep = mdns.find_broker(
        "discovery-with-fallback", "mqtt://192.0.2.1", zc=object(), schedule=short
    )
    assert ep is not None and ep.host == "192.0.2.1"
    assert len(calls) == 2


def test_find_broker_tls_config_skips_plain_broker(monkeypatch):
    plain = _broker("_mqtt._tcp", server="broker-2.local", port=1883)
    _patch_browse(monkeypatch, mdns, [[plain], [plain], [plain]])
    base = {
        "host": "broker-1.local",
        "use_tls": True,
        "authentication": {"type": "USER_PASS", "username": "u", "password": "p"},
    }
    ep = mdns.find_broker("discovery-with-fallback", base_cfg=base, zc=object(), schedule=FAST)
    assert (ep.host, ep.use_tls) == ("broker-1.local", True)  # the configured fallback
    assert ep.mqtt_cfg(base)["use_tls"] is True


def test_find_broker_fallback_does_not_take_other_broker(monkeypatch):
    other = _broker("_secure-mqtt._tcp", server="broker-2.local")
    calls = _patch_browse(monkeypatch, mdns, [[other], [other], [other]])
    base = {"host": "broker-1.local", "use_tls": True}
    ep = mdns.find_broker("discovery-with-fallback", base_cfg=base, zc=object(), schedule=FAST)
    assert ep.host == "broker-1.local" and len(calls) == 3


def test_find_broker_fallback_allow_unmatched(monkeypatch):
    other = _broker("_secure-mqtt._tcp", server="broker-2.local")
    _patch_browse(monkeypatch, mdns, [[other]])
    base = {"host": "broker-1.local", "use_tls": True}
    ep = mdns.find_broker(
        "discovery-with-fallback",
        base_cfg=base,
        zc=object(),
        schedule=FAST,
        allow_unmatched=True,
    )
    assert ep.host == "broker-2.local"


def test_find_broker_stop(monkeypatch):
    calls = _patch_browse(monkeypatch, mdns, [])
    stop = threading.Event()
    stop.set()
    assert mdns.find_broker(zc=object(), stop=stop, schedule=FAST) is None
    assert calls == []


def test_find_broker_stop_interrupts_wait(monkeypatch):
    _patch_browse(monkeypatch, mdns, [])
    stop = threading.Event()
    threading.Timer(0.1, stop.set).start()
    slow = RetrySchedule(fast_interval=30, slow_interval=30)
    assert mdns.find_broker(zc=object(), stop=stop, schedule=slow) is None


def test_mqtt_cfg_round_trip(monkeypatch):
    _patch_browse(
        monkeypatch,
        mdns,
        [[_broker("_secure-mqtt._tcp", txt={"broker": "broker-1.example."}, port=8884)]],
    )
    base = {"host": "x", "tls_ca_cert": "/ca.pem", "authentication": {"type": "USER_PASS"}}
    ep = mdns.find_broker(base_cfg=base, zc=object(), schedule=FAST)
    assert ep.mqtt_cfg(base) == {
        "host": "broker-1.example",
        "port": 8884,
        "use_tls": True,
        "tls_ca_cert": "/ca.pem",
        "authentication": {"type": "USER_PASS"},
    }


# --- fakes for advertising ----------------------------------------------------


class FakeZeroconf:
    """Enough of zeroconf.Zeroconf for the advertiser, on a real loop thread."""

    def __init__(self, taken=(), start_loop=True, probing=(), hold_broadcast=False):
        self.taken = set(taken)
        self.probing = set(probing)  # names whose probe never finishes
        self.hold_broadcast = hold_broadcast  # announcements never finish
        self.registered: dict[str, ServiceInfo] = {}
        self.unregistered: list[str] = []
        self.sent = []
        self.closed = False
        self.cache = FakeCache()
        self.loop = None
        if start_loop:
            self.loop = asyncio.new_event_loop()
            threading.Thread(target=self.loop.run_forever, daemon=True).start()

    async def async_wait_for_start(self):
        return None

    async def async_register_service(self, info):
        if info.name in self.taken or info.name in self.registered:
            raise NonUniqueNameException(info.name)
        if info.name in self.probing:
            await asyncio.Event().wait()
        self.registered[info.name] = info
        fut = asyncio.get_running_loop().create_future()
        if not self.hold_broadcast:
            fut.set_result(None)
        return fut

    async def async_unregister_service(self, info):
        self.registered.pop(info.name, None)
        self.unregistered.append(info.name)
        fut = asyncio.get_running_loop().create_future()
        fut.set_result(None)
        return fut

    def async_send(self, out):
        self.sent.append(out)

    def close(self):
        self.closed = True
        if self.loop is not None:
            self.loop.call_soon_threadsafe(self.loop.stop)


class FakeCache:
    def __init__(self):
        self.entries: dict[str, list] = {}

    def async_entries_with_name(self, name):
        return self.entries.get(name, [])


@pytest.fixture
def os_name(monkeypatch):
    async def fake(zc, timeout=3.0, addresses=None):
        return "host-1.local."

    monkeypatch.setattr(_mdns_core, "async_os_hostname", fake)


# --- os host name detection --------------------------------------------------


def test_async_os_hostname_reads_reverse_ptr():
    zc = FakeZeroconf(start_loop=False)
    ip = ipaddress.ip_address("192.0.2.5")
    name = "5.2.0.192.in-addr.arpa."
    zc.cache.entries[name] = [DNSPointer(name, 12, 1, 120, "host-1.local.")]
    got = asyncio.run(_mdns_core.async_os_hostname(zc, 1.0, [ip]))
    assert got == "host-1.local."
    assert len(zc.sent) == 1


def test_async_os_hostname_repeats_query_then_gives_up():
    zc = FakeZeroconf(start_loop=False)
    got = asyncio.run(_mdns_core.async_os_hostname(zc, 0.3, [ipaddress.ip_address("2001:db8::5")]))
    assert got is None
    assert len(zc.sent) == 3


def test_async_os_hostname_ignores_non_local_names():
    zc = FakeZeroconf(start_loop=False)
    name = "5.2.0.192.in-addr.arpa."
    zc.cache.entries[name] = [DNSPointer(name, 12, 1, 120, "host-1.example.com.")]
    assert (
        asyncio.run(_mdns_core.async_os_hostname(zc, 0.1, [ipaddress.ip_address("192.0.2.5")]))
        is None
    )


def test_async_name_answered():
    zc = FakeZeroconf(start_loop=False)
    assert not asyncio.run(_mdns_core.async_name_answered(zc, "free.local.", 0.1))
    zc.cache.entries["taken.local."] = [
        DNSAddress("taken.local.", 1, 1, 120, ipaddress.ip_address("192.0.2.9").packed)
    ]
    assert asyncio.run(_mdns_core.async_name_answered(zc, "taken.local.", 1.0))


def test_async_os_hostname_no_addresses():
    zc = FakeZeroconf(start_loop=False)
    assert asyncio.run(_mdns_core.async_os_hostname(zc, 0.1, [])) is None


# --- mdns.Advertiser ------------------------------------------------------------


def _txt(info):
    return {k.decode(): (v or b"").decode() for k, v in info.properties.items()}


def test_advertiser_registers_services_under_os_name(os_name):
    zc = FakeZeroconf()
    http = [HttpService(port=8080), HttpService(port=8443, tls=True)]
    adv = mdns.Advertiser(IDENT, http=http, zc=zc)
    with adv:
        assert adv.running
        assert adv.server == "host-1.local."
        assert adv.instance_name == "host-1"
        infos = {i.type: i for i in adv.infos}
        assert set(infos) == {
            "_ebus._tcp.local.",
            "_device-info._tcp.local.",
            "_http._tcp.local.",
            "_https._tcp.local.",
        }
        for info in infos.values():
            assert info.server == "host-1.local."
            assert info.addresses == []  # the OS responder answers for the host name
        assert infos["_ebus._tcp.local."].port == 8080  # the first HTTP port
        assert infos["_device-info._tcp.local."].port == 0
        assert _txt(infos["_ebus._tcp.local."])["device_id"] == "dev-1"
        assert _txt(infos["_device-info._tcp.local."])["serial_number"] == "sn-0001"
        assert _txt(infos["_https._tcp.local."])["path"] == "/api/v1"
    assert not adv.running
    assert len(zc.unregistered) == 4
    assert not zc.closed  # a passed instance is never closed
    zc.close()


def test_advertiser_renames_on_conflict(os_name, caplog):
    zc = FakeZeroconf(taken={"host-1._device-info._tcp.local.", "host-1-2._ebus._tcp.local."})
    with caplog.at_level(logging.INFO), mdns.Advertiser(IDENT, zc=zc, port=1234) as adv:
        assert adv.instance_name == "host-1-3"
        assert sorted(zc.registered) == [
            "host-1-3._device-info._tcp.local.",
            "host-1-3._ebus._tcp.local.",
        ]
        # the non-conflicting registrations of the rejected names were withdrawn
        assert "host-1._ebus._tcp.local." in zc.unregistered
        assert "host-1-2._device-info._tcp.local." in zc.unregistered
    assert "instanceRenamed,from=host-1,to=host-1-3" in caplog.text
    zc.close()


def test_advertiser_gives_up_after_99(os_name):
    names = _mdns_core.instance_candidates("taken")
    zc = FakeZeroconf(taken={f"{n}._ebus._tcp.local." for n in names})
    adv = mdns.Advertiser(IDENT, zc=zc, instance_name="taken")
    with pytest.raises(NonUniqueNameException):
        adv.start()
    assert not adv.running
    assert zc.registered == {}
    zc.close()


def test_advertiser_owns_and_closes_its_zeroconf(os_name, monkeypatch):
    created = []

    def factory():
        created.append(FakeZeroconf())
        return created[-1]

    monkeypatch.setattr(mdns, "new_zeroconf", factory)
    adv = mdns.Advertiser(IDENT)
    adv.start()
    adv.start()  # idempotent
    assert len(created) == 1 and not created[0].closed
    adv.stop()
    assert created[0].closed


def test_advertiser_closes_owned_zeroconf_when_start_fails(monkeypatch):
    async def none(zc, timeout=3.0, addresses=None):
        return None

    monkeypatch.setattr(_mdns_core, "async_os_hostname", none)
    monkeypatch.setattr(_mdns_core, "os_responder_present", lambda: True)
    created = []
    monkeypatch.setattr(mdns, "new_zeroconf", lambda: created.append(FakeZeroconf()) or created[-1])
    with pytest.raises(RuntimeError, match="did not answer"):
        mdns.Advertiser(IDENT).start()
    assert created[0].closed


def test_advertiser_explicit_server_skips_detection(monkeypatch):
    async def boom(*a, **kw):
        raise AssertionError("detection should not run")

    monkeypatch.setattr(_mdns_core, "async_os_hostname", boom)
    zc = FakeZeroconf()
    with mdns.Advertiser(
        IDENT, zc=zc, server="named.local", addresses=["192.0.2.30"], instance_name="Named"
    ) as adv:
        info = adv.infos[0]
        assert info.server == "named.local."
        assert info.parsed_addresses() == ["192.0.2.30"]
        assert info.name == "Named._ebus._tcp.local."
    zc.close()


def test_advertiser_never_publishes_addresses_under_os_name(os_name, caplog):
    zc = FakeZeroconf()
    with (
        caplog.at_level(logging.WARNING),
        mdns.Advertiser(IDENT, zc=zc, addresses=["192.0.2.5"]) as adv,
    ):
        assert adv.server == "host-1.local."
        assert all(info.addresses == [] for info in adv.infos)
    assert "addressesIgnoredUnderOsHostname,server=host-1.local.,addresses=192.0.2.5" in caplog.text
    zc.close()


def test_interrupted_sync_start_withdraws_what_it_registered(os_name):
    zc = FakeZeroconf(hold_broadcast=True)
    plan = _mdns_core.AdvertisementPlan(
        IDENT,
        port=None,
        device_info_port=0,
        http=None,
        server=None,
        addresses=None,
        instance_name=None,
    )
    with pytest.raises(concurrent.futures.TimeoutError):
        mdns._run(zc, _mdns_core.async_advertise(zc, plan, 1.0), timeout=0.3)
    assert zc.registered == {}
    assert sorted(zc.unregistered) == [
        "host-1._device-info._tcp.local.",
        "host-1._ebus._tcp.local.",
    ]
    zc.close()


def test_advertiser_without_os_responder_publishes_own_addresses(monkeypatch):
    async def none(zc, timeout=3.0, addresses=None):
        return None

    async def unanswered(zc, server, timeout):
        return False

    monkeypatch.setattr(_mdns_core, "async_os_hostname", none)
    monkeypatch.setattr(_mdns_core, "os_responder_present", lambda: False)
    monkeypatch.setattr(_mdns_core, "async_name_answered", unanswered)
    monkeypatch.setattr(_mdns_core, "fallback_hostname", lambda: "plain-host.local.")
    monkeypatch.setattr(_mdns_core, "local_addresses", lambda: [ipaddress.ip_address("192.0.2.40")])
    zc = FakeZeroconf()
    with mdns.Advertiser(IDENT, zc=zc) as adv:
        assert adv.server == "plain-host.local."
        assert adv.instance_name == "plain-host"
        assert adv.infos[0].parsed_addresses() == ["192.0.2.40"]
    zc.close()


def test_advertiser_fallback_name_taken(monkeypatch):
    async def none(zc, timeout=3.0, addresses=None):
        return None

    async def answered(zc, server, timeout):
        return True

    monkeypatch.setattr(_mdns_core, "async_os_hostname", none)
    monkeypatch.setattr(_mdns_core, "os_responder_present", lambda: False)
    monkeypatch.setattr(_mdns_core, "async_name_answered", answered)
    zc = FakeZeroconf()
    with pytest.raises(RuntimeError, match="another responder"):
        mdns.Advertiser(IDENT, zc=zc).start()
    zc.close()


def test_os_responder_present(monkeypatch, tmp_path):
    monkeypatch.setattr(_mdns_core.sys, "platform", "darwin")
    assert _mdns_core.os_responder_present()
    monkeypatch.setattr(_mdns_core.sys, "platform", "linux")
    monkeypatch.setattr(_mdns_core, "AVAHI_SOCKETS", (str(tmp_path / "none"),))
    assert not _mdns_core.os_responder_present()
    sock = tmp_path / "socket"
    sock.write_text("")
    monkeypatch.setattr(_mdns_core, "AVAHI_SOCKETS", (str(sock),))
    assert _mdns_core.os_responder_present()


def test_sync_call_from_zeroconf_loop_is_refused():
    zc = FakeZeroconf()

    async def inner():
        return mdns.browse("_ebus._tcp", 0.01, zc=zc)

    with pytest.raises(RuntimeError, match="mdns_async"):
        asyncio.run_coroutine_threadsafe(inner(), zc.loop).result(5)
    zc.close()


def test_invalid_http_txt_fails_before_network():
    with pytest.raises(ValueError):
        mdns.Advertiser(IDENT, http=HttpService(port=80, extra_txt={"x": "y" * 300}))

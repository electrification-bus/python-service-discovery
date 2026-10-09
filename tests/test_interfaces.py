"""Interface selection (``interfaces=``), against stubbed ifaddr adapters."""

import asyncio
import logging
import time

import pytest

pytest.importorskip("zeroconf")

import ifaddr  # noqa: E402
from test_mdns import (  # noqa: E402
    IDENT,
    FakeZeroconf,
    os_name,  # noqa: F401 (fixture)
)
from test_mdns_async import FakeAsyncZeroconf  # noqa: E402
from zeroconf import InterfaceChoice, IPVersion  # noqa: E402

from ebus_service_discovery import _mdns_core, mdns, mdns_async  # noqa: E402
from ebus_service_discovery.ebus import RetrySchedule  # noqa: E402


def _adapter(name, *ips, index=None, nice_name=None):
    out = []
    for text in ips:
        addr, prefix = text.split("/")
        ip = addr if ":" not in addr else (addr, 0, index or 0)
        out.append(ifaddr.IP(ip, int(prefix), name))
    return ifaddr.Adapter(name, nice_name or name, out, index=index)


LO = _adapter("lo", "127.0.0.1/8", "::1/128", index=1)
ETH = _adapter("eth0", "192.0.2.10/24", "fe80::10/64", index=2)
WLAN = _adapter("wlan0", "192.0.2.11/24", "fe80::11/64", index=3)
WLAN_OTHER = _adapter("wlan0", "198.51.100.11/24", "fe80::11/64", index=3)


def _names(selection):
    return [s.name for s in selection]


@pytest.fixture
def adapters(monkeypatch):
    current = []
    monkeypatch.setattr(ifaddr, "get_adapters", lambda: list(current))
    return current


@pytest.fixture(autouse=True)
def sysfs(tmp_path, monkeypatch):
    """An empty /sys/class/net, so the host's own interfaces do not leak in."""
    monkeypatch.setattr(_mdns_core, "SYSFS_NET", str(tmp_path))
    return tmp_path


def _operstate(sysfs, name, state):
    (sysfs / name).mkdir(exist_ok=True)
    (sysfs / name / "operstate").write_text(state + "\n")


# --- one-per-subnet -----------------------------------------------------------


@pytest.mark.parametrize("order", [[LO, ETH, WLAN], [LO, WLAN, ETH]])
def test_one_per_subnet_prefers_wired_on_a_shared_subnet(order, caplog):
    with caplog.at_level(logging.INFO, logger="ebus_service_discovery.mdns"):
        selection = _mdns_core.select_interfaces("one-per-subnet", order)
    assert _names(selection) == ["eth0"]
    assert "reason=interfaceSharesSubnet,kept=eth0,dropped=wlan0" in caplog.text


def test_one_per_subnet_keeps_both_on_different_subnets():
    selection = _mdns_core.select_interfaces("one-per-subnet", [LO, ETH, WLAN_OTHER])
    assert _names(selection) == ["eth0", "wlan0"]


def test_one_per_subnet_excludes_loopback():
    assert _mdns_core.select_interfaces("one-per-subnet", [LO]) == []


def test_one_per_subnet_wifi_only():
    assert _names(_mdns_core.select_interfaces("one-per-subnet", [LO, WLAN])) == ["wlan0"]


def test_one_per_subnet_two_wired_keeps_the_first():
    eth1 = _adapter("eth1", "192.0.2.12/24", index=4)
    assert _names(_mdns_core.select_interfaces("one-per-subnet", [eth1, ETH])) == ["eth1"]


def test_one_per_subnet_keeps_wifi_only_when_it_adds_a_subnet():
    # wlan0 is on eth0's subnet and on usb0's: both are covered, so it is dropped.
    wlan = _adapter("wlan0", "192.0.2.11/24", "203.0.113.11/24", index=3)
    usb = _adapter("usb0", "203.0.113.12/24", index=5)
    assert _names(_mdns_core.select_interfaces("one-per-subnet", [wlan, usb, ETH])) == [
        "usb0",
        "eth0",
    ]
    wlan = _adapter("wlan0", "192.0.2.11/24", "198.51.100.11/24", index=3)
    assert _names(_mdns_core.select_interfaces("one-per-subnet", [wlan, ETH])) == [
        "wlan0",
        "eth0",
    ]


def test_one_per_subnet_keeps_ipv6_only_adapter():
    v6 = _adapter("tun0", "2001:db8::20/64", "fe80::20/64", index=6)
    assert _names(_mdns_core.select_interfaces("one-per-subnet", [ETH, WLAN, v6])) == [
        "eth0",
        "tun0",
    ]


def test_one_per_subnet_leaves_out_link_local_only_adapters():
    veth = _adapter("veth1234", "fe80::99/64", index=9)
    assert _names(_mdns_core.select_interfaces("one-per-subnet", [LO, ETH, veth])) == ["eth0"]


def test_wireless_heuristic_reads_the_description():
    wifi = _adapter("{GUID-1}", "192.0.2.20/24", nice_name="Intel(R) Wi-Fi 6 AX201")
    wired = _adapter("{GUID-2}", "192.0.2.21/24", nice_name="Realtek PCIe GbE")
    assert _mdns_core.is_wireless(wifi) and not _mdns_core.is_wireless(wired)
    assert _names(_mdns_core.select_interfaces("one-per-subnet", [wifi, wired])) == ["{GUID-2}"]


# --- explicit selections ------------------------------------------------------


def test_all_selects_nothing_specific():
    assert _mdns_core.select_interfaces("all", [ETH]) is None
    assert _mdns_core.select_interfaces(["all"], [ETH]) is None


def test_names_and_addresses():
    sel = _mdns_core.select_interfaces(["wlan0"], [LO, ETH, WLAN])
    assert _names(sel) == ["wlan0"]
    assert [str(a) for a in sel[0].addresses()] == ["192.0.2.11", "fe80::11"]
    sel = _mdns_core.select_interfaces("192.0.2.10", [LO, ETH, WLAN])
    assert _names(sel) == ["eth0"] and [str(a) for a in sel[0].addresses()] == ["192.0.2.10"]
    sel = _mdns_core.select_interfaces(["fe80::11%wlan0", "eth0"], [LO, ETH, WLAN])
    assert _names(sel) == ["wlan0", "eth0"]


@pytest.mark.parametrize(
    "value, match",
    [
        (["nope0"], "no interface named 'nope0'"),
        (["203.0.113.9"], "no interface holds"),
        ([], "empty"),
        (["all", "eth0"], "all"),
        (["one-per-subnet", "eth0"], "one-per-subnet"),
    ],
)
def test_invalid_selection(value, match):
    with pytest.raises(ValueError, match=match):
        _mdns_core.select_interfaces(value, [LO, ETH, WLAN])


# --- the Zeroconf argument -----------------------------------------------------


def test_zeroconf_interfaces_by_ip_version():
    sel = _mdns_core.select_interfaces(["eth0", "wlan0"], [ETH, WLAN])
    assert _mdns_core.zeroconf_interfaces(sel, IPVersion.V4Only) == ["192.0.2.10", "192.0.2.11"]
    assert _mdns_core.zeroconf_interfaces(sel, IPVersion.All) == ["192.0.2.10", "192.0.2.11", 2, 3]
    assert _mdns_core.zeroconf_interfaces(sel, IPVersion.V6Only) == [2, 3]
    assert _mdns_core.zeroconf_interfaces(None, IPVersion.All) is InterfaceChoice.All
    v4 = _mdns_core.select_interfaces(["192.0.2.10"], [ETH])
    with pytest.raises(ValueError, match="V6Only"):
        _mdns_core.zeroconf_interfaces(v4, IPVersion.V6Only)


def test_resolve_interfaces(adapters):
    adapters += [LO, ETH, WLAN]
    assert _mdns_core.resolve_interfaces("one-per-subnet", IPVersion.All) == ["192.0.2.10", 2]
    assert _mdns_core.resolve_interfaces("all", IPVersion.All) is InterfaceChoice.All
    assert mdns_async.resolve_interfaces is _mdns_core.resolve_interfaces


def test_resolve_one_per_subnet_with_only_loopback_is_all(adapters):
    adapters.append(LO)
    assert _mdns_core.resolve_interfaces("one-per-subnet", IPVersion.V4Only) is InterfaceChoice.All


def test_addresses_of_a_selection(adapters):
    adapters += [LO, ETH, WLAN]
    selection = _mdns_core.select_interfaces("one-per-subnet")
    assert [str(a) for a in _mdns_core.addresses_of(selection)] == ["192.0.2.10", "fe80::10"]


# --- library-created instances -------------------------------------------------


def test_new_zeroconf_passes_the_selection(adapters, monkeypatch):
    adapters += [LO, ETH, WLAN]
    calls = []
    monkeypatch.setattr(_mdns_core, "default_ip_version", lambda: IPVersion.All)

    def fake(interfaces, ip_version):
        calls.append((interfaces, ip_version))
        if ip_version is IPVersion.All and len(calls) == 2:
            raise OSError("no IPv6")
        return "zc"

    monkeypatch.setattr(mdns, "Zeroconf", fake)
    assert mdns.new_zeroconf() == "zc"
    assert calls[-1] == (InterfaceChoice.All, IPVersion.All)
    assert mdns.new_zeroconf("one-per-subnet") == "zc"
    assert calls[-2:] == [(["192.0.2.10", 2], IPVersion.All), (["192.0.2.10"], IPVersion.V4Only)]


def test_interfaces_with_a_passed_zc_is_refused():
    with pytest.raises(ValueError, match="interfaces="):
        mdns.browse("_ebus._tcp", zc=object(), interfaces="all")
    with pytest.raises(ValueError, match="interfaces="):
        mdns.browse_many(["_ebus._tcp"], zc=object(), interfaces=["eth0"])
    with pytest.raises(ValueError, match="interfaces="):
        mdns.find_broker("configured-only", "mqtt://b.local", zc=object(), interfaces="all")


def test_browse_and_find_broker_default_to_all(monkeypatch):
    seen = []

    def factory(interfaces):
        seen.append(interfaces)
        return FakeZeroconf(start_loop=False)

    monkeypatch.setattr(mdns, "new_zeroconf", factory)
    monkeypatch.setattr(mdns, "_run", lambda zc, coro, timeout=None: coro.close() or [])
    mdns.browse("_ebus._tcp")
    mdns.browse_many(["_ebus._tcp"], interfaces=["eth0"])
    mdns.find_broker(
        "discovery-with-fallback",
        "mqtt://b.local",
        schedule=RetrySchedule(fast_attempts=1, fast_interval=0, max_attempts=1),
        interfaces="one-per-subnet",
    )
    assert seen == ["all", ["eth0"], "one-per-subnet"]


class Factory:
    """Records the selection each owned instance is created on."""

    def __init__(self):
        self.created = []

    def __call__(self, selection):
        zc = FakeZeroconf()
        self.created.append((None if selection is None else _names(selection), zc))
        return zc

    @property
    def selections(self):
        return [names for names, _ in self.created]


@pytest.fixture
def factory(monkeypatch):
    f = Factory()
    monkeypatch.setattr(mdns, "_zeroconf_on", f)
    return f


@pytest.mark.usefixtures("os_name")
def test_advertiser_defaults_to_one_per_subnet(adapters, factory):
    adapters += [LO, ETH, WLAN]
    with mdns.Advertiser(IDENT):
        pass
    with mdns.Advertiser(IDENT, interfaces="all"):
        pass
    assert factory.selections == [["eth0"], None]


def test_advertiser_invalid_interfaces_fail_before_network(adapters):
    adapters += [ETH]
    with pytest.raises(ValueError, match="one-per-subnet"):
        mdns.Advertiser(IDENT, interfaces=["one-per-subnet", "eth0"])
    with pytest.raises(ValueError, match="no interface of wlan9 is up"):
        mdns.Advertiser(IDENT, interfaces=["wlan9"], interface_check_interval=None).start()


def _no_os_responder(monkeypatch):
    async def none(zc, timeout=3.0, addresses=None):
        return None

    async def unanswered(zc, server, timeout):
        return False

    monkeypatch.setattr(_mdns_core, "async_os_hostname", none)
    monkeypatch.setattr(_mdns_core, "os_responder_present", lambda: False)
    monkeypatch.setattr(_mdns_core, "async_name_answered", unanswered)
    monkeypatch.setattr(_mdns_core, "fallback_hostname", lambda: "plain-host.local.")


def test_fallback_addresses_come_from_the_selected_interfaces(adapters, factory, monkeypatch):
    adapters += [LO, ETH, WLAN]
    _no_os_responder(monkeypatch)
    with mdns.Advertiser(IDENT) as adv:
        assert adv.infos[0].parsed_addresses() == ["192.0.2.10", "fe80::10"]
    zc = FakeZeroconf()
    with mdns.Advertiser(IDENT, zc=zc) as adv:  # a passed zc: all addresses
        assert adv.infos[0].parsed_addresses() == [
            "192.0.2.10",
            "192.0.2.11",
            "fe80::10",
            "fe80::11",
        ]
    zc.close()


def test_async_advertiser_interfaces_limit_fallback_addresses(adapters, monkeypatch):
    adapters += [LO, ETH, WLAN]
    _no_os_responder(monkeypatch)
    aiozc = FakeAsyncZeroconf()

    async def run():
        async with mdns_async.Advertiser(IDENT, aiozc, interfaces=["wlan0"]) as adv:
            return adv.infos[0].parsed_addresses()

    assert asyncio.run(run()) == ["192.0.2.11", "fe80::11"]


# --- ranked candidates and up state --------------------------------------------


def test_ranked_list_keeps_the_first_up_candidate_per_subnet(sysfs):
    assert _names(_mdns_core.advertise_selection(["eth0", "wlan0"], [ETH, WLAN])) == ["eth0"]
    assert _names(_mdns_core.advertise_selection(["wlan0", "eth0"], [ETH, WLAN])) == ["wlan0"]
    other = [ETH, WLAN_OTHER]
    assert _names(_mdns_core.advertise_selection(["wlan0", "eth0"], other)) == ["wlan0", "eth0"]
    _operstate(sysfs, "eth0", "down")
    assert _names(_mdns_core.advertise_selection(["eth0", "wlan0"], [ETH, WLAN])) == ["wlan0"]
    assert _names(_mdns_core.advertise_selection(["eth0", "wlan9"], [ETH, WLAN])) == []


def test_one_per_subnet_skips_an_interface_that_is_down(sysfs):
    _operstate(sysfs, "eth0", "down")
    assert _names(_mdns_core.select_interfaces("one-per-subnet", [LO, ETH, WLAN])) == ["wlan0"]
    _operstate(sysfs, "eth0", "up")
    assert _names(_mdns_core.select_interfaces("one-per-subnet", [LO, ETH, WLAN])) == ["eth0"]


def test_is_up():
    assert _mdns_core.is_up(ETH)  # no operstate (macOS): an address is enough
    assert not _mdns_core.is_up(_adapter("eth1"))


# --- re-selection when interfaces change ---------------------------------------

ETH_NO_ADDR = _adapter("eth0", index=2)


def _registered_names(zc):
    return sorted(zc.registered)


@pytest.mark.usefixtures("os_name")
def test_advertiser_moves_to_wifi_and_back(adapters, factory, caplog):
    adapters += [LO, ETH, WLAN]
    adv = mdns.Advertiser(IDENT, interface_check_interval=None).start()
    first = factory.created[0][1]
    names = _registered_names(first)
    assert factory.selections == [["eth0"]] and names

    assert not adv.check_interfaces()  # unchanged: nothing re-registered
    assert len(factory.created) == 1 and first.unregistered == []

    adapters[1] = ETH_NO_ADDR  # Ethernet loses its address
    with caplog.at_level(logging.INFO, logger="ebus_service_discovery.mdns"):
        assert adv.check_interfaces()
    assert "reason=advertiseInterfacesChanged,old=eth0,new=wlan0" in caplog.text
    assert first.closed and sorted(first.unregistered) == names
    second = factory.created[1][1]
    assert factory.selections[1] == ["wlan0"] and _registered_names(second) == names

    adapters[1] = ETH  # Ethernet is back
    assert adv.check_interfaces()
    assert factory.selections[2] == ["eth0"] and second.closed
    assert _registered_names(factory.created[2][1]) == names
    adv.stop()
    assert factory.created[2][1].closed


@pytest.mark.usefixtures("os_name")
def test_advertiser_moves_when_operstate_goes_down(adapters, factory, sysfs):
    adapters += [LO, ETH, WLAN]
    _operstate(sysfs, "eth0", "up")
    with mdns.Advertiser(IDENT, interface_check_interval=None) as adv:
        _operstate(sysfs, "eth0", "down")  # cable out, static address kept
        assert adv.check_interfaces()
        assert factory.selections == [["eth0"], ["wlan0"]]


@pytest.mark.usefixtures("os_name")
def test_advertiser_honors_a_ranked_list(adapters, factory):
    adapters += [LO, ETH, WLAN]
    with mdns.Advertiser(IDENT, interfaces=["wlan0", "eth0"], interface_check_interval=None) as adv:
        adapters[2] = _adapter("wlan0", index=3)  # Wi-Fi drops
        assert adv.check_interfaces()
        adapters[2] = WLAN
        assert adv.check_interfaces()
    assert factory.selections == [["wlan0"], ["eth0"], ["wlan0"]]


@pytest.mark.usefixtures("os_name")
def test_advertiser_stays_put_while_nothing_is_up(adapters, factory):
    adapters += [LO, ETH]
    with mdns.Advertiser(IDENT, interface_check_interval=None) as adv:
        adapters[1] = ETH_NO_ADDR
        assert not adv.check_interfaces()
        assert adv.running and len(factory.created) == 1
        adapters[1] = ETH  # the same interface returns: announce afresh
        assert adv.check_interfaces()
    assert factory.selections == [["eth0"], ["eth0"]]


@pytest.mark.usefixtures("os_name")
def test_advertiser_retries_a_failed_move(adapters, factory, monkeypatch):
    adapters += [LO, ETH, WLAN]
    with mdns.Advertiser(IDENT, interface_check_interval=None) as adv:
        adapters[1] = ETH_NO_ADDR

        def boom(selection):
            raise OSError("bind failed")

        monkeypatch.setattr(mdns, "_zeroconf_on", boom)
        assert not adv.check_interfaces() and not adv.running
        monkeypatch.setattr(mdns, "_zeroconf_on", factory)
        assert adv.check_interfaces() and adv.running
    assert factory.selections == [["eth0"], ["wlan0"]]


def test_advertiser_with_passed_zc_does_not_reselect(adapters, os_name):  # noqa: F811
    adapters += [LO, ETH, WLAN]
    zc = FakeZeroconf()
    with mdns.Advertiser(IDENT, zc=zc) as adv:
        adapters[1] = ETH_NO_ADDR
        assert not adv.check_interfaces()
        assert adv._watcher is None
    zc.close()


@pytest.mark.usefixtures("os_name")
def test_advertiser_watcher_thread_moves_and_stops(adapters, factory):
    adapters += [LO, ETH, WLAN]
    adv = mdns.Advertiser(IDENT, interface_check_interval=0.01).start()
    watcher = adv._watcher
    assert watcher.is_alive() and watcher.daemon
    adapters[1] = ETH_NO_ADDR
    deadline = time.monotonic() + 5
    while len(factory.created) < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert factory.selections[:2] == [["eth0"], ["wlan0"]]
    adv.stop()
    assert not watcher.is_alive() and adv._watcher is None
    assert all(zc.closed for _, zc in factory.created)


class OwnedAsyncZeroconf:
    """An ``AsyncZeroconf`` the async advertiser creates, on the running loop."""

    def __init__(self, selections, interfaces, ip_version):
        self.zeroconf = FakeZeroconf(start_loop=False)
        self.interfaces = interfaces
        self.closed = False
        selections.append(self)

    async def async_close(self):
        self.closed = True


@pytest.fixture
def async_factory(monkeypatch):
    created = []
    monkeypatch.setattr(_mdns_core, "default_ip_version", lambda: IPVersion.V4Only)
    monkeypatch.setattr(
        mdns_async,
        "AsyncZeroconf",
        lambda interfaces, ip_version: OwnedAsyncZeroconf(created, interfaces, ip_version),
    )
    return created


@pytest.mark.usefixtures("os_name")
def test_async_advertiser_owns_moves_and_stops(adapters, async_factory, caplog):
    adapters += [LO, ETH, WLAN]

    async def run():
        adv = mdns_async.Advertiser(IDENT, interface_check_interval=None)
        await adv.start()
        assert not await adv.check_interfaces()
        adapters[1] = ETH_NO_ADDR
        assert await adv.check_interfaces()
        adapters[1] = ETH
        assert await adv.check_interfaces()
        await adv.stop()
        return adv

    with caplog.at_level(logging.INFO, logger="ebus_service_discovery.mdns"):
        adv = asyncio.run(run())
    assert [z.interfaces for z in async_factory] == [
        ["192.0.2.10"],
        ["192.0.2.11"],
        ["192.0.2.10"],
    ]
    assert all(z.closed for z in async_factory) and not adv.running
    assert async_factory[0].zeroconf.unregistered and async_factory[2].zeroconf.registered == {}
    assert "reason=advertiseInterfacesChanged,old=wlan0,new=eth0" in caplog.text


@pytest.mark.usefixtures("os_name")
def test_async_advertiser_watcher_task_moves_and_is_cancelled(adapters, async_factory):
    adapters += [LO, ETH, WLAN]

    async def run():
        adv = mdns_async.Advertiser(IDENT, interface_check_interval=0.01)
        await adv.start()
        task = adv._watcher
        adapters[1] = ETH_NO_ADDR
        for _ in range(500):
            if len(async_factory) > 1:
                break
            await asyncio.sleep(0.01)
        await adv.stop()
        return task, adv

    task, adv = asyncio.run(run())
    assert len(async_factory) == 2 and task.cancelled() and adv._watcher is None
    assert all(z.closed for z in async_factory)


def test_async_advertiser_with_passed_aiozc_starts_no_task(os_name):  # noqa: F811
    aiozc = FakeAsyncZeroconf()

    async def run():
        async with mdns_async.Advertiser(IDENT, aiozc) as adv:
            assert adv._watcher is None and not await adv.check_interfaces()

    asyncio.run(run())
    assert not aiozc.closed


# --- what makes a move ------------------------------------------------------------

ETH_V6 = _adapter("eth0", "192.0.2.10/24", "2001:db8::aaaa/64", "fe80::10/64", index=2)
ETH_V6_ROTATED = _adapter("eth0", "192.0.2.10/24", "2001:db8::bbbb/64", "fe80::10/64", index=2)
VETH = _adapter("veth1234", "fe80::99/64", index=9)


@pytest.mark.usefixtures("os_name")
def test_ipv6_churn_and_link_local_veths_do_not_move(adapters, factory):
    adapters += [LO, ETH_V6]
    with mdns.Advertiser(IDENT, interface_check_interval=None) as adv:
        adapters[1] = ETH_V6_ROTATED  # temporary address rotates
        assert not adv.check_interfaces()
        adapters.append(VETH)  # a container starts
        assert not adv.check_interfaces()
        adapters.pop()  # and stops
        assert not adv.check_interfaces()
        assert len(factory.created) == 1 and factory.created[0][1].unregistered == []
    with mdns.Advertiser(IDENT, interfaces="all", interface_check_interval=None) as adv:
        adapters.append(VETH)
        assert not adv.check_interfaces()
    assert len(factory.created) == 2


def _count_detection(monkeypatch):
    calls = []
    for attr in ("async_os_hostname", "async_name_answered"):
        inner = getattr(_mdns_core, attr)

        async def counted(*args, _inner=inner, _attr=attr, **kw):
            calls.append(_attr)
            return await _inner(*args, **kw)

        monkeypatch.setattr(_mdns_core, attr, counted)
    return calls


def test_address_change_without_os_responder_updates_in_place(adapters, factory, monkeypatch):
    adapters += [LO, ETH_V6]
    _no_os_responder(monkeypatch)
    calls = _count_detection(monkeypatch)
    with mdns.Advertiser(IDENT, interface_check_interval=None) as adv:
        zc = factory.created[0][1]
        names = _registered_names(zc)
        adapters[1] = ETH_V6_ROTATED
        assert adv.check_interfaces()
        assert len(factory.created) == 1 and zc.unregistered == []
        assert sorted(zc.updated) == names
        assert adv.infos[0].parsed_addresses() == ["192.0.2.10", "2001:db8::bbbb", "fe80::10"]
        adapters.append(VETH)  # left out: neither a move nor new addresses
        assert not adv.check_interfaces()
    assert calls == ["async_os_hostname", "async_name_answered"]


def test_move_reuses_the_host_name(adapters, factory, monkeypatch):
    adapters += [LO, ETH, WLAN]
    _no_os_responder(monkeypatch)
    calls = _count_detection(monkeypatch)
    with mdns.Advertiser(IDENT, interface_check_interval=None) as adv:
        adapters[1] = ETH_NO_ADDR
        assert adv.check_interfaces()
        assert adv.server == "plain-host.local."
        assert adv.infos[0].parsed_addresses() == ["192.0.2.11", "fe80::11"]
    assert calls == ["async_os_hostname", "async_name_answered"]


@pytest.mark.usefixtures("os_name")
def test_ranked_list_waits_for_an_interface_at_start(adapters, factory):
    adapters += [LO]
    adv = mdns.Advertiser(IDENT, interfaces=["eth0", "wlan0"], interface_check_interval=None)
    with pytest.raises(ValueError, match="no interface of eth0, wlan0 is up"):
        adv.start()
    adv = mdns.Advertiser(IDENT, interfaces=["eth0", "wlan0"], interface_check_interval=0.01)
    adv.start()
    try:
        assert not adv.running and factory.created == []
        adapters.append(WLAN)
        deadline = time.monotonic() + 5
        while not adv.running and time.monotonic() < deadline:
            time.sleep(0.01)
        assert adv.running and factory.selections == [["wlan0"]]
    finally:
        adv.stop()
    assert factory.created[0][1].closed


def test_passed_zc_with_no_address_on_the_interfaces_raises(adapters, monkeypatch):
    adapters += [LO, ETH_NO_ADDR, WLAN]
    _no_os_responder(monkeypatch)
    zc = FakeZeroconf()
    try:
        with pytest.raises(ValueError, match="no address to publish"):
            mdns.Advertiser(IDENT, zc=zc, interfaces=["eth0"]).start()
        with pytest.raises(ValueError, match="no interface named 'eth9'"):
            mdns.Advertiser(IDENT, zc=zc, interfaces=["eth9"]).start()
        assert zc.registered == {}
    finally:
        zc.close()


def test_passed_zc_reads_a_list_as_resolve_interfaces_does(adapters, monkeypatch):
    adapters += [LO, ETH, WLAN]
    _no_os_responder(monkeypatch)
    zc = FakeZeroconf()
    with mdns.Advertiser(IDENT, zc=zc, interfaces=["eth0", "wlan0"]) as adv:
        assert adv.infos[0].parsed_addresses() == [
            "192.0.2.10",
            "192.0.2.11",
            "fe80::10",
            "fe80::11",
        ]
    zc.close()


def test_async_advertiser_waits_then_readdresses(adapters, async_factory, monkeypatch):
    adapters += [LO]
    _no_os_responder(monkeypatch)

    async def run():
        adv = mdns_async.Advertiser(IDENT, interfaces=["eth0"], interface_check_interval=None)
        with pytest.raises(ValueError, match="no interface of eth0 is up"):
            await adv.start()
        adv._interval = 3600  # a watcher that never fires on its own
        await adv.start()
        assert not adv.running and async_factory == []
        adapters.append(ETH_V6)
        assert await adv.check_interfaces() and adv.running
        adapters[1] = ETH_V6_ROTATED
        assert await adv.check_interfaces()
        addresses = adv.infos[0].parsed_addresses()
        await adv.stop()
        return addresses

    assert asyncio.run(run()) == ["192.0.2.10", "2001:db8::bbbb", "fe80::10"]
    assert len(async_factory) == 1 and async_factory[0].zeroconf.updated

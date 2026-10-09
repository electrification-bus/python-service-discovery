"""Interface selection (``interfaces=``), against stubbed ifaddr adapters."""

import asyncio
import logging

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
    v6 = _adapter("tun0", "fe80::20/64", index=6)
    assert _names(_mdns_core.select_interfaces("one-per-subnet", [ETH, WLAN, v6])) == [
        "eth0",
        "tun0",
    ]


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


def test_selected_addresses(adapters):
    adapters += [LO, ETH, WLAN]
    assert [str(a) for a in _mdns_core.selected_addresses("one-per-subnet")] == [
        "192.0.2.10",
        "fe80::10",
    ]


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


@pytest.mark.usefixtures("os_name")
def test_advertiser_defaults_to_one_per_subnet(monkeypatch):
    seen = []

    def factory(interfaces):
        seen.append(interfaces)
        return FakeZeroconf()

    monkeypatch.setattr(mdns, "new_zeroconf", factory)
    with mdns.Advertiser(IDENT):
        pass
    with mdns.Advertiser(IDENT, interfaces="all"):
        pass
    assert seen == ["one-per-subnet", "all"]


def test_advertiser_invalid_interfaces_fail_before_network(adapters):
    adapters += [ETH]
    with pytest.raises(ValueError, match="wlan9"):
        mdns.Advertiser(IDENT, interfaces=["wlan9"])


def _no_os_responder(monkeypatch):
    async def none(zc, timeout=3.0, addresses=None):
        return None

    async def unanswered(zc, server, timeout):
        return False

    monkeypatch.setattr(_mdns_core, "async_os_hostname", none)
    monkeypatch.setattr(_mdns_core, "os_responder_present", lambda: False)
    monkeypatch.setattr(_mdns_core, "async_name_answered", unanswered)
    monkeypatch.setattr(_mdns_core, "fallback_hostname", lambda: "plain-host.local.")


def test_fallback_addresses_come_from_the_selected_interfaces(adapters, monkeypatch):
    adapters += [LO, ETH, WLAN]
    _no_os_responder(monkeypatch)
    monkeypatch.setattr(mdns, "new_zeroconf", lambda interfaces: FakeZeroconf())
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

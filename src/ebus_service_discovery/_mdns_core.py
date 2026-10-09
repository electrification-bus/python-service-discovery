"""Shared asyncio core of ``mdns`` and ``mdns_async`` (needs the ``[zeroconf]`` extra).

Everything here runs on the event loop of a ``zeroconf.Zeroconf`` instance:
``mdns_async`` awaits it directly and ``mdns`` submits it to the loop thread
of a synchronous ``Zeroconf``.

Advertising under the host's existing ``.local`` name
------------------------------------------------------

An entity advertises its services under the name the operating system's mDNS
responder already claims (mDNSResponder on macOS, avahi-daemon on most Linux
distributions). These findings, measured on macOS against mDNSResponder,
shape how:

1. The services carry no address records of their own. The SRV target is the
   OS host name and the OS responder answers the A/AAAA queries for it, per
   interface. Resolution worked from both python-zeroconf and ``dns-sd -L``,
   and mDNSResponder logged no conflict.

2. Publishing addresses from python-zeroconf under the OS name is harmful.
   It answers with every address of the host on every interface, including
   the loopback interface, so a peer on one link learns addresses reachable
   only on another. An address the OS responder does not hold for that name
   made mDNSResponder log repeated name conflicts. Worst, while mDNSResponder
   was re-probing its name, python-zeroconf's address records counted as a
   conflict: mDNSResponder gave up the name and renamed the host to
   ``<name>-2.local``, a rename that persists. avahi-daemon also resolves a
   host-name conflict by renaming the host; how it treats such records from
   its own host was not measured.

3. The OS name is found by asking the OS responder over mDNS for the reverse
   mapping (``PTR`` of ``<addr>.in-addr.arpa`` / ``ip6.arpa``) of this host's
   own addresses. mDNSResponder answers with its current name, which can
   differ from ``socket.gethostname()``. A responder that is probing its name
   does not answer, so the query is repeated within the timeout. avahi-daemon
   publishes the same reverse records by default (``publish-addresses=yes``);
   that it answers the same way has not been measured here.

So addresses are published only when no OS responder is present (see
``os_responder_present``): the advertiser then uses ``<gethostname>.local``,
after checking that no other host answers for it. When an OS responder is
present but does not answer, advertising fails rather than guess.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import socket
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence

from zeroconf import (
    BadTypeInNameException,
    DNSAddress,
    DNSOutgoing,
    DNSPointer,
    DNSQuestion,
    InterfaceChoice,
    IPVersion,
    NonUniqueNameException,
    ServiceInfo,
    ServiceNameAlreadyRegistered,
    ServiceStateChange,
    Zeroconf,
)
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo

from ebus_service_discovery.ebus import (
    BROKER_PREFERENCE,
    DEVICE_INFO_SERVICE,
    EBUS_SERVICE,
    ROLE_BROKER_HOST,
    SECURE_MQTT_SERVICE,
    TCP_BROKER_TYPES,
    BrokerEndpoint,
    BrokerMode,
    BrokerService,
    HttpService,
    Identity,
    decode_txt,
    rank_brokers,
    select_broker,
)
from ebus_service_discovery.instance import ServiceInstance, strip_dot
from ebus_service_discovery.record import Address

logger = logging.getLogger("ebus_service_discovery.mdns")

_DOMAIN = "local."
_TYPE_A = 1
_TYPE_PTR = 12
_TYPE_AAAA = 28
_CLASS_IN = 1
_FLAGS_QR_QUERY = 0x0000

#: Instance-name suffixes tried on a conflict: ``-2`` through ``-99``.
MAX_RENAME_SUFFIX = 99
#: Longest device id used as the default instance name: one 63-octet DNS
#: label less the ``-99`` suffix.
MAX_DEFAULT_INSTANCE_OCTETS = 63 - len(f"-{MAX_RENAME_SUFFIX}")


def fq_type(service_type: str) -> str:
    """``_ebus._tcp`` -> ``_ebus._tcp.local.`` (an already-qualified type passes)."""
    t = service_type.rstrip(".")
    if t.endswith(".local"):
        t = t[: -len(".local")]
    return f"{t}.{_DOMAIN}"


def bare_type(service_type: str) -> str:
    """``_ebus._tcp.local.`` -> ``_ebus._tcp``."""
    return fq_type(service_type)[: -len(_DOMAIN) - 1]


# --- browse ------------------------------------------------------------------


def info_to_instance(info: ServiceInfo, service_type: str) -> ServiceInstance:
    """A resolved ``ServiceInfo`` as a ``ServiceInstance``.

    ``interface`` is set from ``info.interface_index``, which python-zeroconf
    fills only for a scoped (link-local) IPv6 answer; an IPv4-only result has
    no interface.
    """
    full = fq_type(service_type)
    name = info.name
    instance = name[: -len(full) - 1] if name.endswith("." + full) else name
    interface = None
    if info.interface_index:
        try:
            interface = socket.if_indextoname(info.interface_index)
        except OSError:
            interface = None
    return ServiceInstance(
        service_type=bare_type(service_type),
        instance_name=instance,
        server=strip_dot(info.server or ""),
        port=info.port or 0,
        addresses=tuple(Address.parse(a) for a in info.parsed_scoped_addresses(IPVersion.All)),
        txt=decode_txt(info.properties or {}),
        interface=interface,
    )


async def async_browse(zc: Zeroconf, service_type: str, timeout: float) -> list[ServiceInstance]:
    """Browse one service type for ``timeout`` seconds, resolving each instance as it is seen.

    Returns within ``timeout``. An instance that is not resolved (SRV, TXT and
    an address) by then, or that was removed, is left out. A responder usually
    sends the SRV, TXT and address records with its answer, so most instances
    resolve from the cache at once.
    """
    full = fq_type(service_type)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    pending: dict[str, tuple[AsyncServiceInfo, asyncio.Future]] = {}

    def on_change(
        zeroconf: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange
    ) -> None:
        if state_change is ServiceStateChange.Removed:
            entry = pending.pop(name, None)
            if entry is not None:
                entry[1].cancel()
        elif name not in pending:
            info = AsyncServiceInfo(full, name)
            wait_ms = max(int(1000 * (deadline - loop.time())), 0)
            pending[name] = (info, asyncio.ensure_future(info.async_request(zc, wait_ms)))

    browser = AsyncServiceBrowser(zc, full, handlers=[on_change])
    try:
        await asyncio.sleep(timeout)
    except BaseException:
        for _, task in pending.values():
            task.cancel()
        raise
    finally:
        await browser.async_cancel()
    # Each request ends by the shared deadline, so this wait is short.
    entries = list(pending.values())
    results = await asyncio.gather(*(task for _, task in entries), return_exceptions=True)
    out = []
    for (info, _), ok in zip(entries, results, strict=True):
        if ok is True:
            out.append(info_to_instance(info, full))
        else:
            logger.debug("reason=resolveTimeout,name=%s", info.name)
    return out


async def async_browse_many(
    zc: Zeroconf, service_types: Sequence[str], timeout: float
) -> list[ServiceInstance]:
    """Browse several service types at once; results in ``service_types`` order."""
    batches = await asyncio.gather(*(async_browse(zc, t, timeout) for t in service_types))
    return [inst for batch in batches for inst in batch]


# --- broker resolution -------------------------------------------------------


def configured_endpoint(url: str | None, base_cfg: Mapping | None) -> BrokerEndpoint | None:
    """The configured broker: ``url`` if given, else ``base_cfg``'s host/port/use_tls."""
    if url:
        return BrokerEndpoint.from_url(url)
    if base_cfg and base_cfg.get("host"):
        return BrokerEndpoint.from_mqtt_cfg(base_cfg)
    return None


class BrokerSearch:
    """The mode and retry decisions of ``find_broker``, without I/O.

    ``mdns.find_broker`` and ``mdns_async.find_broker`` drive one of these:
    for each attempt they browse ``browse_types`` and pass the results to
    ``decide``, which returns ``(done, endpoint)``.

    ``accept`` defaults to ``TCP_BROKER_TYPES``, or to ``_secure-mqtt._tcp``
    alone when TLS is configured (an ``mqtts://`` url or ``base_cfg``
    ``use_tls``), so the credentials of a TLS config are never sent to a
    plain broker that answered the multicast query. In
    ``discovery-with-fallback`` with a configured broker, only a discovered
    broker that matches it (``ebus.match_configured``) is chosen, unless
    ``allow_unmatched``; the configured broker is returned after
    ``fast_attempts`` attempts without a match, or after ``max_attempts`` if
    that is fewer.
    """

    def __init__(
        self,
        mode: BrokerMode | str | None,
        url: str | None,
        base_cfg: Mapping | None,
        accept: Sequence[str] | None = None,
        fast_attempts: int = 3,
        max_attempts: int | None = None,
        allow_unmatched: bool = False,
    ):
        self.mode = BrokerMode.parse(mode)
        self.allow_unmatched = allow_unmatched
        self.configured = configured_endpoint(url, base_cfg)
        self.requires_tls = bool(
            (self.configured is not None and self.configured.use_tls)
            or (base_cfg and base_cfg.get("use_tls"))
        )
        if accept is None:
            accept = (SECURE_MQTT_SERVICE,) if self.requires_tls else TCP_BROKER_TYPES
        self.accept = tuple(accept)
        self.fallback_after = (
            fast_attempts if max_attempts is None else min(fast_attempts, max_attempts)
        )
        if self.mode is BrokerMode.CONFIGURED_ONLY and self.configured is None:
            raise ValueError("configured-only needs a broker url or a base_cfg with a host")
        # Browse every broker type so an unusable (WebSocket) broker is reported.
        self.browse_types = tuple(BROKER_PREFERENCE)

    @property
    def needs_browse(self) -> bool:
        return self.mode is not BrokerMode.CONFIGURED_ONLY

    def decide(
        self, found: Iterable[ServiceInstance], attempt: int
    ) -> tuple[bool, BrokerEndpoint | None]:
        endpoints = [BrokerEndpoint.from_instance(i) for i in found]
        usable = rank_brokers(endpoints, accept=self.accept)
        usable_hosts = {e.host.lower() for e in usable}
        for ep in rank_brokers(endpoints):
            if ep.service_type not in self.accept and ep.host.lower() not in usable_hosts:
                logger.info(
                    "reason=brokerTransportNotAccepted,url=%s,accept=%s",
                    ep.url,
                    "|".join(self.accept),
                )
        if usable:
            chosen = select_broker(
                self.mode, self.configured, usable, allow_unmatched=self.allow_unmatched
            )
            if chosen is not self.configured:
                logger.info("reason=brokerDiscovered,url=%s,attempt=%d", chosen.url, attempt + 1)
                return True, chosen
        else:
            logger.info("reason=brokerNotFound,attempt=%d", attempt + 1)
        if (
            self.mode is BrokerMode.DISCOVERY_WITH_FALLBACK
            and self.configured is not None
            and attempt + 1 >= self.fallback_after
        ):
            logger.info("reason=brokerFallbackToConfigured,url=%s", self.configured.url)
            return True, self.configured
        return False, None


# --- interface selection -----------------------------------------------------

#: Every interface: python-zeroconf's ``InterfaceChoice.All``.
INTERFACES_ALL = "all"
#: One interface per IPv4 subnet, preferring wired over Wi-Fi.
INTERFACES_ONE_PER_SUBNET = "one-per-subnet"
INTERFACE_POLICIES = (INTERFACES_ALL, INTERFACES_ONE_PER_SUBNET)

_WIRELESS_PREFIXES = ("wl", "wifi")
_WIRELESS_WORDS = ("wi-fi", "wifi", "wireless", "wlan")
#: Where Linux lists network interfaces.
SYSFS_NET = "/sys/class/net"


def _ip_text(ip) -> str:
    return ip.ip if isinstance(ip.ip, str) else ip.ip[0]


def _parse_ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return None


def _is_loopback_adapter(adapter) -> bool:
    return any(_ip_text(ip) in ("127.0.0.1", "::1") for ip in adapter.ips)


def is_wireless(adapter) -> bool:
    """The Wi-Fi heuristic of ``"one-per-subnet"``.

    True when the name starts with ``wl`` or ``wifi`` (``wlan0``, ``wlp3s0``),
    the description says Wi-Fi, wireless or WLAN, or ``/sys/class/net/<name>``
    has a ``wireless`` or ``phy80211`` entry. Anything else counts as wired.
    """
    name = (adapter.name or "").lower()
    nice = (adapter.nice_name or "").lower()
    if name.startswith(_WIRELESS_PREFIXES):
        return True
    if any(w in nice for w in _WIRELESS_WORDS):
        return True
    sysfs = f"{SYSFS_NET}/{adapter.name}"
    return os.path.exists(f"{sysfs}/wireless") or os.path.exists(f"{sysfs}/phy80211")


#: Linux ``operstate`` values of an interface that cannot carry traffic.
_NOT_UP_OPERSTATES = ("down", "lowerlayerdown", "dormant", "notpresent")


def is_up(adapter) -> bool:
    """True when the adapter has an address and, where Linux reports
    ``/sys/class/net/<name>/operstate``, that state is not down. Elsewhere an
    address is all that is checked.
    """
    if not adapter.ips:
        return False
    try:
        with open(f"{SYSFS_NET}/{adapter.name}/operstate") as f:
            state = f.read().strip()
    except OSError:
        return True
    return state not in _NOT_UP_OPERSTATES


class SelectedInterface:
    """One selected adapter and the addresses selected on it."""

    def __init__(self, name: str, index: int | None, ips: Sequence):
        self.name = name
        self.index = index
        self.ips = list(ips)

    def addresses(self) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        out = []
        for ip in self.ips:
            addr = _parse_ip(_ip_text(ip))
            if addr is not None:
                out.append(addr)
        return out

    def __repr__(self) -> str:
        return f"SelectedInterface({self.name!r}, {[str(a) for a in self.addresses()]})"


def _ipv4_networks(ips: Sequence) -> set[ipaddress.IPv4Network]:
    nets = set()
    for ip in ips:
        if isinstance(ip.ip, str):
            try:
                nets.add(ipaddress.ip_interface(f"{ip.ip}/{ip.network_prefix}").network)
            except ValueError:
                continue
    return nets


def _per_subnet(candidates: Sequence[SelectedInterface]) -> list[SelectedInterface]:
    """Keep, in order, each candidate with an IPv4 subnet that no candidate
    kept before it has, or with no IPv4 address at all."""
    covered: dict[ipaddress.IPv4Network, str] = {}
    kept = []
    for cand in candidates:
        nets = _ipv4_networks(cand.ips)
        if not nets or nets - covered.keys():
            kept.append(cand)
            for net in nets:
                covered.setdefault(net, cand.name)
        else:
            logger.info(
                "reason=interfaceSharesSubnet,kept=%s,dropped=%s",
                ",".join(sorted({covered[n] for n in nets})),
                cand.name,
            )
    return kept


def _one_per_subnet(adapters: Sequence) -> list:
    """Collapse adapters that share an IPv4 subnet to one, preferring wired.

    Loopback adapters and adapters that are not up (``is_up``) are left out.
    Wired adapters are considered before Wi-Fi ones, each kind in
    ``adapters`` order; an adapter is kept when it has an IPv4 subnet that no
    adapter kept before it has, or no IPv4 address at all. Results are in
    ``adapters`` order.
    """
    candidates = [a for a in adapters if not _is_loopback_adapter(a) and is_up(a)]
    order = sorted(range(len(candidates)), key=lambda i: (is_wireless(candidates[i]), i))
    kept = _per_subnet([SelectedInterface(candidates[i].name, i, candidates[i].ips) for i in order])
    keep = {sel.index for sel in kept}
    return [a for i, a in enumerate(candidates) if i in keep]


def _entries(interfaces: str | Sequence[str]) -> list[str] | None:
    """The entries of an ``interfaces=`` value; None for ``"all"``."""
    entries = [interfaces] if isinstance(interfaces, str) else list(interfaces)
    if not entries:
        raise ValueError("interfaces= is empty")
    if INTERFACES_ALL in entries:
        if len(entries) > 1:
            raise ValueError('"all" cannot be combined with other interfaces')
        return None
    if INTERFACES_ONE_PER_SUBNET in entries and len(entries) > 1:
        raise ValueError('"one-per-subnet" cannot be combined with other interfaces')
    return entries


def validate_interfaces(interfaces: str | Sequence[str]) -> None:
    """Raise ``ValueError`` for an ``interfaces=`` value no host could satisfy."""
    _entries(interfaces)


def get_adapters(adapters: Sequence | None = None) -> list:
    """``adapters``, else ``ifaddr.get_adapters()``."""
    if adapters is None:
        import ifaddr  # a zeroconf dependency

        adapters = ifaddr.get_adapters()
    return list(adapters)


def _matches(entry: str, adapters: Sequence) -> list[tuple[object, list]]:
    """The adapters an entry names, each with the addresses it selects."""
    addr = _parse_ip(entry)
    if addr is None:
        return [(a, list(a.ips)) for a in adapters if entry in (a.name, a.nice_name)]
    return [
        (adapter, [ip])
        for adapter in adapters
        for ip in adapter.ips
        if _parse_ip(_ip_text(ip)) == addr
    ]


def _merge(pairs: Iterable[tuple[object, list]]) -> list[SelectedInterface]:
    selected: dict[str, SelectedInterface] = {}
    for adapter, ips in pairs:
        entry = selected.setdefault(
            adapter.name, SelectedInterface(adapter.name, adapter.index, [])
        )
        for ip in ips:
            if ip not in entry.ips:
                entry.ips.append(ip)
    return list(selected.values())


def select_interfaces(
    interfaces: str | Sequence[str], adapters: Sequence | None = None
) -> list[SelectedInterface] | None:
    """The adapters an ``interfaces=`` value selects; None for ``"all"``.

    ``interfaces`` is ``"all"``, ``"one-per-subnet"``, or one or more interface
    names (``eth0``; on Windows the adapter name or its description) and
    addresses (``192.0.2.7``, ``fe80::1%eth0``). A name selects every address
    of that adapter; an address selects only itself. An unknown name or an
    address no adapter holds raises ``ValueError``. ``adapters`` defaults to
    ``ifaddr.get_adapters()``. ``Advertiser`` reads a list differently; see
    ``advertise_selection``.
    """
    entries = _entries(interfaces)
    if entries is None:
        return None
    adapters = get_adapters(adapters)
    if entries == [INTERFACES_ONE_PER_SUBNET]:
        return [SelectedInterface(a.name, a.index, a.ips) for a in _one_per_subnet(adapters)]
    pairs = []
    for entry in entries:
        found = _matches(entry, adapters)
        if not found:
            if _parse_ip(entry) is not None:
                raise ValueError(f"no interface holds the address {entry}")
            names = ", ".join(sorted({a.name for a in adapters}))
            raise ValueError(f"no interface named {entry!r} (have: {names})")
        pairs += found
    return _merge(pairs)


def advertise_selection(
    interfaces: str | Sequence[str], adapters: Sequence | None = None
) -> list[SelectedInterface] | None:
    """The interfaces an ``Advertiser`` uses now; None for ``"all"``.

    ``"one-per-subnet"`` is as in ``select_interfaces``. A list of names and
    addresses is a ranked candidate set: candidates that are not up
    (``is_up``) or not present are skipped, and of the rest sharing an IPv4
    subnet the first listed is kept. Returns ``[]`` when nothing is selected.
    """
    entries = _entries(interfaces)
    if entries is None:
        return None
    adapters = get_adapters(adapters)
    if entries == [INTERFACES_ONE_PER_SUBNET]:
        return select_interfaces(INTERFACES_ONE_PER_SUBNET, adapters)
    pairs = [
        (adapter, ips)
        for entry in entries
        for adapter, ips in _matches(entry, adapters)
        if is_up(adapter)
    ]
    return _per_subnet(_merge(pairs))


def zeroconf_interfaces(
    selection: list[SelectedInterface] | None, ip_version: IPVersion
) -> InterfaceChoice | list[str | int]:
    """The ``Zeroconf(interfaces=...)`` value for a selection.

    ``InterfaceChoice.All`` for None (``"all"``); otherwise the IPv4
    addresses, plus the interface index of each adapter with an IPv6 address
    when ``ip_version`` includes IPv6 (python-zeroconf joins IPv6 multicast by
    index). Raises ``ValueError`` when nothing usable for ``ip_version`` is
    selected.
    """
    if selection is None:
        return InterfaceChoice.All
    v4: list[str] = []
    v6: list[int] = []
    for sel in selection:
        for ip in sel.ips:
            if isinstance(ip.ip, str):
                if ip_version is not IPVersion.V6Only and ip.ip not in v4:
                    v4.append(ip.ip)
            elif (
                ip_version is not IPVersion.V4Only and sel.index is not None and sel.index not in v6
            ):
                v6.append(sel.index)
    out: list[str | int] = [*v4, *v6]
    if not out:
        names = ",".join(s.name for s in selection) or "none"
        raise ValueError(f"no {ip_version.name} address on the selected interfaces ({names})")
    return out


def resolve_interfaces(
    interfaces: str | Sequence[str], ip_version: IPVersion | None = None
) -> InterfaceChoice | list[str | int]:
    """An ``interfaces=`` value as the ``interfaces`` argument of ``Zeroconf``.

    ``ip_version`` defaults to ``default_ip_version()``; pass the same value
    to ``Zeroconf`` / ``AsyncZeroconf``. ``"one-per-subnet"`` on a host with
    no interface but loopback resolves to ``InterfaceChoice.All``.
    """
    version = ip_version if ip_version is not None else default_ip_version()
    return zeroconf_interfaces(instance_selection(interfaces), version)


def instance_selection(interfaces: str | Sequence[str]) -> list[SelectedInterface] | None:
    """``select_interfaces``, with ``"one-per-subnet"`` on a host with no
    interface but loopback falling back to ``"all"`` (None)."""
    selection = select_interfaces(interfaces)
    if selection == [] and interfaces == INTERFACES_ONE_PER_SUBNET:
        logger.info("reason=noInterfaceSelected,fallback=all")
        selection = None
    return selection


def create_instance(factory: Callable, selection: list[SelectedInterface] | None):
    """``factory(interfaces=..., ip_version=...)`` (``Zeroconf`` or
    ``AsyncZeroconf``) on ``selection``, at ``default_ip_version()``; IPv4
    only if IPv6 is unavailable."""
    version = default_ip_version()
    try:
        return factory(interfaces=zeroconf_interfaces(selection, version), ip_version=version)
    except OSError:
        if version is IPVersion.V4Only:
            raise
        logger.info("reason=ipv6Unavailable,fallback=ipv4")
        return factory(
            interfaces=zeroconf_interfaces(selection, IPVersion.V4Only),
            ip_version=IPVersion.V4Only,
        )


def addresses_of(
    selection: list[SelectedInterface] | None,
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """The addresses of a selection (None: ``local_addresses()``), ordered as
    ``local_addresses``."""
    if selection is None:
        return local_addresses()
    found: dict[str, ipaddress.IPv4Address | ipaddress.IPv6Address] = {}
    for sel in selection:
        for addr in sel.addresses():
            if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
                continue
            found[str(addr)] = addr
    return sorted(found.values(), key=lambda a: (a.version, a.is_link_local))


# --- re-selecting the advertised interfaces ----------------------------------

#: Default seconds between interface checks of an ``Advertiser`` that owns its instance.
DEFAULT_INTERFACE_CHECK_INTERVAL = 5.0


def interface_snapshot(adapters: Sequence) -> tuple:
    """What the interface check compares: each adapter's name, ``is_up`` and addresses."""
    return tuple(
        (a.name, is_up(a), tuple(sorted(f"{_ip_text(ip)}/{ip.network_prefix}" for ip in a.ips)))
        for a in adapters
    )


def _selection_key(selection: list[SelectedInterface] | None, adapters: Sequence) -> tuple:
    if selection is None:  # "all": every interface that is up
        selection = [
            SelectedInterface(a.name, a.index, a.ips)
            for a in adapters
            if is_up(a) and not _is_loopback_adapter(a)
        ]
    return tuple((s.name, tuple(sorted(_ip_text(ip) for ip in s.ips))) for s in selection)


def _describe(key: tuple) -> str:
    return "+".join(name for name, _ in key) or "none"


class InterfaceWatch:
    """Which interfaces an ``Advertiser`` that owns its instance advertises on,
    and when to move.

    ``initial()`` selects the interfaces to start on. ``check()`` takes a new
    ``ifaddr`` snapshot and, when it differs from the last one and the
    selection it yields differs from the advertised one, returns
    ``(True, selection)``; the caller then moves and reports ``moved()`` or
    ``failed()`` (a failed move is retried on the next check). When no
    interface is up the advertisement stays where it is.
    """

    def __init__(self, interfaces: str | Sequence[str]):
        validate_interfaces(interfaces)
        self.interfaces = interfaces
        self._snapshot: tuple | None = None
        self._key: tuple = ()
        self._pending: tuple = ()

    def initial(self, adapters: Sequence | None = None) -> list[SelectedInterface] | None:
        """The selection to start on; raises ``ValueError`` when a list selects nothing."""
        adapters = get_adapters(adapters)
        selection = advertise_selection(self.interfaces, adapters)
        entries = _entries(self.interfaces) or []
        if entries != [INTERFACES_ONE_PER_SUBNET]:
            missing = [e for e in entries if not _matches(e, adapters)]
            if missing:
                logger.warning("reason=interfaceNotFound,interfaces=%s", ",".join(missing))
        if selection == []:
            if entries != [INTERFACES_ONE_PER_SUBNET]:
                raise ValueError(f"no interface of {', '.join(entries)} is up with an address")
            logger.info("reason=noInterfaceSelected,fallback=all")
            selection = None
        self._snapshot = interface_snapshot(adapters)
        self._key = _selection_key(selection, adapters)
        return selection

    def check(
        self, adapters: Sequence | None = None
    ) -> tuple[bool, list[SelectedInterface] | None]:
        adapters = get_adapters(adapters)
        snapshot = interface_snapshot(adapters)
        if snapshot == self._snapshot:
            return False, None
        self._snapshot = snapshot
        selection = advertise_selection(self.interfaces, adapters)
        if selection == []:
            if self._key:
                logger.warning("reason=noInterfaceUp,advertised=%s", _describe(self._key))
            self._key = ()  # whichever interface comes up next is a move
            return False, None
        key = _selection_key(selection, adapters)
        if key == self._key:
            return False, None
        logger.info(
            "reason=advertiseInterfacesChanged,old=%s,new=%s",
            _describe(self._key),
            _describe(key),
        )
        self._pending = key
        return True, selection

    def moved(self) -> None:
        self._key = self._pending

    def failed(self) -> None:
        self._snapshot = None
        self._key = ()


# --- the OS host name --------------------------------------------------------


def local_addresses() -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """This host's addresses, excluding loopback: IPv4 first, link-local last."""
    import ifaddr  # a zeroconf dependency

    found: dict[str, ipaddress.IPv4Address | ipaddress.IPv6Address] = {}
    for adapter in ifaddr.get_adapters():
        texts = [ip.ip if isinstance(ip.ip, str) else ip.ip[0] for ip in adapter.ips]
        if any(t in ("127.0.0.1", "::1") for t in texts):
            continue  # the loopback interface, including its fe80::1
        for ip in adapter.ips:
            text = ip.ip if isinstance(ip.ip, str) else ip.ip[0]
            try:
                addr = ipaddress.ip_address(text.split("%", 1)[0])
            except ValueError:
                continue
            if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
                continue
            found[str(addr)] = addr
    return sorted(found.values(), key=lambda a: (a.version, a.is_link_local))


async def _async_ask(
    zc: Zeroconf,
    questions: Sequence[tuple[str, int]],
    match: Callable[[object], object],
    timeout: float,
):
    """Send one mDNS query and poll the cache for the first record ``match`` accepts.

    The query goes out at once and again at a third and two thirds of
    ``timeout``: a responder that is probing its own name does not answer,
    and one query sent by a just-started instance can go unanswered.
    """
    out = DNSOutgoing(_FLAGS_QR_QUERY)
    for name, rtype in questions:
        out.add_question(DNSQuestion(name, rtype, _CLASS_IN))
    await zc.async_wait_for_start()
    loop = asyncio.get_running_loop()
    start = loop.time()
    deadline = start + timeout
    resend = [start + timeout * f for f in (0.0, 1 / 3, 2 / 3)]
    while True:
        now = loop.time()
        while resend and now >= resend[0]:
            resend.pop(0)
            zc.async_send(out)
        for name, _ in questions:
            for rec in zc.cache.async_entries_with_name(name):
                found = match(rec)
                if found:
                    return found
        if now >= deadline:
            return None
        await asyncio.sleep(0.05)


async def async_os_hostname(
    zc: Zeroconf,
    timeout: float = 3.0,
    addresses: Sequence[ipaddress.IPv4Address | ipaddress.IPv6Address] | None = None,
) -> str | None:
    """The ``.local`` name the OS responder answers for this host, or None.

    Asks for the reverse ``PTR`` of up to eight of this host's addresses and
    returns the first ``.local.`` name answered (with its trailing dot). None
    means no OS responder answered within ``timeout``.
    """
    addrs = list(addresses if addresses is not None else local_addresses())[:8]
    if not addrs:
        return None

    def match(rec):
        if isinstance(rec, DNSPointer) and rec.alias.lower().endswith(".local."):
            return rec.alias
        return None

    questions = [(f"{a.reverse_pointer}.", _TYPE_PTR) for a in addrs]
    return await _async_ask(zc, questions, match, timeout)


def default_ip_version() -> IPVersion:
    """The ``IPVersion`` for a ``Zeroconf`` this library creates.

    ``IPVersion.All`` uses one dual-stack socket. On macOS (measured) its IPv4
    multicast join fails with ``EINVAL`` (python-zeroconf logs "does not
    support multicast"), leaving an IPv6-only instance that IPv4 peers never
    hear; an ``IPVersion.V4Only`` instance there works over IPv4 only. So
    macOS gets ``V4Only`` and other platforms ``All``.
    """
    return IPVersion.V4Only if sys.platform == "darwin" else IPVersion.All


#: Sockets of avahi-daemon; one exists while the daemon runs.
AVAHI_SOCKETS = ("/run/avahi-daemon/socket", "/var/run/avahi-daemon/socket")


def os_responder_present() -> bool:
    """True when an OS mDNS responder is expected to own this host's name.

    macOS always runs mDNSResponder; on Linux, avahi-daemon is detected by its
    socket. Windows is treated as present, so addresses are never published
    under a name it may answer for.
    """
    if sys.platform in ("darwin", "win32"):
        return True
    return any(os.path.exists(p) for p in AVAHI_SOCKETS)


async def async_name_answered(zc: Zeroconf, server: str, timeout: float) -> bool:
    """True when some responder answers an A or AAAA query for ``server``."""
    questions = [(server, _TYPE_A), (server, _TYPE_AAAA)]
    found = await _async_ask(zc, questions, lambda rec: isinstance(rec, DNSAddress), timeout)
    return bool(found)


def fallback_hostname() -> str:
    """``<gethostname, first label>.local.``: the name used with no OS responder."""
    return f"{socket.gethostname().split('.', 1)[0]}.local."


# --- advertising -------------------------------------------------------------


def build_infos(
    identity: Identity,
    instance_name: str,
    server: str,
    addresses: Sequence[str],
    port: int,
    device_info_port: int,
    http: Sequence[HttpService],
    brokers: Sequence[BrokerService] = (),
) -> list[ServiceInfo]:
    """The ``ServiceInfo`` objects one advertisement registers."""
    services: list[tuple[str, int, dict[str, str]]] = [
        (EBUS_SERVICE, port, identity.ebus_txt()),
        (DEVICE_INFO_SERVICE, device_info_port, identity.device_info_txt()),
    ]
    services += [(h.service_type, h.port, h.txt(identity)) for h in http]
    services += [(b.service_type, b.port or 0, b.txt(identity, server)) for b in brokers]
    infos = []
    for service_type, svc_port, txt in services:
        full = fq_type(service_type)
        infos.append(
            ServiceInfo(
                full,
                f"{instance_name}.{full}",
                port=svc_port,
                properties=txt,
                server=server,
                parsed_addresses=list(addresses),
            )
        )
    return infos


def instance_candidates(base: str) -> list[str]:
    """``base``, then ``base-2`` through ``base-99``."""
    return [base] + [f"{base}-{n}" for n in range(2, MAX_RENAME_SUFFIX + 1)]


async def async_register(
    zc: Zeroconf, build: Callable[[str], list[ServiceInfo]], base_name: str
) -> tuple[str, list[ServiceInfo]]:
    """Register the services under ``base_name``, renaming ``-2``..``-99`` on a conflict.

    All services share one instance name: when any of them conflicts, the ones
    already registered are withdrawn and the next name is tried. Returns the
    name used and the registered infos.

    If this coroutine is cancelled or fails part way, every service it
    registered is withdrawn before the exception propagates, so none is left
    on a caller's ``Zeroconf`` with no ``Advertiser`` holding it.
    """
    for name in instance_candidates(base_name):
        infos = build(name)
        registered: list[ServiceInfo] = []

        async def register(info: ServiceInfo, registered: list[ServiceInfo] = registered):
            broadcast = await zc.async_register_service(info)
            # No await between the registry add and here, so this list is
            # exactly what is in the registry when a cancellation lands.
            registered.append(info)
            return broadcast

        try:
            results = await asyncio.gather(
                *(register(info) for info in infos), return_exceptions=True
            )
            failed = [r for r in results if isinstance(r, BaseException)]
            if not failed:
                await asyncio.gather(*results)  # the announcement broadcasts
                if name != base_name:
                    logger.info("reason=instanceRenamed,from=%s,to=%s", base_name, name)
                return name, infos
        except BaseException:
            if registered:
                # Shielded: a second cancellation must not cut the withdrawal short.
                await asyncio.shield(async_unregister(zc, list(registered)))
            raise
        if registered:
            await async_unregister(zc, registered)
        unexpected = [
            r
            for r in failed
            if not isinstance(r, (NonUniqueNameException, ServiceNameAlreadyRegistered))
        ]
        if unexpected:
            raise unexpected[0]
        logger.info("reason=instanceNameConflict,name=%s", name)
    raise NonUniqueNameException(f"no free instance name from {base_name} to -{MAX_RENAME_SUFFIX}")


async def async_unregister(zc: Zeroconf, infos: Sequence[ServiceInfo]) -> None:
    """Withdraw services, sending goodbyes."""
    tasks = await asyncio.gather(
        *(zc.async_unregister_service(info) for info in infos), return_exceptions=True
    )
    await asyncio.gather(
        *(t for t in tasks if not isinstance(t, BaseException)), return_exceptions=True
    )


#: ``async_advertise``'s default: the selection follows ``AdvertisementPlan.interfaces``.
FROM_PLAN = object()


class AdvertisementPlan:
    """What ``Advertiser.start`` registers, resolved from its arguments."""

    def __init__(
        self,
        identity: Identity,
        *,
        port: int | None,
        device_info_port: int,
        http: HttpService | Sequence[HttpService] | None,
        server: str | None,
        addresses: Sequence[str] | None,
        instance_name: str | None,
        brokers: BrokerService | Sequence[BrokerService] | None = None,
        interfaces: str | Sequence[str] | None = None,
    ):
        self.identity = identity
        if interfaces is not None:
            validate_interfaces(interfaces)  # before touching the network
        self.interfaces = interfaces
        if http is None:
            self.http: tuple[HttpService, ...] = ()
        elif isinstance(http, HttpService):
            self.http = (http,)
        else:
            self.http = tuple(http)
        if brokers is None:
            self.brokers: tuple[BrokerService, ...] = ()
        elif isinstance(brokers, BrokerService):
            self.brokers = (brokers,)
        else:
            self.brokers = tuple(brokers)
        if port is None:
            port = self.http[0].port if self.http else 0
        self.port = port
        self.device_info_port = device_info_port
        self.server = server
        self.addresses = list(addresses) if addresses is not None else None
        self.instance_name = instance_name
        for h in self.http:
            h.txt(identity)  # validate before touching the network
        types = [b.service_type for b in self.brokers]
        dup = sorted({t for t in types if types.count(t) > 1})
        if dup:
            raise ValueError(f"more than one BrokerService of type {', '.join(dup)}")
        for b in self.brokers:
            b.txt(identity, server or "host.local.")  # the SRV target is not known yet
        if self.brokers and ROLE_BROKER_HOST not in identity.roles:
            logger.warning("reason=brokersWithoutBrokerHostRole,roles=%s", ",".join(identity.roles))

    async def async_resolve_host(
        self, zc: Zeroconf, detect_timeout: float, selection=FROM_PLAN
    ) -> tuple[str, list[str]]:
        """The SRV target and the addresses to publish for it.

        An explicit ``server`` is used as given, with ``addresses`` (default
        none: something else answers for the name). Otherwise the OS responder's
        name is used with no addresses, and ``addresses`` is ignored with a
        warning; with no OS responder, the fallback name with ``addresses``
        (default: the addresses of ``selection``, else of ``interfaces``, else
        all of this host's).
        """
        if self.server:
            server = self.server if self.server.endswith(".") else self.server + "."
            return server, self.addresses or []
        os_name = await async_os_hostname(zc, detect_timeout)
        if os_name:
            logger.info("reason=advertiseUnderOsHostname,server=%s", os_name)
            if self.addresses:
                logger.warning(
                    "reason=addressesIgnoredUnderOsHostname,server=%s,addresses=%s",
                    os_name,
                    ",".join(self.addresses),
                )
            return os_name, []
        if os_responder_present():
            raise RuntimeError(
                "the OS mDNS responder did not answer for this host's name within "
                f"{detect_timeout} s; retry, or pass server= (the host's .local name)"
            )
        server = fallback_hostname()
        if await async_name_answered(zc, server, detect_timeout):
            raise RuntimeError(
                f"another responder answers for {server}; pass server= and addresses="
            )
        if self.addresses is not None:
            addrs = self.addresses
        else:
            if selection is FROM_PLAN:
                selection = (
                    advertise_selection(self.interfaces) if self.interfaces is not None else None
                )
            addrs = [str(a) for a in addresses_of(selection)]
        logger.info(
            "reason=noOsResponder,server=%s,addresses=%s", server, ",".join(addrs) or "none"
        )
        return server, addrs

    def base_instance_name(self, server: str) -> str:
        """``instance_name``, else the first device id, else the host label.

        A device id is used when it fits one DNS label with a ``-99`` rename
        suffix (``MAX_DEFAULT_INSTANCE_OCTETS``). The host label is the last
        resort: on a host whose OS responder holds records under it (macOS
        publishes ``<host>._device-info._tcp``), the rename probe does not see
        them, and two TXT record sets end up under one name.
        """
        if self.instance_name:
            return self.instance_name
        first = self.identity.device_ids[0]
        if len(first.encode()) <= MAX_DEFAULT_INSTANCE_OCTETS:
            return first
        host = strip_dot(server).rsplit(".local", 1)[0]
        logger.info("reason=deviceIdTooLongForInstanceName,deviceId=%s,instance=%s", first, host)
        return host

    def builder(self, server: str, addresses: Sequence[str]) -> Callable[[str], list[ServiceInfo]]:
        def build(name: str) -> list[ServiceInfo]:
            return build_infos(
                self.identity,
                name,
                server,
                addresses,
                self.port,
                self.device_info_port,
                self.http,
                self.brokers,
            )

        return build


async def async_advertise(
    zc: Zeroconf, plan: AdvertisementPlan, detect_timeout: float, selection=FROM_PLAN
) -> tuple[str, str, list[ServiceInfo]]:
    """Resolve the host name and register; returns ``(server, instance_name, infos)``.

    ``selection`` (an ``advertise_selection`` result) is the interfaces ``zc``
    was created on; by default it is resolved from ``plan.interfaces``.
    """
    server, addresses = await plan.async_resolve_host(zc, detect_timeout, selection)
    try:
        name, infos = await async_register(
            zc, plan.builder(server, addresses), plan.base_instance_name(server)
        )
    except BadTypeInNameException as exc:
        raise ValueError(f"invalid service or instance name: {exc}") from exc
    return server, name, infos

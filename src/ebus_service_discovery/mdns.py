"""Direct mDNS discovery and advertising, synchronous (the ``[zeroconf]`` extra).

``browse`` lists the instances of a service type, ``find_broker`` resolves the
broker to connect to under the framework.md broker modes, and ``Advertiser``
registers the ``_ebus._tcp`` / ``_device-info._tcp`` services (and
``_http._tcp`` / ``_https._tcp`` when given) under the host's existing
``.local`` name.

Each takes an optional ``zeroconf.Zeroconf``. When none is passed one is
created for the call (or for the advertiser's lifetime) and closed afterwards;
a passed instance is never closed. ``interfaces=`` selects the interfaces of a
created instance (see ``new_zeroconf``): browsing defaults to ``"all"``,
advertising to ``"one-per-subnet"``. Call these from a thread other than the
``Zeroconf`` instance's own event loop. For asyncio hosts, use ``mdns_async``.

Importing ``ebus_service_discovery`` does not import this module or zeroconf.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import threading
from collections.abc import Iterator, Mapping, Sequence

try:
    from zeroconf import ServiceInfo, Zeroconf
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        'ebus_service_discovery.mdns needs zeroconf: pip install "ebus-service-discovery[zeroconf]"'
    ) from exc

from ebus_service_discovery import _mdns_core as core
from ebus_service_discovery.ebus import (
    BrokerEndpoint,
    BrokerMode,
    BrokerService,
    HttpService,
    Identity,
    RetrySchedule,
)
from ebus_service_discovery.instance import ServiceInstance

logger = logging.getLogger(__name__)

DEFAULT_BROWSE_TIMEOUT = 3.0

INTERFACES_ALL = core.INTERFACES_ALL
INTERFACES_ONE_PER_SUBNET = core.INTERFACES_ONE_PER_SUBNET
DEFAULT_INTERFACE_CHECK_INTERVAL = core.DEFAULT_INTERFACE_CHECK_INTERVAL
resolve_interfaces = core.resolve_interfaces


def new_zeroconf(interfaces: str | Sequence[str] = INTERFACES_ALL) -> Zeroconf:
    """A ``Zeroconf`` configured as this module creates its own (see
    ``_mdns_core.default_ip_version``); IPv4 only if IPv6 is unavailable.

    ``interfaces`` is ``"all"`` (python-zeroconf's default), ``"one-per-subnet"``
    (interfaces sharing an IPv4 subnet collapse to one, wired preferred over
    Wi-Fi; loopback left out), or interface names and addresses
    (``["eth0"]``, ``["192.0.2.7"]``). See ``resolve_interfaces``.
    """
    return _zeroconf_on(core.instance_selection(interfaces))


def _zeroconf_on(selection: list[core.SelectedInterface] | None) -> Zeroconf:
    return core.create_instance(Zeroconf, selection)


def _check_interfaces(zc: Zeroconf | None, interfaces: str | Sequence[str] | None) -> None:
    if zc is not None and interfaces is not None:
        raise ValueError(
            "interfaces= applies only to a Zeroconf this library creates; "
            "build the passed zc with new_zeroconf(interfaces) instead"
        )


@contextlib.contextmanager
def _zeroconf(
    zc: Zeroconf | None, interfaces: str | Sequence[str] | None = None
) -> Iterator[Zeroconf]:
    """Yield ``zc``, or a new instance on ``interfaces`` closed on exit."""
    _check_interfaces(zc, interfaces)
    if zc is not None:
        yield zc
        return
    own = new_zeroconf(interfaces if interfaces is not None else INTERFACES_ALL)
    try:
        yield own
    finally:
        own.close()


#: Seconds ``_run`` waits for a cancelled coroutine to unwind (withdraw services).
CANCEL_GRACE = 5.0


def _run(zc: Zeroconf, coro, timeout: float | None = None):
    """Run a coroutine on ``zc``'s event loop from another thread.

    If the wait is interrupted (``KeyboardInterrupt``, ``timeout``), the
    coroutine is cancelled and given up to ``CANCEL_GRACE`` seconds to unwind
    before the exception propagates, so an interrupted ``Advertiser.start``
    withdraws what it registered on a shared ``Zeroconf``.
    """
    loop = zc.loop
    if loop is None or not loop.is_running():
        coro.close()
        raise RuntimeError("the Zeroconf instance is not running")
    try:
        running = asyncio.get_running_loop()
    except RuntimeError:
        running = None
    if running is loop:
        coro.close()
        raise RuntimeError(
            "called from the Zeroconf event loop; use ebus_service_discovery.mdns_async"
        )
    started = threading.Event()
    finished = threading.Event()

    async def guarded():
        started.set()
        try:
            return await coro
        finally:
            finished.set()

    future = asyncio.run_coroutine_threadsafe(guarded(), loop)
    try:
        return future.result(timeout)
    except BaseException:
        if not future.done():
            future.cancel()
            if started.is_set():  # a task cancelled before it started has nothing to undo
                finished.wait(CANCEL_GRACE)
        raise


def browse(
    service_type: str,
    timeout: float = DEFAULT_BROWSE_TIMEOUT,
    zc: Zeroconf | None = None,
    *,
    interfaces: str | Sequence[str] | None = None,
) -> list[ServiceInstance]:
    """The instances of ``service_type`` (``_ebus._tcp``) seen within ``timeout`` seconds.

    Each instance is resolved (SRV, TXT, addresses) as it is seen; one not
    resolved within ``timeout`` is left out, so the call returns after about
    ``timeout`` seconds. ``interfaces`` (default ``"all"``) applies when no
    ``zc`` is passed.
    """
    with _zeroconf(zc, interfaces) as z:
        return _run(z, core.async_browse(z, service_type, timeout))


def browse_many(
    service_types: Sequence[str],
    timeout: float = DEFAULT_BROWSE_TIMEOUT,
    zc: Zeroconf | None = None,
    *,
    interfaces: str | Sequence[str] | None = None,
) -> list[ServiceInstance]:
    """Browse several service types at once for ``timeout`` seconds."""
    with _zeroconf(zc, interfaces) as z:
        return _run(z, core.async_browse_many(z, service_types, timeout))


def find_broker(
    mode: BrokerMode | str | None = None,
    url: str | None = None,
    *,
    base_cfg: Mapping | None = None,
    stop: threading.Event | None = None,
    zc: Zeroconf | None = None,
    accept: Sequence[str] | None = None,
    schedule: RetrySchedule | None = None,
    browse_timeout: float = DEFAULT_BROWSE_TIMEOUT,
    allow_unmatched: bool = False,
    interfaces: str | Sequence[str] | None = None,
) -> BrokerEndpoint | None:
    """Resolve the broker to connect to (framework.md requirement 22).

    The configured broker is ``url`` (``mqtt://`` or ``mqtts://``) or, when
    ``url`` is None, the ``host``/``port``/``use_tls`` of ``base_cfg``.

    - ``configured-only``: returns the configured broker; never browses.
    - ``discovery-only`` (the default): browses until a broker is found.
    - ``discovery-with-fallback``: browses for the configured broker; if the
      first ``fast_attempts`` of ``schedule`` (or all ``max_attempts``, if
      fewer) do not find it, returns the configured broker. A different
      discovered broker is never returned in its place unless
      ``allow_unmatched`` is True. With no configured broker, this is
      ``discovery-only``.

    Each attempt browses all four broker types for ``browse_timeout`` seconds.
    Brokers whose type is in ``accept`` are ranked by ``ebus.rank_brokers``
    and chosen by ``ebus.select_broker``; others are logged. ``accept``
    defaults to ``_secure-mqtt._tcp`` and ``_mqtt._tcp``, or to
    ``_secure-mqtt._tcp`` alone when TLS is configured (an ``mqtts://`` url or
    ``base_cfg["use_tls"]``), so a TLS config's credentials never go to a
    plain broker. Attempts follow ``schedule``
    (default: 3 attempts 3 s apart, then every 30 s). Returns None when
    ``stop`` is set or ``schedule.max_attempts`` runs out. There is no
    reachability probe: connecting is the probe.

    Connect with ``endpoint.mqtt_cfg(base_cfg)``, which keeps the TLS material
    and credentials of ``base_cfg``. ``interfaces`` (default ``"all"``) applies
    when no ``zc`` is passed.
    """
    schedule = schedule or RetrySchedule()
    search = core.BrokerSearch(
        mode,
        url,
        base_cfg,
        accept,
        schedule.fast_attempts,
        schedule.max_attempts,
        allow_unmatched,
    )
    _check_interfaces(zc, interfaces)
    if not search.needs_browse:
        return search.configured
    with _zeroconf(zc, interfaces) as z:
        for attempt, delay in enumerate(schedule.delays()):
            if delay and _wait(stop, delay):
                return None
            if stop is not None and stop.is_set():
                return None
            found = browse_many(search.browse_types, browse_timeout, z)
            done, endpoint = search.decide(found, attempt)
            if done:
                return endpoint
    return None


def _wait(stop: threading.Event | None, seconds: float) -> bool:
    """Sleep ``seconds``; True if ``stop`` was set meanwhile."""
    if stop is None:
        threading.Event().wait(seconds)
        return False
    return stop.wait(seconds)


def os_hostname(zc: Zeroconf | None = None, timeout: float = 3.0) -> str | None:
    """The ``.local.`` name the OS mDNS responder answers for this host, or None."""
    with _zeroconf(zc) as z:
        return _run(z, core.async_os_hostname(z, timeout))


class Advertiser:
    """Advertise this entity's eBus services under the host's ``.local`` name.

    Registers ``_ebus._tcp`` and ``_device-info._tcp`` from ``identity``, and
    ``_http._tcp`` / ``_https._tcp`` for each ``HttpService`` in ``http``,
    and one broker service type for each ``BrokerService`` in ``brokers`` (at
    most one per type; its TXT ``broker`` defaults to the SRV target).
    All share one instance name: ``instance_name``, else the first of
    ``identity.device_ids`` (the host label if that is over 60 bytes). On a
    conflict it becomes ``<name>-2`` through ``<name>-99``. The conflict probe
    sees only names advertised with a PTR record for the service type, not the
    bare TXT record macOS publishes at ``<host label>._device-info._tcp``, so do
    not use the host label as ``instance_name`` on macOS.

    The SRV target is the name the OS responder already answers for this host,
    found over mDNS, and no address records are published, so the OS keeps
    answering for its own name. ``start`` raises ``RuntimeError`` when an OS
    responder is present (macOS, a running avahi-daemon) but does not answer
    within ``detect_timeout``. With no OS responder the target is
    ``<gethostname>.local`` and this host's addresses (or ``addresses``) are
    published, unless another host answers for that name. ``server`` skips
    the detection and is published with ``addresses`` (default none).
    ``addresses`` without ``server`` is never published under the OS
    responder's name: it is ignored there, with a warning. See ``_mdns_core``
    for the measurements behind this.

    ``port`` is the ``_ebus._tcp`` SRV port (default: the first HTTP port, else
    0); ``device_info_port`` is the ``_device-info._tcp`` port (default 0).

    ``interfaces`` selects the interfaces of the ``Zeroconf`` created when no
    ``zc`` is passed (default ``"one-per-subnet"``), and with no OS responder
    the addresses published for the fallback name come only from them. A list
    (``["eth0", "wlan0"]``) is a ranked candidate set: per IPv4 subnet, the
    first listed interface that is up and has an address is used (see
    ``_mdns_core.advertise_selection``). With a passed ``zc`` it limits only
    the published addresses (default: all of this host's).

    An owned ``Zeroconf`` follows interface changes: every
    ``interface_check_interval`` seconds (None: never) a daemon thread compares
    the interfaces and their addresses with the last check, and when the
    selection changes it withdraws the services, replaces the ``Zeroconf``
    with one on the new selection and registers them again. So with
    ``eth0`` and ``wlan0`` on one subnet, Wi-Fi takes over while Ethernet is
    down and Ethernet takes back when it returns. ``check_interfaces()``
    runs a check at once. With a passed ``zc``, re-selection is the caller's.
    """

    def __init__(
        self,
        identity: Identity,
        *,
        http: HttpService | Sequence[HttpService] | None = None,
        brokers: BrokerService | Sequence[BrokerService] | None = None,
        zc: Zeroconf | None = None,
        port: int | None = None,
        device_info_port: int = 0,
        server: str | None = None,
        addresses: Sequence[str] | None = None,
        instance_name: str | None = None,
        detect_timeout: float = 3.0,
        interfaces: str | Sequence[str] | None = None,
        interface_check_interval: float | None = DEFAULT_INTERFACE_CHECK_INTERVAL,
    ):
        if zc is None and interfaces is None:
            interfaces = INTERFACES_ONE_PER_SUBNET
        self._plan = core.AdvertisementPlan(
            identity,
            port=port,
            device_info_port=device_info_port,
            http=http,
            server=server,
            addresses=addresses,
            instance_name=instance_name,
            brokers=brokers,
            interfaces=interfaces,
        )
        self._zc = zc
        self._own_zc: Zeroconf | None = None
        self._watch = core.InterfaceWatch(interfaces) if zc is None else None
        self._interval = interface_check_interval
        self._lock = threading.Lock()  # serializes start, stop and moves
        self._stopping = threading.Event()
        self._watcher: threading.Thread | None = None
        self._active = False  # started on an owned Zeroconf, not yet stopped
        self._detect_timeout = detect_timeout
        self._infos: list[ServiceInfo] = []
        self.server: str | None = None
        self.instance_name: str | None = None

    @property
    def infos(self) -> list[ServiceInfo]:
        """The registered ``ServiceInfo`` objects (empty when stopped)."""
        return list(self._infos)

    @property
    def running(self) -> bool:
        return bool(self._infos)

    def start(self) -> Advertiser:
        """Register the services; blocks while the host name is found and names are probed (a few seconds)."""
        with self._lock:
            if self._infos or self._active:
                return self
            if self._zc is not None:
                self._advertise(self._zc, core.FROM_PLAN)
                return self
            selection = self._watch.initial()
            self._own_zc = _zeroconf_on(selection)
            try:
                self._advertise(self._own_zc, selection)
            except BaseException:
                self._close_own()
                raise
            self._active = True
            self._stopping.clear()
            if self._interval is not None:
                self._watcher = threading.Thread(
                    target=self._watch_loop, name="ebus-advertiser-interfaces", daemon=True
                )
                self._watcher.start()
        return self

    def _advertise(self, zc: Zeroconf, selection) -> None:
        self.server, self.instance_name, self._infos = _run(
            zc, core.async_advertise(zc, self._plan, self._detect_timeout, selection)
        )

    def check_interfaces(self) -> bool:
        """Check the interfaces now; True if the advertisement moved.

        Only between ``start`` and ``stop`` of an advertiser that owns its
        ``Zeroconf``; otherwise False. A failed move is logged and retried on
        the next check.
        """
        with self._lock:
            if not self._active or self._stopping.is_set():
                return False
            move, selection = self._watch.check()
            if not move:
                return False
            self._withdraw()
            self._close_own()
            try:
                self._own_zc = _zeroconf_on(selection)
                self._advertise(self._own_zc, selection)
            except Exception:
                logger.warning("reason=advertiseMoveFailed", exc_info=True)
                self._close_own()
                self._watch.failed()
                return False
            except BaseException:
                self._close_own()
                self._watch.failed()
                raise
            self._watch.moved()
            return True

    def _watch_loop(self) -> None:
        while not self._stopping.wait(self._interval):
            try:
                self.check_interfaces()
            except Exception:
                logger.warning("reason=interfaceCheckFailed", exc_info=True)

    def stop(self) -> None:
        """Withdraw the services (goodbye packets), end the interface checks
        and close an owned ``Zeroconf``."""
        self._stopping.set()
        watcher, self._watcher = self._watcher, None
        if watcher is not None and watcher is not threading.current_thread():
            watcher.join()
        with self._lock:
            self._active = False
            try:
                self._withdraw()
            finally:
                self._close_own()

    def _withdraw(self) -> None:
        zc = self._zc or self._own_zc
        infos, self._infos = self._infos, []
        if infos and zc is not None:
            try:
                _run(zc, core.async_unregister(zc, infos))
            except Exception:
                if zc is self._zc:
                    raise
                logger.warning("reason=withdrawFailed", exc_info=True)

    def _close_own(self) -> None:
        if self._own_zc is not None:
            self._own_zc.close()
            self._own_zc = None

    def __enter__(self) -> Advertiser:
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

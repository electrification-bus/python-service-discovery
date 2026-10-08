"""Direct mDNS discovery and advertising, synchronous (the ``[zeroconf]`` extra).

``browse`` lists the instances of a service type, ``find_broker`` resolves the
broker to connect to under the framework.md broker modes, and ``Advertiser``
registers the ``_ebus._tcp`` / ``_device-info._tcp`` services (and
``_http._tcp`` / ``_https._tcp`` when given) under the host's existing
``.local`` name.

Each takes an optional ``zeroconf.Zeroconf``. When none is passed one is
created for the call (or for the advertiser's lifetime) and closed afterwards;
a passed instance is never closed. Call these from a thread other than the
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
    from zeroconf import IPVersion, ServiceInfo, Zeroconf
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        'ebus_service_discovery.mdns needs zeroconf: pip install "ebus-service-discovery[zeroconf]"'
    ) from exc

from ebus_service_discovery import _mdns_core as core
from ebus_service_discovery.ebus import (
    TCP_BROKER_TYPES,
    BrokerEndpoint,
    BrokerMode,
    HttpService,
    Identity,
    RetrySchedule,
)
from ebus_service_discovery.instance import ServiceInstance

logger = logging.getLogger(__name__)

DEFAULT_BROWSE_TIMEOUT = 3.0


def _new_zeroconf() -> Zeroconf:
    try:
        return Zeroconf(ip_version=IPVersion.All)
    except OSError:
        logger.info("reason=ipv6Unavailable,fallback=ipv4")
        return Zeroconf()


@contextlib.contextmanager
def _zeroconf(zc: Zeroconf | None) -> Iterator[Zeroconf]:
    """Yield ``zc``, or a new instance closed on exit."""
    if zc is not None:
        yield zc
        return
    own = _new_zeroconf()
    try:
        yield own
    finally:
        own.close()


def _run(zc: Zeroconf, coro, timeout: float | None = None):
    """Run a coroutine on ``zc``'s event loop from another thread."""
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
    return asyncio.run_coroutine_threadsafe(coro, loop).result(timeout)


def browse(
    service_type: str, timeout: float = DEFAULT_BROWSE_TIMEOUT, zc: Zeroconf | None = None
) -> list[ServiceInstance]:
    """The instances of ``service_type`` (``_ebus._tcp``) seen within ``timeout`` seconds.

    Each instance is resolved (SRV, TXT, addresses) before it is returned;
    one that does not resolve is left out.
    """
    with _zeroconf(zc) as z:
        return _run(z, core.async_browse(z, service_type, timeout))


def browse_many(
    service_types: Sequence[str],
    timeout: float = DEFAULT_BROWSE_TIMEOUT,
    zc: Zeroconf | None = None,
) -> list[ServiceInstance]:
    """Browse several service types at once for ``timeout`` seconds."""
    with _zeroconf(zc) as z:
        return _run(z, core.async_browse_many(z, service_types, timeout))


def find_broker(
    mode: BrokerMode | str | None = None,
    url: str | None = None,
    *,
    base_cfg: Mapping | None = None,
    stop: threading.Event | None = None,
    zc: Zeroconf | None = None,
    accept: Sequence[str] = TCP_BROKER_TYPES,
    schedule: RetrySchedule | None = None,
    browse_timeout: float = DEFAULT_BROWSE_TIMEOUT,
) -> BrokerEndpoint | None:
    """Resolve the broker to connect to (framework.md requirement 22).

    The configured broker is ``url`` (``mqtt://`` or ``mqtts://``) or, when
    ``url`` is None, the ``host``/``port``/``use_tls`` of ``base_cfg``.

    - ``configured-only``: returns the configured broker; never browses.
    - ``discovery-only`` (the default): browses until a broker is found.
    - ``discovery-with-fallback``: browses; if the first ``fast_attempts`` of
      ``schedule`` find nothing, returns the configured broker.

    Each attempt browses all four broker types for ``browse_timeout`` seconds.
    Brokers whose type is in ``accept`` (default ``_secure-mqtt._tcp`` and
    ``_mqtt._tcp``) are ranked by ``ebus.rank_brokers`` and chosen by
    ``ebus.select_broker``; others are logged. Attempts follow ``schedule``
    (default: 3 attempts 3 s apart, then every 30 s). Returns None when
    ``stop`` is set or ``schedule.max_attempts`` runs out. There is no
    reachability probe: connecting is the probe.

    Connect with ``endpoint.mqtt_cfg(base_cfg)``, which keeps the TLS material
    and credentials of ``base_cfg``.
    """
    schedule = schedule or RetrySchedule()
    search = core.BrokerSearch(mode, url, base_cfg, accept, schedule.fast_attempts)
    if not search.needs_browse:
        return search.configured
    with _zeroconf(zc) as z:
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
    ``_http._tcp`` / ``_https._tcp`` for each ``HttpService`` in ``http``.
    All share one instance name, by default the host label; on a conflict it
    becomes ``<name>-2`` through ``<name>-99``.

    The SRV target is the name the OS responder already answers for this host,
    found over mDNS, and no address records are published, so the OS keeps
    answering for its own name. ``start`` raises ``RuntimeError`` when an OS
    responder is present (macOS, a running avahi-daemon) but does not answer
    within ``detect_timeout``. With no OS responder the target is
    ``<gethostname>.local`` and this host's addresses are published, unless
    another host answers for that name. ``server`` (and ``addresses``) skip
    the detection. See ``_mdns_core`` for the measurements behind this.

    ``port`` is the ``_ebus._tcp`` SRV port (default: the first HTTP port, else
    0); ``device_info_port`` is the ``_device-info._tcp`` port (default 0).
    """

    def __init__(
        self,
        identity: Identity,
        *,
        http: HttpService | Sequence[HttpService] | None = None,
        zc: Zeroconf | None = None,
        port: int | None = None,
        device_info_port: int = 0,
        server: str | None = None,
        addresses: Sequence[str] | None = None,
        instance_name: str | None = None,
        detect_timeout: float = 3.0,
    ):
        self._plan = core.AdvertisementPlan(
            identity,
            port=port,
            device_info_port=device_info_port,
            http=http,
            server=server,
            addresses=addresses,
            instance_name=instance_name,
        )
        self._zc = zc
        self._own_zc: Zeroconf | None = None
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
        if self._infos:
            return self
        zc = self._zc
        if zc is None:
            zc = self._own_zc = _new_zeroconf()
        try:
            self.server, self.instance_name, self._infos = _run(
                zc, core.async_advertise(zc, self._plan, self._detect_timeout)
            )
        except BaseException:
            self._close_own()
            raise
        return self

    def stop(self) -> None:
        """Withdraw the services (goodbye packets) and close an owned ``Zeroconf``."""
        zc = self._zc or self._own_zc
        try:
            if self._infos and zc is not None:
                _run(zc, core.async_unregister(zc, self._infos))
        finally:
            self._infos = []
            self._close_own()

    def _close_own(self) -> None:
        if self._own_zc is not None:
            self._own_zc.close()
            self._own_zc = None

    def __enter__(self) -> Advertiser:
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

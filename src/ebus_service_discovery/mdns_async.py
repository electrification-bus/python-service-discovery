"""Direct mDNS discovery and advertising for asyncio (the ``[zeroconf]`` extra).

The same operations as ``mdns``, for hosts that own an event loop and a shared
``zeroconf.asyncio.AsyncZeroconf`` (Home Assistant, for one). Every function
REQUIRES the caller's ``AsyncZeroconf`` and never creates or closes one;
``Advertiser`` creates and closes its own when none is passed. To select the
interfaces of a caller-built instance as ``mdns`` does, use
``resolve_interfaces``::

    version = default_ip_version()
    aiozc = AsyncZeroconf(
        interfaces=resolve_interfaces("one-per-subnet", version), ip_version=version
    )
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Mapping, Sequence

try:
    from zeroconf import ServiceInfo
    from zeroconf.asyncio import AsyncZeroconf
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "ebus_service_discovery.mdns_async needs zeroconf: "
        'pip install "ebus-service-discovery[zeroconf]"'
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

logger = logging.getLogger("ebus_service_discovery.mdns")

DEFAULT_BROWSE_TIMEOUT = 3.0

INTERFACES_ALL = core.INTERFACES_ALL
INTERFACES_ONE_PER_SUBNET = core.INTERFACES_ONE_PER_SUBNET
DEFAULT_INTERFACE_CHECK_INTERVAL = core.DEFAULT_INTERFACE_CHECK_INTERVAL
resolve_interfaces = core.resolve_interfaces
default_ip_version = core.default_ip_version


def _require(aiozc: AsyncZeroconf) -> None:
    if aiozc is None:
        raise TypeError("an AsyncZeroconf instance is required (the caller owns it)")


async def browse(
    aiozc: AsyncZeroconf, service_type: str, timeout: float = DEFAULT_BROWSE_TIMEOUT
) -> list[ServiceInstance]:
    """The instances of ``service_type`` seen within ``timeout`` seconds, resolved."""
    _require(aiozc)
    return await core.async_browse(aiozc.zeroconf, service_type, timeout)


async def browse_many(
    aiozc: AsyncZeroconf, service_types: Sequence[str], timeout: float = DEFAULT_BROWSE_TIMEOUT
) -> list[ServiceInstance]:
    """Browse several service types at once for ``timeout`` seconds."""
    _require(aiozc)
    return await core.async_browse_many(aiozc.zeroconf, service_types, timeout)


async def find_broker(
    aiozc: AsyncZeroconf,
    mode: BrokerMode | str | None = None,
    url: str | None = None,
    *,
    base_cfg: Mapping | None = None,
    stop: asyncio.Event | None = None,
    accept: Sequence[str] | None = None,
    schedule: RetrySchedule | None = None,
    browse_timeout: float = DEFAULT_BROWSE_TIMEOUT,
    allow_unmatched: bool = False,
) -> BrokerEndpoint | None:
    """Resolve the broker to connect to; see ``mdns.find_broker``.

    ``stop`` is an ``asyncio.Event``; cancelling the task also stops the search.
    """
    _require(aiozc)
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
    if not search.needs_browse:
        return search.configured
    for attempt, delay in enumerate(schedule.delays()):
        if delay and await _wait(stop, delay):
            return None
        if stop is not None and stop.is_set():
            return None
        found = await browse_many(aiozc, search.browse_types, browse_timeout)
        done, endpoint = search.decide(found, attempt)
        if done:
            return endpoint
    return None


async def _wait(stop: asyncio.Event | None, seconds: float) -> bool:
    """Sleep ``seconds``; True if ``stop`` was set meanwhile."""
    if stop is None:
        await asyncio.sleep(seconds)
        return False
    with contextlib.suppress(asyncio.TimeoutError):
        await asyncio.wait_for(stop.wait(), seconds)
    return stop.is_set()


async def os_hostname(aiozc: AsyncZeroconf, timeout: float = 3.0) -> str | None:
    """The ``.local.`` name the OS mDNS responder answers for this host, or None."""
    _require(aiozc)
    return await core.async_os_hostname(aiozc.zeroconf, timeout)


class Advertiser:
    """The asyncio form of ``mdns.Advertiser``.

    ``await start()`` / ``await stop()``, or ``async with``. With a passed
    ``aiozc``, ``stop`` withdraws the services and leaves it open, and
    ``interfaces`` limits only the addresses published for the fallback name
    when there is no OS responder (default: all of this host's); pass the
    value the ``AsyncZeroconf`` was built with (see ``resolve_interfaces``),
    which reads it the same way. Re-selecting its interfaces is then the
    caller's job.

    With no ``aiozc``, the advertiser creates an ``AsyncZeroconf`` on
    ``interfaces`` (default ``"one-per-subnet"``), closes it on ``stop``, and
    follows interface changes as ``mdns.Advertiser`` does, from a task that
    checks every ``interface_check_interval`` seconds (None: never).
    """

    def __init__(
        self,
        identity: Identity,
        aiozc: AsyncZeroconf | None = None,
        *,
        http: HttpService | Sequence[HttpService] | None = None,
        brokers: BrokerService | Sequence[BrokerService] | None = None,
        port: int | None = None,
        device_info_port: int = 0,
        server: str | None = None,
        addresses: Sequence[str] | None = None,
        instance_name: str | None = None,
        detect_timeout: float = 3.0,
        interfaces: str | Sequence[str] | None = None,
        interface_check_interval: float | None = DEFAULT_INTERFACE_CHECK_INTERVAL,
    ):
        if aiozc is None and interfaces is None:
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
        self._aiozc = aiozc
        self._own: AsyncZeroconf | None = None
        self._watch = core.InterfaceWatch(interfaces) if aiozc is None else None
        self._interval = interface_check_interval
        self._lock = asyncio.Lock()  # serializes start, stop and moves
        self._watcher: asyncio.Task | None = None
        self._active = False  # started on an owned AsyncZeroconf, not yet stopped
        self._detect_timeout = detect_timeout
        self._infos: list[ServiceInfo] = []
        self.server: str | None = None
        self.instance_name: str | None = None

    @property
    def infos(self) -> list[ServiceInfo]:
        return list(self._infos)

    @property
    def running(self) -> bool:
        return bool(self._infos)

    async def start(self) -> Advertiser:
        async with self._lock:
            if self._infos or self._active:
                return self
            if self._aiozc is not None:
                await self._advertise(self._aiozc, core.FROM_PLAN)
                return self
            selection = self._watch.initial()
            if selection == [] and self._interval is None:
                raise self._watch.nothing_up()
            self.server = None
            if selection != []:  # else the first check that finds one up starts it
                self._own = core.create_instance(AsyncZeroconf, selection)
                try:
                    await self._advertise(self._own, selection)
                except BaseException:
                    await self._close_own()
                    raise
            self._active = True
            if self._interval is not None:
                self._watcher = asyncio.get_running_loop().create_task(self._watch_loop())
        return self

    async def _advertise(self, aiozc: AsyncZeroconf, selection, server: str | None = None) -> None:
        self.server, self.instance_name, self._infos = await core.async_advertise(
            aiozc.zeroconf, self._plan, self._detect_timeout, selection, server
        )
        if self._watch is not None:
            self._watch.track_addresses = self._plan.publishes_selection

    async def check_interfaces(self) -> bool:
        """Check the interfaces now; True if the advertisement moved.

        Only between ``start`` and ``stop`` of an advertiser that owns its
        ``AsyncZeroconf``; otherwise False. A failed move is logged and
        retried on the next check.
        """
        async with self._lock:
            if not self._active:
                return False
            change, selection = self._watch.check(await asyncio.to_thread(core.get_adapters))
            if change is None:
                return False
            if change == core.READDRESS:
                try:
                    self._infos = await core.async_readdress(
                        self._own.zeroconf, self._plan, self.server, self.instance_name, selection
                    )
                except Exception:
                    logger.warning("reason=advertiseReaddressFailed", exc_info=True)
                    self._watch.failed()  # the next check moves
                    return False
                self._watch.moved()
                return True
            await self._withdraw()
            await self._close_own()
            try:
                self._own = core.create_instance(AsyncZeroconf, selection)
                await self._advertise(self._own, selection, self.server)
            except Exception:
                logger.warning("reason=advertiseMoveFailed", exc_info=True)
                await self._close_own()
                self._watch.failed()
                return False
            except BaseException:
                await self._close_own()
                self._watch.failed()
                raise
            self._watch.moved()
            return True

    async def _watch_loop(self) -> None:
        while True:
            await asyncio.sleep(self._interval)
            try:
                await self.check_interfaces()
            except Exception:
                logger.warning("reason=interfaceCheckFailed", exc_info=True)

    async def stop(self) -> None:
        watcher, self._watcher = self._watcher, None
        if watcher is not None:
            watcher.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await watcher
        async with self._lock:
            self._active = False
            try:
                await self._withdraw()
            finally:
                await self._close_own()

    async def _withdraw(self) -> None:
        aiozc = self._aiozc or self._own
        infos, self._infos = self._infos, []
        if infos and aiozc is not None:
            await core.async_unregister(aiozc.zeroconf, infos)

    async def _close_own(self) -> None:
        own, self._own = self._own, None
        if own is not None:
            await own.async_close()

    async def __aenter__(self) -> Advertiser:
        return await self.start()

    async def __aexit__(self, *exc) -> None:
        await self.stop()

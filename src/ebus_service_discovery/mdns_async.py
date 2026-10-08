"""Direct mDNS discovery and advertising for asyncio (the ``[zeroconf]`` extra).

The same operations as ``mdns``, for hosts that own an event loop and a shared
``zeroconf.asyncio.AsyncZeroconf`` (Home Assistant, for one). Every function
REQUIRES the caller's ``AsyncZeroconf`` and never creates or closes one.
"""

from __future__ import annotations

import asyncio
import contextlib
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
    HttpService,
    Identity,
    RetrySchedule,
)
from ebus_service_discovery.instance import ServiceInstance

DEFAULT_BROWSE_TIMEOUT = 3.0


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
    """The asyncio form of ``mdns.Advertiser``, on a caller-owned ``AsyncZeroconf``.

    ``await start()`` / ``await stop()``, or ``async with``. ``stop`` withdraws
    the services and leaves the ``AsyncZeroconf`` open.
    """

    def __init__(
        self,
        identity: Identity,
        aiozc: AsyncZeroconf,
        *,
        http: HttpService | Sequence[HttpService] | None = None,
        port: int | None = None,
        device_info_port: int = 0,
        server: str | None = None,
        addresses: Sequence[str] | None = None,
        instance_name: str | None = None,
        detect_timeout: float = 3.0,
    ):
        _require(aiozc)
        self._plan = core.AdvertisementPlan(
            identity,
            port=port,
            device_info_port=device_info_port,
            http=http,
            server=server,
            addresses=addresses,
            instance_name=instance_name,
        )
        self._aiozc = aiozc
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
        if self._infos:
            return self
        self.server, self.instance_name, self._infos = await core.async_advertise(
            self._aiozc.zeroconf, self._plan, self._detect_timeout
        )
        return self

    async def stop(self) -> None:
        infos, self._infos = self._infos, []
        if infos:
            await core.async_unregister(self._aiozc.zeroconf, infos)

    async def __aenter__(self) -> Advertiser:
        return await self.start()

    async def __aexit__(self, *exc) -> None:
        await self.stop()

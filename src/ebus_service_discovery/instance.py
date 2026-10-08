"""A transport-neutral DNS-SD service instance.

``ServiceInstance`` is what a browse returns, whatever the source: a direct
mDNS browse (``ebus_service_discovery.mdns``) or a record off the MQTT
discovery bus (``Record.to_instance()``). ``Record`` stays the per-interface
wire model of the bus; a ``ServiceInstance`` carries no bus state (freshness,
tombstones) and its ``interface`` is optional, because a direct browse does
not always know it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ebus_service_discovery.record import Address, AddressFamily


def strip_dot(name: str) -> str:
    """``host.local.`` -> ``host.local``: drop one trailing root dot."""
    return name[:-1] if name.endswith(".") else name


@dataclass(frozen=True)
class ServiceInstance:
    """One DNS-SD service instance.

    ``service_type`` has no domain (``_ebus._tcp``), ``instance_name`` is the
    instance label alone, and ``server`` is the SRV target without its trailing
    dot (``host.local``). TXT keys are as the source reported them; a direct
    browse lowercases them (see ``ebus.decode_txt``).
    """

    service_type: str
    instance_name: str
    server: str
    port: int
    addresses: tuple[Address, ...] = ()
    txt: dict[str, str] = field(default_factory=dict)
    interface: str | None = None

    def candidate_addresses(self) -> list[Address]:
        """Usable addresses, most-preferred first (routable before link-local).

        An IPv6 link-local address needs a zone to connect to, so one is
        kept only when it carries a zone (``fe80::1%en0``) or the instance has
        an ``interface`` to supply it.
        """
        return sorted(
            (a for a in self.addresses if a.is_usable_candidate and self._connectable(a)),
            key=lambda a: a.preference,
        )

    def _connectable(self, address: Address) -> bool:
        if address.family is not AddressFamily.IPV6 or not address.is_link_local:
            return True
        return "%" in address.address or self.interface is not None

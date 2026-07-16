"""The service-discovery record model and its address classification.

A ``Record`` is one DNS-SD service instance as observed on one network
interface. The wire form (see ``record.schema.json``) is deliberately raw: it
carries the literal addresses and never a computed ``scope``. Scope, APIPA and
reachability-preference are *derived* here so the classification can evolve
without a contract change and every consumer shares one implementation.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from urllib.parse import quote

SCHEMA_VERSION = 2
DEFAULT_TOPIC_BASE = "local/mdns/discovery/v2"

_ULA_NET = ipaddress.ip_network("fc00::/7")


class AddressFamily(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"


class AddressScope(str, Enum):
    GLOBAL = "global"
    PRIVATE = "private"  # IPv4 RFC 1918
    UNIQUE_LOCAL = "unique-local"  # IPv6 fc00::/7
    LINK_LOCAL = "link-local"  # IPv6 fe80::/10 and IPv4 APIPA 169.254/16
    LOOPBACK = "loopback"
    UNSPECIFIED = "unspecified"
    OTHER = "other"


class RecordState(str, Enum):
    ACTIVE = "active"
    REMOVED = "removed"


# Lower sorts first: a resolver should try routable candidates before
# link-local/APIPA ones. This is a hint for ordering, not a reachability claim.
_SCOPE_PREFERENCE = {
    AddressScope.GLOBAL: 0,
    AddressScope.PRIVATE: 1,
    AddressScope.UNIQUE_LOCAL: 1,
    AddressScope.LINK_LOCAL: 2,
    AddressScope.OTHER: 3,
    AddressScope.LOOPBACK: 4,
    AddressScope.UNSPECIFIED: 5,
}


def _to_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _from_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


@dataclass(frozen=True)
class Address:
    """A single literal IP address advertised for an instance.

    ``family`` is redundant with the literal but kept for readability; every
    other property here is derived from the address value.
    """

    address: str
    family: AddressFamily

    @classmethod
    def parse(cls, address: str) -> Address:
        family = AddressFamily.IPV6 if ":" in address else AddressFamily.IPV4
        return cls(address=address, family=family)

    @property
    def ip(self) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        # Drop any IPv6 zone id (fe80::1%eth0) before parsing.
        return ipaddress.ip_address(self.address.split("%", 1)[0])

    @property
    def scope(self) -> AddressScope:
        ip = self.ip
        if ip.is_loopback:
            return AddressScope.LOOPBACK
        if ip.is_unspecified:
            return AddressScope.UNSPECIFIED
        if ip.is_link_local:  # fe80::/10 for IPv6, 169.254/16 (APIPA) for IPv4
            return AddressScope.LINK_LOCAL
        if isinstance(ip, ipaddress.IPv6Address) and ip in _ULA_NET:
            return AddressScope.UNIQUE_LOCAL
        if isinstance(ip, ipaddress.IPv4Address) and ip.is_private:
            return AddressScope.PRIVATE
        if ip.is_global:
            return AddressScope.GLOBAL
        return AddressScope.OTHER

    @property
    def is_link_local(self) -> bool:
        return self.ip.is_link_local

    @property
    def is_apipa(self) -> bool:
        """True for an IPv4 169.254/16 self-assigned address (DHCPv4 failed)."""
        return self.family is AddressFamily.IPV4 and self.ip.is_link_local

    @property
    def is_usable_candidate(self) -> bool:
        """A plausible peer address to attempt (excludes loopback/unspecified)."""
        return not (self.ip.is_loopback or self.ip.is_unspecified)

    @property
    def preference(self) -> int:
        """Sort key for ordering candidates before a reachability probe."""
        return _SCOPE_PREFERENCE.get(self.scope, 3)

    def to_dict(self) -> dict[str, str]:
        return {"address": self.address, "family": self.family.value}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Address:
        return cls(address=d["address"], family=AddressFamily(d["family"]))


@dataclass
class Record:
    """One DNS-SD service instance as observed on one interface."""

    service_type: str
    instance_name: str
    hostname: str
    interface: str
    port: int
    addresses: list[Address] = field(default_factory=list)
    txt: dict[str, str] = field(default_factory=dict)
    state: RecordState = RecordState.ACTIVE
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    ttl_seconds: int | None = None
    removed_at: datetime | None = None
    schema_version: int = SCHEMA_VERSION

    @property
    def is_removed(self) -> bool:
        return self.state is RecordState.REMOVED

    def topic(self, base: str = DEFAULT_TOPIC_BASE) -> str:
        """The retained topic for this record. The instance label is
        percent-encoded so an arbitrary UTF-8 label is a single safe segment."""
        instance = quote(self.instance_name, safe="")
        return f"{base}/{self.service_type}/{self.interface}/{instance}"

    def age_seconds(self, now: datetime | None = None) -> float | None:
        if self.last_seen is None:
            return None
        now = now or datetime.now(timezone.utc)
        return (now - self.last_seen).total_seconds()

    def is_stale(self, now: datetime | None = None, grace_seconds: float = 0.0) -> bool:
        """True if the record has outlived its advertised ttl (+ grace). A
        client can age out a record before a tombstone arrives; returns False
        when no ttl is known."""
        if self.ttl_seconds is None:
            return False
        age = self.age_seconds(now)
        return age is not None and age > self.ttl_seconds + grace_seconds

    def candidate_addresses(self) -> list[Address]:
        """Usable addresses, most-preferred first (routable before link-local)."""
        return sorted(
            (a for a in self.addresses if a.is_usable_candidate),
            key=lambda a: a.preference,
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "schema_version": self.schema_version,
            "service_type": self.service_type,
            "instance_name": self.instance_name,
            "hostname": self.hostname,
            "interface": self.interface,
            "port": self.port,
            "addresses": [a.to_dict() for a in self.addresses],
            "txt": dict(self.txt),
            "state": self.state.value,
        }
        if self.first_seen is not None:
            out["first_seen"] = _to_iso(self.first_seen)
        if self.last_seen is not None:
            out["last_seen"] = _to_iso(self.last_seen)
        if self.ttl_seconds is not None:
            out["ttl_seconds"] = self.ttl_seconds
        if self.is_removed and self.removed_at is not None:
            out["removed_at"] = _to_iso(self.removed_at)
        return out

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Record:
        return cls(
            service_type=d["service_type"],
            instance_name=d["instance_name"],
            hostname=d["hostname"],
            interface=d["interface"],
            port=d["port"],
            addresses=[Address.from_dict(a) for a in d.get("addresses", [])],
            txt=dict(d.get("txt", {})),
            state=RecordState(d.get("state", "active")),
            first_seen=_from_iso(d["first_seen"]) if d.get("first_seen") else None,
            last_seen=_from_iso(d["last_seen"]) if d.get("last_seen") else None,
            ttl_seconds=d.get("ttl_seconds"),
            removed_at=_from_iso(d["removed_at"]) if d.get("removed_at") else None,
            schema_version=d.get("schema_version", SCHEMA_VERSION),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"))

    @classmethod
    def from_json(cls, payload: str | bytes) -> Record:
        if isinstance(payload, (bytes, bytearray)):
            payload = payload.decode("utf-8")
        return cls.from_dict(json.loads(payload))

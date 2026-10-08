"""The eBus discovery contract as data and pure functions (standard library only).

The eBus framework specification (framework.md, "Detail: mDNS Discovery")
defines which DNS-SD services an entity advertises, the TXT keys of each, the
broker service types and their preference order, and the broker modes. This
module encodes that contract with no I/O, so the direct mDNS source
(``mdns`` / ``mdns_async``), the MQTT bus and any test can share it.
"""

from __future__ import annotations

import copy
import dataclasses
import enum
import ipaddress
import logging
import warnings
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ebus_service_discovery.instance import ServiceInstance, strip_dot
from ebus_service_discovery.record import Address

logger = logging.getLogger(__name__)

# --- service types ----------------------------------------------------------

EBUS_SERVICE = "_ebus._tcp"
DEVICE_INFO_SERVICE = "_device-info._tcp"
HTTP_SERVICE = "_http._tcp"
HTTPS_SERVICE = "_https._tcp"

SECURE_MQTT_SERVICE = "_secure-mqtt._tcp"
MQTT_WSS_SERVICE = "_mqtt-wss._tcp"
MQTT_WS_SERVICE = "_mqtt-ws._tcp"
MQTT_SERVICE = "_mqtt._tcp"

#: Broker service types in the specification's preference order ("Broker Discovery").
BROKER_PREFERENCE: tuple[str, ...] = (
    SECURE_MQTT_SERVICE,
    MQTT_WSS_SERVICE,
    MQTT_WS_SERVICE,
    MQTT_SERVICE,
)

#: The broker types an MQTT-over-TCP client can use; the default accept set
#: when no TLS is configured (with TLS, ``_secure-mqtt._tcp`` alone).
#: ebus-mqtt-client has no WebSocket transport, so ``_mqtt-ws`` / ``_mqtt-wss``
#: brokers are reported but not selected unless a caller accepts them.
TCP_BROKER_TYPES: tuple[str, ...] = (SECURE_MQTT_SERVICE, MQTT_SERVICE)

#: Port used when an advertisement carries none.
BROKER_DEFAULT_PORT: dict[str, int] = {
    SECURE_MQTT_SERVICE: 8883,
    MQTT_WSS_SERVICE: 9002,
    MQTT_WS_SERVICE: 9001,
    MQTT_SERVICE: 1883,
}

_BROKER_TLS: dict[str, bool] = {
    SECURE_MQTT_SERVICE: True,
    MQTT_WSS_SERVICE: True,
    MQTT_WS_SERVICE: False,
    MQTT_SERVICE: False,
}

_BROKER_SCHEME: dict[str, str] = {
    SECURE_MQTT_SERVICE: "mqtts",
    MQTT_WSS_SERVICE: "wss",
    MQTT_WS_SERVICE: "ws",
    MQTT_SERVICE: "mqtt",
}

_URL_SCHEME_TYPE: dict[str, str] = {
    "mqtts": SECURE_MQTT_SERVICE,
    "mqtt": MQTT_SERVICE,
}

#: The framework.md version this library implements; the default ``ebus_version``.
EBUS_SPEC_VERSION = "0.9"

TXTVERS = "1"

ROLE_DEVICE = "device"
ROLE_CONTROLLER = "controller"
ROLE_BROKER_HOST = "broker-host"
KNOWN_ROLES: frozenset[str] = frozenset({ROLE_DEVICE, ROLE_CONTROLLER, ROLE_BROKER_HOST})


# --- broker mode -------------------------------------------------------------


class BrokerMode(str, enum.Enum):
    """How an entity finds its broker (framework.md requirement 22)."""

    CONFIGURED_ONLY = "configured-only"
    DISCOVERY_WITH_FALLBACK = "discovery-with-fallback"
    DISCOVERY_ONLY = "discovery-only"

    @classmethod
    def parse(cls, value: str | BrokerMode | None) -> BrokerMode:
        """Parse a mode from configuration.

        Accepts the specification's spellings, case-insensitively and with
        ``_`` for ``-``. ``None`` or ``""`` is the specification's default,
        ``discovery-only``.
        """
        if isinstance(value, BrokerMode):
            return value
        if value is None or not str(value).strip():
            return DEFAULT_BROKER_MODE
        text = str(value).strip().lower().replace("_", "-")
        for mode in cls:
            if mode.value == text:
                return mode
        valid = ", ".join(m.value for m in cls)
        raise ValueError(f"unknown broker mode {value!r}; expected one of {valid}")


DEFAULT_BROKER_MODE = BrokerMode.DISCOVERY_ONLY


# --- TXT --------------------------------------------------------------------


def decode_txt(properties: Mapping[bytes | str, bytes | str | None]) -> dict[str, str]:
    """Decode DNS-SD TXT properties to ``str -> str``.

    Keys are lowercased (DNS-SD TXT keys are case-insensitive, RFC 6763 6.4).
    A key with no value (a boolean attribute) becomes ``""``. Bytes decode as
    UTF-8, with undecodable bytes replaced.
    """
    out: dict[str, str] = {}
    for key, value in properties.items():
        k = key.decode("utf-8", "replace") if isinstance(key, (bytes, bytearray)) else str(key)
        if value is None:
            v = ""
        elif isinstance(value, (bytes, bytearray)):
            v = bytes(value).decode("utf-8", "replace")
        else:
            v = str(value)
        out[k.lower()] = v
    return out


def _split_list(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(p.strip() for p in value.split(",") if p.strip())


EBUS_REQUIRED_KEYS: tuple[str, ...] = ("txtvers", "ebus_version", "roles", "device_id")
EBUS_RECOMMENDED_KEYS: tuple[str, ...] = (
    "device_type",
    "name",
    "manufacturer",
    "model",
    "fw_version",
    "register",
    "broker_ca",
    "auth_methods",
)
DEVICE_INFO_REQUIRED_KEYS: tuple[str, ...] = ("txtvers", "manufacturer", "model", "serial_number")
DEVICE_INFO_RECOMMENDED_KEYS: tuple[str, ...] = ("fw_version", "hw_version", "os_version", "mac")


@dataclass(frozen=True)
class EbusTxt:
    """A parsed ``_ebus._tcp`` TXT record."""

    txtvers: str
    ebus_version: str
    roles: tuple[str, ...]
    device_ids: tuple[str, ...]
    auth_methods: tuple[str, ...]
    txt: dict[str, str]

    @property
    def missing(self) -> tuple[str, ...]:
        """Required keys absent or empty in the advertisement."""
        return tuple(k for k in EBUS_REQUIRED_KEYS if not self.txt.get(k))

    @property
    def is_broker_host(self) -> bool:
        return ROLE_BROKER_HOST in self.roles

    def get(self, key: str, default: str | None = None) -> str | None:
        return self.txt.get(key.lower(), default)


def parse_ebus_txt(txt: Mapping[bytes | str, bytes | str | None]) -> EbusTxt:
    """Parse an ``_ebus._tcp`` TXT record, raw or already decoded.

    ``roles``, ``device_id`` and ``auth_methods`` are comma-separated lists. A
    missing key parses as empty; ``EbusTxt.missing`` names the required ones.
    """
    d = decode_txt(txt)
    return EbusTxt(
        txtvers=d.get("txtvers", ""),
        ebus_version=d.get("ebus_version", ""),
        roles=_split_list(d.get("roles")),
        device_ids=_split_list(d.get("device_id")),
        auth_methods=_split_list(d.get("auth_methods")),
        txt=d,
    )


#: Longest single TXT string (``key=value``) mDNS can carry: one length byte.
TXT_STRING_MAX = 255
#: Warn when one TXT string passes this many bytes.
TXT_STRING_WARN = 200
#: Warn when a whole TXT record passes this many bytes (RFC 6763 6.2 advises
#: against TXT records over 1300 bytes).
TXT_TOTAL_WARN = 1300


class TxtSizeWarning(UserWarning):
    """A TXT record is approaching an mDNS size limit."""


def txt_wire_size(txt: Mapping[str, str]) -> int:
    """Bytes the TXT record occupies on the wire (a length byte per string)."""
    return sum(1 + len(_txt_string(k, v)) for k, v in txt.items())


def _txt_string(key: str, value: str) -> bytes:
    return f"{key}={value}".encode()


def check_txt(service_type: str, txt: Mapping[str, str]) -> None:
    """Validate a TXT record's sizes and keys.

    Raises ``ValueError`` for what mDNS cannot carry (a ``key=value`` string
    over 255 bytes, an empty key or one containing ``=``) and warns
    (``TxtSizeWarning``) as a string or the whole record nears the limits.
    """
    for key, value in txt.items():
        if not key or "=" in key or not key.isascii() or not key.isprintable():
            raise ValueError(f"{service_type}: invalid TXT key {key!r}")
        n = len(_txt_string(key, value))
        if n > TXT_STRING_MAX:
            raise ValueError(
                f"{service_type}: TXT {key!r} is {n} bytes; one TXT string holds at most "
                f"{TXT_STRING_MAX}"
            )
        if n > TXT_STRING_WARN:
            warnings.warn(
                f"{service_type}: TXT {key!r} is {n} bytes, near the {TXT_STRING_MAX}-byte "
                "limit of one TXT string",
                TxtSizeWarning,
                stacklevel=3,
            )
    total = txt_wire_size(txt)
    if total > TXT_TOTAL_WARN:
        warnings.warn(
            f"{service_type}: TXT record is {total} bytes; keep it under {TXT_TOTAL_WARN}",
            TxtSizeWarning,
            stacklevel=3,
        )


# --- identity (what an entity advertises) -----------------------------------


def _as_tuple(value: str | Iterable[str] | None) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return _split_list(value)
    return tuple(str(v).strip() for v in value)


def _put(txt: dict[str, str], key: str, value: str | None) -> None:
    if value:
        txt[key] = value


@dataclass(frozen=True)
class Identity:
    """An entity's ``_ebus._tcp`` and ``_device-info._tcp`` advertisement content.

    One ``_ebus._tcp`` advertisement covers the whole host, so ``device_ids``
    may list several devices; they are joined with commas into ``device_id``.
    ``roles`` and ``auth_methods`` are lists, joined the same way. Recommended
    keys left empty are omitted. ``extra_ebus_txt`` / ``extra_device_info_txt``
    add keys the specification does not define. Construction validates the
    required keys and the TXT sizes (see ``check_txt``).
    """

    device_ids: Sequence[str] | str
    roles: Sequence[str] | str
    manufacturer: str
    model: str
    serial_number: str
    ebus_version: str = EBUS_SPEC_VERSION
    device_type: str | None = None
    name: str | None = None
    fw_version: str | None = None
    register: str | None = None
    broker_ca: str | None = None
    auth_methods: Sequence[str] | str | None = None
    hw_version: str | None = None
    os_version: str | None = None
    mac: str | None = None
    extra_ebus_txt: Mapping[str, str] = field(default_factory=dict)
    extra_device_info_txt: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "device_ids", _as_tuple(self.device_ids))
        object.__setattr__(self, "roles", _as_tuple(self.roles))
        object.__setattr__(self, "auth_methods", _as_tuple(self.auth_methods))
        if not self.device_ids:
            raise ValueError("Identity needs at least one device id")
        for did in self.device_ids:
            if not did or "," in did:
                raise ValueError(f"invalid device id {did!r} (empty or contains a comma)")
        if not self.roles:
            raise ValueError("Identity needs at least one role")
        for role in self.roles:
            if not role or "," in role:
                raise ValueError(f"invalid role {role!r}")
            if role not in KNOWN_ROLES:
                logger.warning("reason=unknownEbusRole,role=%s", role)
        for key in ("manufacturer", "model", "serial_number", "ebus_version"):
            if not getattr(self, key):
                raise ValueError(f"Identity.{key} is required")
        check_txt(EBUS_SERVICE, self.ebus_txt())
        check_txt(DEVICE_INFO_SERVICE, self.device_info_txt())

    @property
    def device_id(self) -> str:
        """The ``device_id`` TXT value: the device ids joined with commas."""
        return ",".join(self.device_ids)

    def ebus_txt(self) -> dict[str, str]:
        """The ``_ebus._tcp`` TXT record."""
        txt = {
            "txtvers": TXTVERS,
            "ebus_version": self.ebus_version,
            "roles": ",".join(self.roles),
            "device_id": self.device_id,
        }
        _put(txt, "device_type", self.device_type)
        _put(txt, "name", self.name)
        _put(txt, "manufacturer", self.manufacturer)
        _put(txt, "model", self.model)
        _put(txt, "fw_version", self.fw_version)
        _put(txt, "register", self.register)
        _put(txt, "broker_ca", self.broker_ca)
        _put(txt, "auth_methods", ",".join(self.auth_methods))
        for k, v in self.extra_ebus_txt.items():
            txt.setdefault(k, v)
        return txt

    def device_info_txt(self) -> dict[str, str]:
        """The ``_device-info._tcp`` TXT record."""
        txt = {
            "txtvers": TXTVERS,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "serial_number": self.serial_number,
        }
        _put(txt, "fw_version", self.fw_version)
        _put(txt, "hw_version", self.hw_version)
        _put(txt, "os_version", self.os_version)
        _put(txt, "mac", self.mac)
        for k, v in self.extra_device_info_txt.items():
            txt.setdefault(k, v)
        return txt


@dataclass(frozen=True)
class HttpService:
    """An HTTP REST API to advertise as ``_http._tcp`` or ``_https._tcp``.

    The TXT carries ``path``, ``version``, ``openapi`` (when set), and the
    identity's ``device_id`` and ``device_type`` (framework.md, "HTTP API
    Advertisement").
    """

    port: int
    path: str = "/api/v1"
    version: str = "1.0"
    tls: bool = False
    openapi: str | None = None
    extra_txt: Mapping[str, str] = field(default_factory=dict)

    @property
    def service_type(self) -> str:
        return HTTPS_SERVICE if self.tls else HTTP_SERVICE

    def txt(self, identity: Identity) -> dict[str, str]:
        txt = {
            "txtvers": TXTVERS,
            "path": self.path,
            "version": self.version,
            "device_id": identity.device_id,
        }
        _put(txt, "device_type", identity.device_type)
        _put(txt, "openapi", self.openapi)
        for k, v in self.extra_txt.items():
            txt.setdefault(k, v)
        check_txt(self.service_type, txt)
        return txt


# --- brokers ----------------------------------------------------------------


def broker_uses_tls(service_type: str) -> bool:
    """True for the TLS broker transports (``_secure-mqtt``, ``_mqtt-wss``)."""
    return _BROKER_TLS.get(service_type, False)


@dataclass(frozen=True)
class BrokerEndpoint:
    """A broker to connect to, discovered or configured.

    ``host`` is the TXT ``broker`` value when advertised (the name a broker's
    certificate is issued for), otherwise the SRV target; either without a
    trailing dot. ``use_tls`` follows from the service type.
    """

    service_type: str
    host: str
    port: int
    txt: dict[str, str] = field(default_factory=dict)
    addresses: tuple[Address, ...] = ()
    instance_name: str | None = None
    server: str | None = None
    interface: str | None = None

    @property
    def use_tls(self) -> bool:
        return broker_uses_tls(self.service_type)

    @property
    def is_tcp(self) -> bool:
        """True when an MQTT-over-TCP client (ebus-mqtt-client) can connect."""
        return self.service_type in TCP_BROKER_TYPES

    @property
    def url(self) -> str:
        scheme = _BROKER_SCHEME.get(self.service_type, "mqtt")
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{scheme}://{host}:{self.port}"

    @classmethod
    def from_instance(cls, instance: ServiceInstance) -> BrokerEndpoint:
        """A broker endpoint from a browsed broker service instance."""
        broker = (instance.txt.get("broker") or "").strip()
        server = strip_dot(instance.server) if instance.server else ""
        host = strip_dot(broker) if broker else server
        port = instance.port or BROKER_DEFAULT_PORT.get(instance.service_type, 1883)
        return cls(
            service_type=instance.service_type,
            host=host,
            port=port,
            txt=dict(instance.txt),
            addresses=tuple(instance.addresses),
            instance_name=instance.instance_name,
            server=server or None,
            interface=instance.interface,
        )

    @classmethod
    def from_url(cls, url: str) -> BrokerEndpoint:
        """A broker endpoint from a configured ``mqtt://`` or ``mqtts://`` URL.

        The port defaults to 1883 or 8883 when the URL has none.
        """
        parts = urlsplit(url.strip())
        scheme = parts.scheme.lower()
        if scheme not in _URL_SCHEME_TYPE:
            raise ValueError(
                f"unsupported broker URL {url!r}: expected mqtt:// or mqtts:// "
                "(MQTT over TCP; no WebSocket transport)"
            )
        if not parts.hostname:
            raise ValueError(f"broker URL {url!r} has no host")
        service_type = _URL_SCHEME_TYPE[scheme]
        port = parts.port or BROKER_DEFAULT_PORT[service_type]
        return cls(service_type=service_type, host=parts.hostname, port=port)

    @classmethod
    def from_mqtt_cfg(cls, cfg: Mapping) -> BrokerEndpoint:
        """The broker an ebus-mqtt-client config names (``host``, ``port``, ``use_tls``)."""
        host = str(cfg.get("host") or "").strip()
        if not host:
            raise ValueError("broker config has no host")
        service_type = SECURE_MQTT_SERVICE if cfg.get("use_tls") else MQTT_SERVICE
        port = int(cfg.get("port") or BROKER_DEFAULT_PORT[service_type])
        return cls(service_type=service_type, host=host, port=port)

    def mqtt_cfg(self, base: Mapping | None = None) -> dict:
        """A copy of an ebus-mqtt-client config with this broker's address.

        Only ``host``, ``port`` and ``use_tls`` are replaced; every other key
        (authentication, CA and client certificates) is kept, and ``base`` is
        not modified. Replacing ``use_tls`` True with False logs a warning.
        """
        cfg = copy.deepcopy(dict(base)) if base else {}
        if cfg.get("use_tls") and not self.use_tls:
            logger.warning("reason=tlsDisabledForPlainBroker,url=%s", self.url)
        cfg["host"] = self.host
        cfg["port"] = self.port
        cfg["use_tls"] = self.use_tls
        return cfg


def _norm_host(name: str | None) -> str:
    return strip_dot(name).lower() if name else ""


def _broker_keys(ep: BrokerEndpoint) -> set[tuple[str, str]]:
    keys = {("host", _norm_host(ep.host))}
    if ep.server:
        keys.add(("host", _norm_host(ep.server)))
    if ep.txt.get("device_id"):
        keys.add(("device_id", ep.txt["device_id"]))
    keys.discard(("host", ""))
    return keys


def rank_brokers(
    endpoints: Iterable[BrokerEndpoint], accept: Sequence[str] | None = None
) -> list[BrokerEndpoint]:
    """One endpoint per distinct broker, most-preferred transport first.

    A broker host often advertises itself under several service types (TLS
    and plain, say), and may be heard on several interfaces. Endpoints that
    share a host name, SRV target or ``device_id`` are one broker; its most
    preferred accepted type is kept. The result is ordered by
    ``BROKER_PREFERENCE`` and then by host name, so every client sees the same
    order. ``accept`` limits the types considered (default: all four).
    """
    allowed = tuple(accept) if accept is not None else BROKER_PREFERENCE
    rank = {t: i for i, t in enumerate(BROKER_PREFERENCE)}
    candidates = sorted(
        (e for e in endpoints if e.service_type in allowed and e.service_type in rank),
        key=lambda e: (rank[e.service_type], _norm_host(e.host), e.port),
    )
    kept: list[tuple[BrokerEndpoint, set[tuple[str, str]]]] = []
    for ep in candidates:
        keys = _broker_keys(ep)
        for _, seen in kept:
            if seen & keys:
                seen |= keys
                break
        else:
            kept.append((ep, keys))
    return [ep for ep, _ in kept]


def _ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return None


def _find_configured(
    configured: BrokerEndpoint, ranked: Iterable[BrokerEndpoint]
) -> tuple[BrokerEndpoint, BrokerEndpoint] | None:
    """(discovered endpoint, endpoint to use) for the first match, or None."""
    want = _norm_host(configured.host)
    want_ip = _ip(configured.host)
    for ep in ranked:
        if want in (_norm_host(ep.host), _norm_host(ep.server)):
            return ep, ep
        if want_ip is not None and any(_ip(a.address) == want_ip for a in ep.addresses):
            return ep, dataclasses.replace(ep, host=configured.host)
    return None


def match_configured(
    configured: BrokerEndpoint, ranked: Iterable[BrokerEndpoint]
) -> BrokerEndpoint | None:
    """The discovered broker that is the configured one, or None.

    A discovered broker matches when the configured host equals its TXT
    ``broker`` name or SRV target (case-insensitive, trailing dot ignored) or,
    for a configured IP address, one of its advertised addresses. The first
    match in ``ranked`` is returned with its discovered port and transport;
    a match by address keeps the configured address as ``host``.
    """
    found = _find_configured(configured, ranked)
    return found[1] if found else None


def select_broker(
    mode: BrokerMode | str | None,
    configured: BrokerEndpoint | None,
    ranked: Sequence[BrokerEndpoint],
    *,
    allow_unmatched: bool = False,
) -> BrokerEndpoint | None:
    """Choose the broker to connect to.

    - ``configured-only``: ``configured`` (discovery is ignored).
    - ``discovery-only``: the first of ``ranked``, or None.
    - ``discovery-with-fallback``: the discovered broker that matches
      ``configured`` (see ``match_configured``), else ``configured``. A
      different discovered broker is never chosen in place of the configured
      one unless ``allow_unmatched`` is True, which restores the 0.4.0
      behavior: the matching broker if any, else the first of ``ranked``.
      With no ``configured``, the first of ``ranked``.

    Choosing among several distinct discovered brokers in ``discovery-only``,
    or with no configured broker, is outside the specification; here the
    first of ``ranked`` wins (the
    most-preferred transport, then the lowest host name). Each discovered
    broker not chosen is logged.
    """
    mode = BrokerMode.parse(mode)
    if mode is BrokerMode.CONFIGURED_ONLY:
        return configured
    if not ranked:
        return configured if mode is BrokerMode.DISCOVERY_WITH_FALLBACK else None
    picked = ranked[0]  # the discovered endpoint chosen
    chosen = picked
    if mode is BrokerMode.DISCOVERY_WITH_FALLBACK and configured is not None:
        found = _find_configured(configured, ranked)
        if found is not None:
            picked, chosen = found
        elif not allow_unmatched:
            picked = chosen = configured
    for ep in ranked:
        if ep is not picked:
            logger.info("reason=brokerNotChosen,url=%s,chosen=%s", ep.url, chosen.url)
    if chosen is configured:
        logger.info("reason=configuredBrokerNotDiscovered,url=%s", configured.url)
        return configured
    if len(ranked) > 1:
        logger.info(
            "reason=brokerChosenAmongSeveral,count=%d,chosen=%s,candidates=%s",
            len(ranked),
            chosen.url,
            "|".join(ep.url for ep in ranked),
        )
    return chosen


# --- retry ------------------------------------------------------------------


@dataclass(frozen=True)
class RetrySchedule:
    """When to browse again while no broker is found.

    The default matches esp32-sdk: three attempts 3 s apart, then one every
    30 s. ``max_attempts`` (None: unbounded) caps the total.
    """

    fast_attempts: int = 3
    fast_interval: float = 3.0
    slow_interval: float = 30.0
    max_attempts: int | None = None

    def delay(self, attempt: int) -> float:
        """Seconds to wait before attempt ``attempt`` (0-based; attempt 0 is immediate)."""
        if attempt <= 0:
            return 0.0
        return self.fast_interval if attempt < self.fast_attempts else self.slow_interval

    def delays(self) -> Iterator[float]:
        """The wait before each attempt, in order: 0, 3, 3, 30, 30, ..."""
        attempt = 0
        while self.max_attempts is None or attempt < self.max_attempts:
            yield self.delay(attempt)
            attempt += 1

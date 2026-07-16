from datetime import datetime, timezone

import pytest

from ebus_service_discovery_client import (
    Address,
    AddressFamily,
    AddressScope,
    Record,
    RecordState,
    validate_record,
)


def _record(**overrides):
    base = dict(
        service_type="_example._tcp",
        instance_name="Example Device 42",
        hostname="host-1234.local",
        interface="eth0",
        port=80,
        addresses=[
            Address.parse("192.168.1.10"),
            Address.parse("2606:4700:4700::1111"),
            Address.parse("fe80::1"),
        ],
        txt={"model": "example-1", "id": "abc123"},
        first_seen=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        last_seen=datetime(2026, 1, 2, 3, 9, 5, tzinfo=timezone.utc),
        ttl_seconds=120,
    )
    base.update(overrides)
    return Record(**base)


@pytest.mark.parametrize(
    "literal,family",
    [("192.168.1.10", AddressFamily.IPV4), ("fe80::1", AddressFamily.IPV6)],
)
def test_address_family_inferred(literal, family):
    assert Address.parse(literal).family is family


@pytest.mark.parametrize(
    "literal,scope",
    [
        ("8.8.8.8", AddressScope.GLOBAL),
        ("192.168.1.10", AddressScope.PRIVATE),
        ("169.254.1.1", AddressScope.LINK_LOCAL),  # IPv4 APIPA
        ("127.0.0.1", AddressScope.LOOPBACK),
        ("2606:4700:4700::1111", AddressScope.GLOBAL),
        ("fd00::5", AddressScope.UNIQUE_LOCAL),
        ("fe80::1", AddressScope.LINK_LOCAL),
        ("::1", AddressScope.LOOPBACK),
    ],
)
def test_address_scope(literal, scope):
    assert Address.parse(literal).scope is scope


def test_apipa_detection():
    assert Address.parse("169.254.1.1").is_apipa is True
    assert Address.parse("192.168.1.10").is_apipa is False
    assert Address.parse("fe80::1").is_apipa is False  # link-local but not IPv4


def test_zone_id_stripped_for_classification():
    assert Address.parse("fe80::1%eth0").scope is AddressScope.LINK_LOCAL


def test_candidate_ordering_prefers_routable_over_link_local():
    rec = _record()
    ordered = [a.address for a in rec.candidate_addresses()]
    # global IPv6 and private IPv4 rank ahead of the link-local IPv6
    assert ordered[-1] == "fe80::1"
    assert set(ordered[:2]) == {"192.168.1.10", "2606:4700:4700::1111"}


def test_topic_percent_encodes_instance():
    rec = _record(instance_name="Example Device 42")
    assert rec.topic() == "local/mdns/discovery/v1/_example._tcp/eth0/Example%20Device%2042"
    assert rec.topic(base="x/y") == "x/y/_example._tcp/eth0/Example%20Device%2042"


def test_json_round_trip():
    rec = _record()
    again = Record.from_json(rec.to_json())
    assert again.to_dict() == rec.to_dict()
    assert again.addresses == rec.addresses  # frozen dataclass equality


def test_ipv6_only_record_survives_round_trip():
    rec = _record(addresses=[Address.parse("fe80::1")])
    again = Record.from_json(rec.to_json())
    assert [a.address for a in again.addresses] == ["fe80::1"]


def test_active_dict_has_no_removed_at_and_validates():
    d = _record().to_dict()
    assert "removed_at" not in d
    validate_record(d)  # raises if invalid


def test_tombstone_carries_full_record_and_validates():
    rec = _record(
        state=RecordState.REMOVED,
        removed_at=datetime(2026, 1, 2, 3, 14, 5, tzinfo=timezone.utc),
    )
    d = rec.to_dict()
    assert d["state"] == "removed"
    assert d["removed_at"] == "2026-01-02T03:14:05Z"
    assert d["hostname"] == "host-1234.local"  # full last-known fields retained
    validate_record(d)
    assert Record.from_json(rec.to_json()).is_removed is True


def test_staleness_by_ttl():
    seen = datetime(2026, 1, 2, 3, 0, 0, tzinfo=timezone.utc)
    rec = _record(last_seen=seen, ttl_seconds=120)
    assert rec.is_stale(now=datetime(2026, 1, 2, 3, 1, 0, tzinfo=timezone.utc)) is False
    assert rec.is_stale(now=datetime(2026, 1, 2, 3, 5, 0, tzinfo=timezone.utc)) is True
    # No ttl -> never reported stale on this basis.
    assert (
        _record(ttl_seconds=None).is_stale(now=datetime(2030, 1, 1, tzinfo=timezone.utc)) is False
    )


def test_scope_preference_other_before_link_local():
    # A potentially-routable OTHER address (e.g. CGNAT 100.64/10) is tried before
    # a link-local address, which is only reachable on its own interface.
    cgnat = Address.parse("100.64.0.1")
    assert cgnat.scope is AddressScope.OTHER
    assert cgnat.preference < Address.parse("fe80::1").preference

import json
from datetime import datetime, timezone

import pytest

from ebus_service_discovery_client import Address, Record
from ebus_service_discovery_client.cli import (
    _format_age,
    _match_from_arg,
    main,
    record_to_debug_json,
    render_resolution,
    render_tree,
    resolution_to_json,
)
from ebus_service_discovery_client.resolver import Resolution

NOW = datetime(2026, 1, 1, 0, 10, 0, tzinfo=timezone.utc)


def _record(**kw):
    base = dict(
        service_type="_example._tcp",
        instance_name="Dev 1",
        hostname="h.local",
        interface="eth0",
        port=80,
        addresses=[Address.parse("192.168.1.10"), Address.parse("fe80::1")],
        txt={"serial": "abc"},
        first_seen=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        last_seen=datetime(2026, 1, 1, 0, 5, 0, tzinfo=timezone.utc),
        ttl_seconds=120,
    )
    base.update(kw)
    return Record(**base)


@pytest.mark.parametrize(
    "seconds,text",
    [(None, "?"), (5, "5s"), (90, "1m"), (7200, "2h"), (200000, "2d")],
)
def test_format_age(seconds, text):
    assert _format_age(seconds) == text


def test_render_tree_structure():
    out = render_tree([_record()], now=NOW)
    assert "_example._tcp" in out
    assert "  eth0" in out
    assert "Dev 1" in out and "h.local:80" in out
    assert "192.168.1.10  (ipv4/private)" in out
    assert "fe80::1  (ipv6/link-local)" in out
    assert "STALE" in out  # last_seen 00:05, ttl 120s, now 00:10 -> stale


def test_render_tree_empty():
    assert render_tree([], now=NOW) == "(no records)"


def test_render_resolution():
    rec = _record()
    res = Resolution(rec, Address.parse("192.168.1.10"), "eth0", 443)
    text = render_resolution(res)
    assert "192.168.1.10:443" in text and "via eth0" in text and "ipv4/private" in text
    assert render_resolution(None) == "unresolved (no reachable address)"


def test_match_from_arg():
    assert _match_from_arg(None) is None
    m = _match_from_arg("serial=abc")
    assert m(_record()) is True
    assert m(_record(txt={"serial": "zzz"})) is False


def test_validate_file_valid(tmp_path, capsys):
    p = tmp_path / "rec.json"
    p.write_text(json.dumps(_record().to_dict()))
    assert main(["validate", "--file", str(p)]) == 0
    assert "valid" in capsys.readouterr().out


def test_validate_file_invalid(tmp_path, capsys):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"schema_version": 1, "service_type": "_x._tcp"}))  # missing required
    assert main(["validate", "--file", str(p)]) == 1
    assert "INVALID" in capsys.readouterr().out


def test_validate_file_list(tmp_path, capsys):
    p = tmp_path / "recs.json"
    p.write_text(json.dumps([_record().to_dict(), _record(instance_name="Dev 2").to_dict()]))
    assert main(["validate", "--file", str(p)]) == 0
    assert "2 record(s), 0 invalid" in capsys.readouterr().out


def test_record_to_debug_json():
    d = record_to_debug_json(_record(), now=NOW)
    # wire fields survive
    assert d["service_type"] == "_example._tcp"
    assert d["instance_name"] == "Dev 1"
    # derived fields added
    assert d["age_seconds"] == 300.0  # last_seen 00:05, now 00:10
    assert d["is_stale"] is True  # ttl 120s exceeded
    # per-address scope classification is injected into each wire address
    scopes = {a["address"]: a["scope"] for a in d["addresses"]}
    assert scopes == {"192.168.1.10": "private", "fe80::1": "link-local"}
    # the wire address keys are untouched otherwise
    assert all("family" in a for a in d["addresses"])


def test_resolution_to_json():
    rec = _record()
    res = Resolution(rec, Address.parse("fe80::1"), "eth0", 443)
    d = resolution_to_json(res)
    assert d == {
        "host": "[fe80::1%eth0]",  # link-local host is zone-qualified
        "port": 443,
        "interface": "eth0",
        "address": "fe80::1",
        "family": "ipv6",
        "scope": "link-local",
        "service_type": "_example._tcp",
        "instance_name": "Dev 1",
    }
    assert resolution_to_json(None) is None


def test_validate_json_file_output(tmp_path, capsys):
    p = tmp_path / "recs.json"
    p.write_text(
        json.dumps(
            [
                _record().to_dict(),
                {"schema_version": 1, "service_type": "_x._tcp"},  # invalid
            ]
        )
    )
    # global --json precedes the subcommand
    assert main(["--json", "validate", "--file", str(p)]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out[0] == {"index": 0, "valid": True, "error": None}
    assert out[1]["index"] == 1 and out[1]["valid"] is False
    assert out[1]["error"]  # a non-empty message


def test_main_requires_subcommand():
    with pytest.raises(SystemExit):
        main([])

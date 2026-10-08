import logging
import subprocess
import sys
import warnings

import pytest

from ebus_service_discovery import Address, Record, ServiceInstance
from ebus_service_discovery.ebus import (
    BROKER_PREFERENCE,
    DEFAULT_BROKER_MODE,
    EBUS_SPEC_VERSION,
    MQTT_SERVICE,
    MQTT_WS_SERVICE,
    MQTT_WSS_SERVICE,
    SECURE_MQTT_SERVICE,
    TCP_BROKER_TYPES,
    BrokerEndpoint,
    BrokerMode,
    BrokerService,
    HttpService,
    Identity,
    RetrySchedule,
    TxtSizeWarning,
    check_txt,
    decode_txt,
    match_configured,
    parse_ebus_txt,
    rank_brokers,
    select_broker,
    txt_wire_size,
)


def _identity(**kw):
    base = dict(
        device_ids=["dev-1"],
        roles=["device"],
        manufacturer="Example",
        model="EX-1",
        serial_number="sn-0001",
    )
    base.update(kw)
    return Identity(**base)


def _inst(service_type, server="broker-1.local.", port=8883, txt=None, **kw):
    return ServiceInstance(
        service_type=service_type,
        instance_name=kw.pop("instance_name", "broker-1"),
        server=server,
        port=port,
        addresses=kw.pop("addresses", (Address.parse("192.0.2.10"),)),
        txt=txt or {},
        **kw,
    )


# --- ServiceInstance / Record.to_instance -----------------------------------


def test_record_to_instance():
    rec = Record(
        service_type="_http._tcp",
        instance_name="Dev 1",
        hostname="host-1.local.",
        interface="eth0",
        port=80,
        addresses=[Address.parse("fe80::1"), Address.parse("192.0.2.5")],
        txt={"path": "/api/v1"},
    )
    inst = rec.to_instance()
    assert inst == ServiceInstance(
        service_type="_http._tcp",
        instance_name="Dev 1",
        server="host-1.local",
        port=80,
        addresses=(Address.parse("fe80::1"), Address.parse("192.0.2.5")),
        txt={"path": "/api/v1"},
        interface="eth0",
    )
    assert [a.address for a in inst.candidate_addresses()] == ["192.0.2.5", "fe80::1"]
    inst.txt["path"] = "changed"
    assert rec.txt["path"] == "/api/v1"  # a copy


def test_candidates_drop_zoneless_link_local_without_interface():
    addrs = (
        Address.parse("fe80::1"),
        Address.parse("fe80::2%en0"),
        Address.parse("169.254.0.9"),
        Address.parse("192.0.2.5"),
    )
    inst = ServiceInstance("_http._tcp", "Dev 1", "host-1.local", 80, addresses=addrs)
    assert [a.address for a in inst.candidate_addresses()] == [
        "192.0.2.5",
        "fe80::2%en0",
        "169.254.0.9",
    ]
    assert inst.addresses == addrs  # the raw addresses are kept


# --- constants and mode -----------------------------------------------------


def test_preference_order_matches_specification():
    assert BROKER_PREFERENCE == (
        "_secure-mqtt._tcp",
        "_mqtt-wss._tcp",
        "_mqtt-ws._tcp",
        "_mqtt._tcp",
    )
    assert TCP_BROKER_TYPES == ("_secure-mqtt._tcp", "_mqtt._tcp")


@pytest.mark.parametrize(
    "text,mode",
    [
        ("configured-only", BrokerMode.CONFIGURED_ONLY),
        ("discovery-with-fallback", BrokerMode.DISCOVERY_WITH_FALLBACK),
        ("discovery-only", BrokerMode.DISCOVERY_ONLY),
        ("Discovery_Only", BrokerMode.DISCOVERY_ONLY),
        (" configured_only ", BrokerMode.CONFIGURED_ONLY),
        (None, BrokerMode.DISCOVERY_ONLY),
        ("", BrokerMode.DISCOVERY_ONLY),
        (BrokerMode.DISCOVERY_WITH_FALLBACK, BrokerMode.DISCOVERY_WITH_FALLBACK),
    ],
)
def test_broker_mode_parse(text, mode):
    assert BrokerMode.parse(text) is mode


def test_broker_mode_default_and_unknown():
    assert DEFAULT_BROKER_MODE is BrokerMode.DISCOVERY_ONLY
    with pytest.raises(ValueError, match="discovery-only"):
        BrokerMode.parse("auto")


# --- TXT --------------------------------------------------------------------


def test_decode_txt():
    assert decode_txt({b"Broker": b"h.local", b"flag": None, "k": "v", b"bad": b"\xff"}) == {
        "broker": "h.local",
        "flag": "",
        "k": "v",
        "bad": "�",
    }


def test_parse_ebus_txt():
    parsed = parse_ebus_txt(
        {
            b"txtvers": b"1",
            b"ebus_version": b"0.9",
            b"roles": b"device, broker-host",
            b"device_id": b"dev-1,dev-2",
            b"auth_methods": b"passphrase,mtls",
            b"name": b"Example",
        }
    )
    assert parsed.roles == ("device", "broker-host")
    assert parsed.device_ids == ("dev-1", "dev-2")
    assert parsed.auth_methods == ("passphrase", "mtls")
    assert parsed.is_broker_host
    assert parsed.missing == ()
    assert parsed.get("NAME") == "Example"


def test_parse_ebus_txt_reports_missing():
    parsed = parse_ebus_txt({"txtvers": "1", "roles": "controller"})
    assert parsed.missing == ("ebus_version", "device_id")
    assert parsed.device_ids == ()
    assert not parsed.is_broker_host


def test_check_txt_rejects_unencodable():
    with pytest.raises(ValueError, match="at most 255"):
        check_txt("_x._tcp", {"k": "v" * 254})
    with pytest.raises(ValueError, match="invalid TXT key"):
        check_txt("_x._tcp", {"a=b": "v"})
    with pytest.raises(ValueError, match="invalid TXT key"):
        check_txt("_x._tcp", {"": "v"})


def test_check_txt_warns_near_limits():
    with pytest.warns(TxtSizeWarning, match="near the 255-byte"):
        check_txt("_x._tcp", {"k": "v" * 210})
    big = {f"k{i}": "v" * 150 for i in range(10)}
    assert txt_wire_size(big) > 1300
    with pytest.warns(TxtSizeWarning, match="keep it under 1300"):
        check_txt("_x._tcp", big)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        check_txt("_x._tcp", {"k": "v"})


def test_txt_wire_size():
    assert txt_wire_size({"a": "b", "cd": ""}) == (1 + 3) + (1 + 3)


# --- Identity ---------------------------------------------------------------


def test_identity_ebus_txt_required_and_recommended():
    ident = _identity(
        device_ids=["dev-1", "dev-2"],
        roles="device,controller",
        device_type="example-type",
        name="Example Device",
        fw_version="1.2.3",
        register="/api/v1/auth/register",
        auth_methods=["passphrase", "preconfigured"],
        extra_ebus_txt={"homie_version": "5", "txtvers": "ignored"},
    )
    assert ident.device_id == "dev-1,dev-2"
    assert ident.ebus_txt() == {
        "txtvers": "1",
        "ebus_version": EBUS_SPEC_VERSION,
        "roles": "device,controller",
        "device_id": "dev-1,dev-2",
        "device_type": "example-type",
        "name": "Example Device",
        "manufacturer": "Example",
        "model": "EX-1",
        "fw_version": "1.2.3",
        "register": "/api/v1/auth/register",
        "auth_methods": "passphrase,preconfigured",
        "homie_version": "5",
    }
    assert parse_ebus_txt(ident.ebus_txt()).missing == ()


def test_identity_device_info_txt():
    ident = _identity(fw_version="1.0", mac="a0b1c2d3e4f5", hw_version="")
    assert ident.device_info_txt() == {
        "txtvers": "1",
        "manufacturer": "Example",
        "model": "EX-1",
        "serial_number": "sn-0001",
        "fw_version": "1.0",
        "mac": "a0b1c2d3e4f5",
    }


@pytest.mark.parametrize(
    "kw,msg",
    [
        ({"device_ids": []}, "at least one device id"),
        ({"device_ids": ["a", ""]}, "invalid device id"),
        ({"device_ids": ["a,b"]}, "invalid device id"),
        ({"roles": []}, "at least one role"),
        ({"manufacturer": ""}, "manufacturer"),
        ({"model": ""}, "model"),
        ({"serial_number": ""}, "serial_number"),
        ({"ebus_version": ""}, "ebus_version"),
    ],
)
def test_identity_validation(kw, msg):
    with pytest.raises(ValueError, match=msg):
        _identity(**kw)


def test_identity_unknown_role_logs(caplog):
    with caplog.at_level(logging.WARNING):
        _identity(roles=["device", "observer"])
    assert "unknownEbusRole" in caplog.text


def test_identity_many_device_ids_warn_then_fail():
    ids = [f"device-{i:04d}" for i in range(18)]  # 18*12 - 1 = 215 bytes of device_id
    with pytest.warns(TxtSizeWarning, match="device_id"):
        _identity(device_ids=ids)
    with pytest.raises(ValueError, match="at most 255"):
        _identity(device_ids=[f"device-{i:04d}" for i in range(25)])


def test_http_service_txt():
    ident = _identity(device_type="example-type")
    http = HttpService(port=8080, openapi="/api/v1/openapi.yml")
    assert http.service_type == "_http._tcp"
    assert HttpService(port=443, tls=True).service_type == "_https._tcp"
    assert http.txt(ident) == {
        "txtvers": "1",
        "path": "/api/v1",
        "version": "1.0",
        "device_id": "dev-1",
        "device_type": "example-type",
        "openapi": "/api/v1/openapi.yml",
    }


# --- BrokerService ----------------------------------------------------------


def test_broker_service_txt_per_type():
    ident = _identity(device_ids=["dev-1", "dev-2"], roles=["broker-host"])
    server = "host-1.local."
    assert BrokerService().txt(ident, server) == {
        "txtvers": "1",
        "protocol": "mqtt-v5",
        "broker": "host-1.local",
        "device_id": "dev-1,dev-2",
    }
    for stype in (MQTT_WSS_SERVICE, MQTT_WS_SERVICE):
        assert BrokerService(stype).txt(ident, server) == {
            "txtvers": "1",
            "protocol": "mqtt-v5",
            "path": "/mqtt",
            "subprotocol": "mqtt",
        }
    assert BrokerService(MQTT_SERVICE, protocol="mqtt-v3.1.1").txt(ident, server) == {
        "txtvers": "1",
        "protocol": "mqtt-v3.1.1",
    }


def test_broker_service_defaults_and_overrides():
    assert [BrokerService(t).port for t in BROKER_PREFERENCE] == [8883, 9002, 9001, 1883]
    svc = BrokerService(port=18883, broker="broker.example.local.", extra_txt={"x": "1"})
    txt = svc.txt(_identity(), "host-1.local.")
    assert txt["broker"] == "broker.example.local"
    assert txt["x"] == "1"
    # extra_txt never replaces a key the specification defines
    assert (
        BrokerService(MQTT_SERVICE, extra_txt={"protocol": "x"}).txt(_identity(), "h.local.")[
            "protocol"
        ]
        == "mqtt-v5"
    )


def test_broker_service_rejects_unknown_type_and_logs_unknown_protocol(caplog):
    with pytest.raises(ValueError, match="unknown broker service type"):
        BrokerService("_http._tcp")
    with caplog.at_level(logging.WARNING):
        BrokerService(protocol="mqtt-v4")
    assert "reason=unknownMqttProtocol,protocol=mqtt-v4" in caplog.text


def test_broker_service_txt_too_long():
    with pytest.raises(ValueError, match="at most 255"):
        BrokerService(extra_txt={"x": "y" * 300}).txt(_identity(), "h.local.")


@pytest.mark.parametrize(
    "svc,host",
    [
        (BrokerService(), "host-1.local"),
        (BrokerService(broker="broker.example.local"), "broker.example.local"),
        (BrokerService(MQTT_SERVICE), "host-1.local"),
        (BrokerService(MQTT_WS_SERVICE, port=8080), "host-1.local"),
        (BrokerService(MQTT_SERVICE, extra_txt={"broker": "b.local."}), "b.local"),
    ],
)
def test_broker_service_endpoint_matches_what_a_client_resolves(svc, host):
    ident = _identity(roles=["broker-host"])
    server = "host-1.local."
    advertised = BrokerEndpoint.from_instance(
        _inst(svc.service_type, server=server, port=svc.port, txt=svc.txt(ident, server))
    )
    ep = svc.endpoint(server, ident)
    assert ep.host == advertised.host == host
    assert (ep.service_type, ep.port, ep.txt) == (
        advertised.service_type,
        advertised.port,
        advertised.txt,
    )
    assert ep.server == advertised.server == "host-1.local"
    assert svc.endpoint(server).txt == {}


# --- BrokerEndpoint ---------------------------------------------------------


def test_endpoint_host_from_txt_broker():
    ep = BrokerEndpoint.from_instance(
        _inst(SECURE_MQTT_SERVICE, txt={"broker": "broker-1.example.local."})
    )
    assert ep.host == "broker-1.example.local"
    assert ep.server == "broker-1.local"
    assert ep.port == 8883
    assert ep.use_tls and ep.is_tcp
    assert ep.url == "mqtts://broker-1.example.local:8883"


def test_endpoint_host_falls_back_to_srv_target():
    ep = BrokerEndpoint.from_instance(_inst(MQTT_SERVICE, port=1884))
    assert ep.host == "broker-1.local"
    assert ep.port == 1884
    assert not ep.use_tls


@pytest.mark.parametrize(
    "service_type,port,tls",
    [
        (SECURE_MQTT_SERVICE, 8883, True),
        (MQTT_SERVICE, 1883, False),
        (MQTT_WSS_SERVICE, 9002, True),
        (MQTT_WS_SERVICE, 9001, False),
    ],
)
def test_endpoint_default_port_and_tls(service_type, port, tls):
    ep = BrokerEndpoint.from_instance(_inst(service_type, port=0))
    assert ep.port == port
    assert ep.use_tls is tls
    assert ep.is_tcp is (service_type in TCP_BROKER_TYPES)


def test_endpoint_mqtt_cfg_is_a_copy_with_three_keys_replaced():
    base = {
        "host": "old.example",
        "port": 1,
        "use_tls": False,
        "tls_insecure": False,
        "tls_ca_cert": "/path/ca.pem",
        "authentication": {"type": "USER_PASS", "username": "u", "password": "p"},
    }
    ep = BrokerEndpoint(service_type=SECURE_MQTT_SERVICE, host="broker-1.local", port=8883)
    cfg = ep.mqtt_cfg(base)
    assert cfg == {
        **base,
        "host": "broker-1.local",
        "port": 8883,
        "use_tls": True,
    }
    assert base["host"] == "old.example"
    cfg["authentication"]["password"] = "changed"
    assert base["authentication"]["password"] == "p"
    assert ep.mqtt_cfg() == {"host": "broker-1.local", "port": 8883, "use_tls": True}


def test_endpoint_mqtt_cfg_warns_when_tls_is_turned_off(caplog):
    plain = BrokerEndpoint(service_type="_mqtt._tcp", host="broker-2.local", port=1883)
    with caplog.at_level(logging.WARNING):
        plain.mqtt_cfg({"host": "broker-1.local"})
        assert "tlsDisabled" not in caplog.text
        assert plain.mqtt_cfg({"use_tls": True})["use_tls"] is False
    assert "reason=tlsDisabledForPlainBroker,url=mqtt://broker-2.local:1883" in caplog.text


@pytest.mark.parametrize(
    "url,stype,host,port",
    [
        ("mqtts://broker-1.local:8884", SECURE_MQTT_SERVICE, "broker-1.local", 8884),
        ("mqtts://broker-1.local", SECURE_MQTT_SERVICE, "broker-1.local", 8883),
        ("mqtt://192.0.2.7", MQTT_SERVICE, "192.0.2.7", 1883),
        ("MQTT://[2001:db8::7]:1885", MQTT_SERVICE, "2001:db8::7", 1885),
    ],
)
def test_endpoint_from_url(url, stype, host, port):
    ep = BrokerEndpoint.from_url(url)
    assert (ep.service_type, ep.host, ep.port) == (stype, host, port)


def test_endpoint_from_mqtt_cfg():
    ep = BrokerEndpoint.from_mqtt_cfg({"host": "b.local", "use_tls": True})
    assert (ep.service_type, ep.host, ep.port, ep.use_tls) == (
        SECURE_MQTT_SERVICE,
        "b.local",
        8883,
        True,
    )
    ep = BrokerEndpoint.from_mqtt_cfg({"host": "192.0.2.8", "port": 1999})
    assert (ep.service_type, ep.port, ep.use_tls) == (MQTT_SERVICE, 1999, False)
    with pytest.raises(ValueError, match="no host"):
        BrokerEndpoint.from_mqtt_cfg({"port": 1883})


def test_endpoint_url_brackets_ipv6():
    assert BrokerEndpoint.from_url("mqtt://[2001:db8::7]").url == "mqtt://[2001:db8::7]:1883"


@pytest.mark.parametrize("url", ["ws://h:9001", "wss://h", "http://h", "h:1883", "mqtt://"])
def test_endpoint_from_url_rejects(url):
    with pytest.raises(ValueError):
        BrokerEndpoint.from_url(url)


# --- rank / select ----------------------------------------------------------


def _ep(stype, host, server=None, device_id=None, port=None):
    txt = {"device_id": device_id} if device_id else {}
    return BrokerEndpoint(
        service_type=stype,
        host=host,
        port=port or 1,
        txt=txt,
        server=server,
    )


def test_rank_dedupes_one_broker_under_several_types():
    plain = _ep(MQTT_SERVICE, "b1.local", server="b1.local")
    secure = _ep(SECURE_MQTT_SERVICE, "b1.local", server="b1.local.")
    ranked = rank_brokers([plain, secure])
    assert ranked == [secure]


def test_rank_dedupes_by_device_id_and_server():
    secure = _ep(SECURE_MQTT_SERVICE, "b1.example.net", server="b1.local", device_id="d1")
    plain = _ep(MQTT_SERVICE, "b1.local")  # no TXT broker: host is the SRV target
    other = _ep(MQTT_SERVICE, "b2.local", device_id="d1")  # same device id
    assert rank_brokers([plain, other, secure]) == [secure]


def test_rank_orders_distinct_brokers_by_preference_then_host():
    a = _ep(MQTT_SERVICE, "a.local")
    b = _ep(SECURE_MQTT_SERVICE, "b.local")
    c = _ep(SECURE_MQTT_SERVICE, "C.local")
    ws = _ep(MQTT_WS_SERVICE, "w.local")
    assert rank_brokers([a, ws, c, b]) == [b, c, ws, a]


def test_rank_accept_filters_before_dedupe():
    wss = _ep(MQTT_WSS_SERVICE, "b1.local")
    plain = _ep(MQTT_SERVICE, "b1.local")
    assert rank_brokers([wss, plain]) == [wss]
    assert rank_brokers([wss, plain], accept=TCP_BROKER_TYPES) == [plain]
    assert rank_brokers([_ep("_other._tcp", "x.local")]) == []


def test_select_configured_only_ignores_discovery():
    conf = BrokerEndpoint.from_url("mqtts://conf.local")
    found = [_ep(SECURE_MQTT_SERVICE, "b.local")]
    assert select_broker("configured-only", conf, found) is conf
    assert select_broker(BrokerMode.CONFIGURED_ONLY, None, found) is None


def test_select_discovery_only():
    conf = BrokerEndpoint.from_url("mqtts://conf.local")
    b = _ep(SECURE_MQTT_SERVICE, "b.local")
    assert select_broker("discovery-only", conf, [b]) is b
    assert select_broker("discovery-only", conf, []) is None
    assert select_broker(None, conf, [b]) is b


def test_select_discovery_with_fallback_never_replaces_configured(caplog):
    conf = BrokerEndpoint.from_url("mqtts://conf.local")
    b = _ep(SECURE_MQTT_SERVICE, "b.local")
    with caplog.at_level(logging.INFO, logger="ebus_service_discovery.ebus"):
        assert select_broker("discovery-with-fallback", conf, [b]) is conf
    assert "brokerNotChosen,url=mqtts://b.local:1,chosen=mqtts://conf.local:8883" in caplog.text
    assert select_broker("discovery-with-fallback", conf, []) is conf


def test_select_discovery_with_fallback_takes_discovered_port_of_configured():
    conf = BrokerEndpoint.from_url("mqtt://conf.local")
    other = _ep(SECURE_MQTT_SERVICE, "a.local")
    match = _ep(SECURE_MQTT_SERVICE, "conf.example.net", server="Conf.local.", port=18883)
    assert select_broker("discovery-with-fallback", conf, [other, match]) is match


def test_select_discovery_with_fallback_allow_unmatched():
    conf = BrokerEndpoint.from_url("mqtts://conf.local")
    b1 = _ep(SECURE_MQTT_SERVICE, "b1.local")
    b2 = _ep(SECURE_MQTT_SERVICE, "conf.local")
    mode = "discovery-with-fallback"
    assert select_broker(mode, conf, [b1], allow_unmatched=True) is b1
    assert select_broker(mode, conf, [b1, b2], allow_unmatched=True) is b2
    assert select_broker(mode, conf, [], allow_unmatched=True) is conf


def test_select_discovery_with_fallback_without_configured_takes_first():
    b1 = _ep(SECURE_MQTT_SERVICE, "b1.local")
    b2 = _ep(SECURE_MQTT_SERVICE, "b2.local")
    assert select_broker("discovery-with-fallback", None, [b1, b2]) is b1
    assert select_broker("discovery-with-fallback", None, []) is None


@pytest.mark.parametrize(
    "url,advertised",
    [
        ("mqtt://192.0.2.20", "192.0.2.20"),
        ("mqtt://[2001:db8::20]", "2001:db8::20"),
        ("mqtt://[fe80::20%25eth0]", "fe80::20%eth0"),
    ],
)
def test_match_configured_by_address_keeps_configured_host(url, advertised):
    conf = BrokerEndpoint.from_url(url)
    other = BrokerEndpoint(
        SECURE_MQTT_SERVICE, "a.local", 8883, addresses=(Address.parse("192.0.2.10"),)
    )
    b = BrokerEndpoint(
        SECURE_MQTT_SERVICE,
        "b.local",
        18883,
        addresses=(Address.parse("192.0.2.99"), Address.parse(advertised)),
    )
    chosen = select_broker("discovery-with-fallback", conf, [other, b])
    assert (chosen.host, chosen.port, chosen.use_tls) == (conf.host, 18883, True)
    assert chosen.addresses == b.addresses
    assert match_configured(conf, [other]) is None


def test_match_configured_by_name_ignores_addresses():
    conf = BrokerEndpoint.from_url("mqtt://b.local")
    other = BrokerEndpoint(MQTT_SERVICE, "a.local", 1883, addresses=(Address.parse("192.0.2.1"),))
    assert match_configured(conf, [other]) is None


def test_select_among_several_prefers_configured_host_and_logs(caplog):
    conf = BrokerEndpoint.from_url("mqtts://b2.local")
    b1 = _ep(SECURE_MQTT_SERVICE, "b1.local")
    b2 = _ep(SECURE_MQTT_SERVICE, "b2.example.net", server="B2.local.")
    with caplog.at_level(logging.INFO, logger="ebus_service_discovery.ebus"):
        assert select_broker("discovery-with-fallback", conf, [b1, b2]) is b2
        assert select_broker("discovery-only", conf, [b1, b2]) is b1
    assert caplog.text.count("brokerChosenAmongSeveral") == 2


def test_select_single_broker_does_not_log(caplog):
    with caplog.at_level(logging.INFO, logger="ebus_service_discovery.ebus"):
        select_broker("discovery-only", None, [_ep(SECURE_MQTT_SERVICE, "b.local")])
    assert "brokerChosenAmongSeveral" not in caplog.text


# --- retry ------------------------------------------------------------------


def test_retry_schedule_default():
    s = RetrySchedule(max_attempts=6)
    assert list(s.delays()) == [0.0, 3.0, 3.0, 30.0, 30.0, 30.0]
    assert s.delay(100) == 30.0


def test_retry_schedule_unbounded_and_custom():
    it = RetrySchedule().delays()
    assert [next(it) for _ in range(5)] == [0.0, 3.0, 3.0, 30.0, 30.0]
    assert list(RetrySchedule(1, 0.5, 2.0, max_attempts=3).delays()) == [0.0, 2.0, 2.0]


# --- import isolation -------------------------------------------------------


def test_package_import_loads_neither_transport():
    code = (
        "import sys\n"
        "import ebus_service_discovery\n"
        "import ebus_service_discovery.ebus, ebus_service_discovery.instance\n"
        "import ebus_service_discovery.cli\n"
        "bad = [m for m in sys.modules if m.split('.')[0] in ('zeroconf', 'ebus_mqtt_client')]\n"
        "print(','.join(bad))\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    ).stdout.strip()
    assert out == ""

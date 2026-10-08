"""Live mDNS tests on the local network. Run with EBUS_SD_LIVE=1.

They advertise short-lived services with unique names under this host's
existing .local name and find them again with a separate Zeroconf instance.
"""

import asyncio
import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("EBUS_SD_LIVE") != "1", reason="live mDNS test; set EBUS_SD_LIVE=1"
)

zeroconf = pytest.importorskip("zeroconf")

from zeroconf import ServiceInfo, Zeroconf  # noqa: E402
from zeroconf.asyncio import AsyncZeroconf  # noqa: E402

from ebus_service_discovery import mdns, mdns_async  # noqa: E402
from ebus_service_discovery._mdns_core import default_ip_version  # noqa: E402
from ebus_service_discovery.ebus import (  # noqa: E402
    HttpService,
    Identity,
    RetrySchedule,
    parse_ebus_txt,
)
from ebus_service_discovery.instance import strip_dot  # noqa: E402

BROWSE = 4.0


def _zc() -> Zeroconf:
    return mdns.new_zeroconf()


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _identity(device_id: str) -> Identity:
    return Identity(
        device_ids=[device_id, f"{device_id}-b"],
        roles=["controller"],
        manufacturer="Example",
        model="EX-1",
        serial_number=device_id,
        fw_version="0.0.1",
    )


def _find(instances, name):
    return [i for i in instances if i.instance_name == name]


def test_advertise_then_browse():
    name = _unique("sd-live")
    with mdns.Advertiser(_identity(name), http=HttpService(port=8080), instance_name=name) as adv:
        assert adv.instance_name == name
        zc = _zc()
        try:
            ebus = _find(mdns.browse("_ebus._tcp", BROWSE, zc=zc), name)
            info = _find(mdns.browse("_device-info._tcp", BROWSE, zc=zc), name)
            http = _find(mdns.browse("_http._tcp", BROWSE, zc=zc), name)
        finally:
            zc.close()
    assert len(ebus) == 1 and len(info) == 1 and len(http) == 1
    inst = ebus[0]
    assert inst.server == strip_dot(adv.server)
    assert inst.port == 8080
    assert inst.addresses, "the OS responder answers the host's addresses"
    parsed = parse_ebus_txt(inst.txt)
    assert parsed.missing == ()
    assert parsed.device_ids == (name, f"{name}-b")
    assert info[0].txt["serial_number"] == name
    assert http[0].txt["path"] == "/api/v1"


def test_second_advertiser_with_same_name_is_renamed():
    name = _unique("sd-live")
    zc2 = _zc()
    try:
        with (
            mdns.Advertiser(_identity(name), instance_name=name) as first,
            mdns.Advertiser(_identity(name + "x"), instance_name=name, zc=zc2) as second,
        ):
            assert first.instance_name == name
            assert second.instance_name == f"{name}-2"
    finally:
        zc2.close()


def _broker_info(name: str, server: str, broker_host: str) -> ServiceInfo:
    return ServiceInfo(
        "_secure-mqtt._tcp.local.",
        f"{name}._secure-mqtt._tcp.local.",
        port=18883,
        properties={
            "txtvers": "1",
            "protocol": "mqtt-v5",
            "broker": broker_host,
            "device_id": name,
        },
        server=server,
    )


def test_find_fake_secure_mqtt_broker():
    name = _unique("sd-live-broker")
    zc = _zc()
    try:
        server = mdns.os_hostname(zc)
        assert server, "no OS mDNS responder answered"
        broker_host = strip_dot(server)
        info = _broker_info(name, server, broker_host)
        zc.register_service(info)
        try:
            # Other brokers may be on the network: the configured URL names
            # this one, and discovery-with-fallback prefers a discovered broker
            # whose host matches it.
            base = {"host": "unused.example", "tls_ca_cert": "/path/ca.pem"}
            ep = mdns.find_broker(
                "discovery-with-fallback",
                f"mqtts://{broker_host}:18883",
                base_cfg=base,
                schedule=RetrySchedule(max_attempts=3),
            )
        finally:
            zc.unregister_service(info)
    finally:
        zc.close()
    assert ep is not None
    assert ep.instance_name == name, "the discovered broker, not the configured fallback"
    assert (ep.host, ep.port, ep.use_tls) == (broker_host, 18883, True)
    cfg = ep.mqtt_cfg(base)
    assert cfg["tls_ca_cert"] == "/path/ca.pem" and cfg["host"] == broker_host


def test_async_advertise_browse_and_find_broker():
    name = _unique("sd-live-async")

    async def run():
        aiozc = AsyncZeroconf(ip_version=default_ip_version())
        try:
            server = await mdns_async.os_hostname(aiozc)
            info = _broker_info(name, server, strip_dot(server))
            await aiozc.async_register_service(info)
            async with mdns_async.Advertiser(_identity(name), aiozc, instance_name=name):
                found = _find(await mdns_async.browse(aiozc, "_ebus._tcp", BROWSE), name)
                ep = await mdns_async.find_broker(
                    aiozc,
                    "discovery-with-fallback",
                    f"mqtts://{strip_dot(server)}:18883",
                    schedule=RetrySchedule(max_attempts=3),
                )
            await aiozc.async_unregister_service(info)
            return found, ep
        finally:
            await aiozc.async_close()

    found, ep = asyncio.run(run())
    assert len(found) == 1
    assert ep is not None and ep.instance_name == name

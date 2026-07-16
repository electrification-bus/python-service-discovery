"""Command-line tools for inspecting and resolving a v2 service-discovery bus.

Subcommands: ``dump`` (snapshot the retained bus), ``watch`` (live add/update/
remove), ``resolve`` (find a reachable endpoint for a service), ``validate``
(check records against the bundled JSON Schema). The MQTT client is imported
lazily inside the commands that need a broker, so the pure formatters remain
importable and testable without one.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone

from ebus_service_discovery_client.record import DEFAULT_TOPIC_BASE, Record
from ebus_service_discovery_client.resolver import Resolution, ServiceResolver
from ebus_service_discovery_client.schema import validate_record

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 1883
DEFAULT_WINDOW = 2.0
_CLIENT_ID = "service-discovery-cli"


# --- pure formatters (no I/O) ---------------------------------------------


def _format_age(seconds: float | None) -> str:
    if seconds is None:
        return "?"
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        return f"{s // 3600}h"
    return f"{s // 86400}d"


def render_tree(records: list[Record], now: datetime | None = None) -> str:
    """A readable service_type -> interface -> instance -> addresses tree."""
    now = now or datetime.now(timezone.utc)
    by_type: dict[str, dict[str, list[Record]]] = {}
    for r in records:
        by_type.setdefault(r.service_type, {}).setdefault(r.interface, []).append(r)
    lines: list[str] = []
    for stype in sorted(by_type):
        lines.append(stype)
        for iface in sorted(by_type[stype]):
            lines.append(f"  {iface}")
            for r in sorted(by_type[stype][iface], key=lambda x: x.instance_name):
                stale = " STALE" if r.is_stale(now) else ""
                lines.append(
                    f"    {r.instance_name}  ({r.hostname}:{r.port})  "
                    f"age {_format_age(r.age_seconds(now))}  [{r.state.value}{stale}]"
                )
                for a in r.addresses:
                    lines.append(f"      {a.address}  ({a.family.value}/{a.scope.value})")
    return "\n".join(lines) if lines else "(no records)"


def render_resolution(res: Resolution | None) -> str:
    if res is None:
        return "unresolved (no reachable address)"
    return (
        f"{res.host}:{res.port}  via {res.interface}  "
        f"({res.address.family.value}/{res.address.scope.value})  "
        f"instance={res.record.instance_name}"
    )


def _match_from_arg(spec: str | None):
    """Turn a `key=value` TXT filter into a Record predicate."""
    if not spec:
        return None
    key, _, value = spec.partition("=")

    def _match(record: Record) -> bool:
        return record.txt.get(key) == value

    return _match


# --- MQTT-backed commands (lazy import) -----------------------------------


def _collect(host, port, patterns, window):
    """Connect, subscribe, collect the latest Record per topic for `window` s."""
    from ebus_mqtt_client import MqttClient

    records: dict[str, Record] = {}

    def handler(topic, payload):
        if not payload or not bytes(payload).strip():
            records.pop(topic, None)
            return
        try:
            rec = Record.from_json(bytes(payload))
        except Exception:
            return
        if rec.is_removed:
            records.pop(topic, None)
        else:
            records[topic] = rec

    mqtt = MqttClient(_CLIENT_ID, host, port)
    for pat in patterns:
        mqtt.subscribe(pat, param=handler)
    mqtt.start()
    time.sleep(window)
    mqtt.stop()
    return list(records.values())


def _service_pattern(base, service_type):
    return f"{base}/{service_type}/+/+" if service_type else f"{base}/#"


def cmd_dump(args) -> int:
    records = _collect(
        args.host, args.port, [_service_pattern(args.base, args.service_type)], args.window
    )
    if args.interface:
        records = [r for r in records if r.interface == args.interface]
    print(render_tree(records))
    return 0


def cmd_watch(args) -> int:
    from ebus_mqtt_client import MqttClient

    def handler(topic, payload):
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        if not payload or not bytes(payload).strip():
            print(f"{ts} REMOVED  {topic}")
            return
        try:
            rec = Record.from_json(bytes(payload))
        except Exception:
            print(f"{ts} BADMSG   {topic}")
            return
        verb = "REMOVED" if rec.is_removed else "ACTIVE"
        addrs = ",".join(a.address for a in rec.addresses)
        print(f"{ts} {verb:8} {rec.service_type}/{rec.interface}/{rec.instance_name}  [{addrs}]")

    mqtt = MqttClient(_CLIENT_ID, args.host, args.port)
    mqtt.subscribe(_service_pattern(args.base, args.service_type), param=handler)
    mqtt.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        mqtt.stop()
    return 0


def cmd_resolve(args) -> int:
    from ebus_mqtt_client import MqttClient

    mqtt = MqttClient(_CLIENT_ID, args.host, args.port)
    resolver = ServiceResolver(mqtt, base=args.base)
    resolver.watch(args.service_type)
    mqtt.start()
    time.sleep(args.window)
    res = resolver.resolve(args.service_type, _match_from_arg(args.match), port=args.probe_port)
    mqtt.stop()
    print(render_resolution(res))
    return 0 if res is not None else 1


def cmd_validate(args) -> int:
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            data = json.load(fh)
        records = data if isinstance(data, list) else [data]
    else:
        from ebus_mqtt_client import MqttClient

        records = {}

        def handler(topic, payload):
            if payload and bytes(payload).strip():
                try:
                    records[topic] = json.loads(bytes(payload))
                except json.JSONDecodeError:
                    records[topic] = {"__unparseable__": True}

        mqtt = MqttClient(_CLIENT_ID, args.host, args.port)
        mqtt.subscribe(f"{args.base}/#", param=handler)
        mqtt.start()
        time.sleep(args.window)
        mqtt.stop()
        records = list(records.values())

    errors = 0
    for i, rec in enumerate(records):
        try:
            validate_record(rec)
            print(f"[{i}] valid")
        except Exception as exc:
            errors += 1
            first = str(exc).splitlines()[0]
            print(f"[{i}] INVALID: {first}")
    print(f"{len(records)} record(s), {errors} invalid")
    return 1 if errors else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="service-discovery",
        description="Inspect and resolve a v2 mDNS/DNS-SD service-discovery bus over MQTT.",
    )
    p.add_argument(
        "--host", default=DEFAULT_HOST, help=f"MQTT broker host (default {DEFAULT_HOST})"
    )
    p.add_argument(
        "--port", type=int, default=DEFAULT_PORT, help=f"MQTT broker port (default {DEFAULT_PORT})"
    )
    p.add_argument("--base", default=DEFAULT_TOPIC_BASE, help="discovery topic base")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("dump", help="snapshot the retained bus as a tree")
    d.add_argument("service_type", nargs="?", help="limit to one service type")
    d.add_argument("--interface", help="limit to one interface")
    d.add_argument("--window", type=float, default=DEFAULT_WINDOW)
    d.set_defaults(func=cmd_dump)

    w = sub.add_parser("watch", help="live add/update/remove stream")
    w.add_argument("service_type", nargs="?")
    w.set_defaults(func=cmd_watch)

    r = sub.add_parser("resolve", help="resolve a reachable endpoint for a service")
    r.add_argument("service_type")
    r.add_argument("--match", help="TXT filter key=value, e.g. serialnum=123")
    r.add_argument(
        "--probe-port",
        type=int,
        dest="probe_port",
        help="probe/return this port instead of the advertised one",
    )
    r.add_argument("--window", type=float, default=DEFAULT_WINDOW)
    r.set_defaults(func=cmd_resolve)

    v = sub.add_parser("validate", help="validate record(s) against the JSON Schema")
    v.add_argument("--file", help="a JSON file with a record or a list of records")
    v.add_argument("--window", type=float, default=DEFAULT_WINDOW)
    v.set_defaults(func=cmd_validate)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

# ebus-service-discovery-client

[![PyPI version](https://img.shields.io/pypi/v/ebus-service-discovery-client.svg)](https://pypi.org/project/ebus-service-discovery-client/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

Client and shared model for an mDNS/DNS-SD **service-discovery bus over MQTT**: a
discovery service browses the local network and publishes each advertisement as
a retained MQTT record; consumers subscribe, keep a fresh view (honoring
freshness and tombstones), and resolve a reachable address per interface.

This library is the **consumer side plus the shared contract**. The record model
and its [JSON Schema](src/ebus_service_discovery_client/record.schema.json) are
the wire contract; a publisher and any number of clients share them.

> **Status: alpha.** Shipped today: the `Record`/`Address` model, the draft
> 2020-12 JSON Schema, and derived address classification. The MQTT `resolver`
> (subscribe + reachability probe with IPv4/IPv6 fallback) and the `service-discovery`
> debug CLI are next.

## Why

Advertisements are messy in ways every consumer otherwise re-solves alone:

- An advertised IPv4 can be a self-assigned APIPA (`169.254.x`) address that is
  unreachable; the peer may be reachable only over IPv6.
- The same instance can be heard on several interfaces with different addresses;
  reachability is per-interface (`SO_BINDTODEVICE`).
- Records go stale unless something expires them.

So the contract is deliberately **honest and raw** — it carries the current
addresses per interface and an explicit freshness/tombstone state — and the
**classification lives here, in code**, computed from the address value:

```python
from ebus_service_discovery_client import Address

a = Address.parse("169.254.1.1")
a.scope        # AddressScope.LINK_LOCAL
a.is_apipa     # True  -> DHCPv4 failed; do not prefer this
a.preference   # sort key: routable addresses before link-local/APIPA
```

## Install

```bash
pip install ebus-service-discovery-client
# optional on-device/CI JSON Schema validation:
pip install "ebus-service-discovery-client[validation]"
```

## Quick start

```python
from ebus_service_discovery_client import Record

# A record as published (retained) by a discovery service on
#   {base}/v2/{service_type}/{interface}/{percent_encoded_instance}
rec = Record.from_json(mqtt_payload)

if rec.is_removed:
    drop(rec)            # tombstone: the advertisement went away
else:
    print(rec.service_type, rec.instance_name, "on", rec.interface)
    for addr in rec.candidate_addresses():   # routable first, link-local/APIPA last
        print(addr.address, addr.family.value, addr.scope.value)
```

## The contract

- **Topic:** `{base}/v2/{service_type}/{interface}/{percent_encoded_instance}` — keyed
  by the DNS-SD service **instance** (percent-encoded so an arbitrary UTF-8 label
  is one safe segment), split per interface.
- **Payload:** the [record schema](src/ebus_service_discovery_client/record.schema.json)
  — raw `addresses` (never carried forward, IPv6-only allowed), `txt`, an explicit
  `state` (`active`/`removed`), and `first_seen`/`last_seen`/`ttl_seconds` freshness.
- Validate a payload dict with `validate_record(...)` (requires the `validation` extra).

## Releasing

The version lives in exactly one place: `__version__` in
`src/ebus_service_discovery_client/__init__.py`. `pyproject.toml` reads it
dynamically, the `setup.py` legacy shim reads it by regex, and the publish
workflow refuses to release a tag that disagrees with it. To cut a release:

1. Bump `__version__` in `src/ebus_service_discovery_client/__init__.py` (the only place).
2. Move the CHANGELOG's `[Unreleased]` entries under a new version heading.
3. Commit, then tag it `v`-prefixed to match: `git tag vX.Y.Z && git push --tags`.

Pushing a `v*` tag runs the publish workflow, which verifies the tag equals
`v$__version__`, builds the sdist and wheel, and publishes to PyPI via Trusted
Publishing (OIDC, no stored token).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for Discussions, Issues, and pull requests.
The library is intentionally vendor- and product-agnostic: it models generic
DNS-SD discovery, not any particular device.

## License

[MIT License](LICENSE) — Copyright (c) 2026 Clark Communications Corporation

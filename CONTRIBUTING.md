# Contributing to ebus-service-discovery-client

Thanks for your interest in contributing! `ebus-service-discovery-client` is the
consumer side plus the shared contract for an mDNS/DNS-SD service-discovery bus
carried over MQTT: a record model, its JSON Schema, and (as they land) a resolver
and a debug CLI. It is intentionally **vendor- and product-agnostic** — it models
generic DNS-SD discovery, not any particular device or integration.

## How to contribute

### Discussions

Use [Discussions](https://github.com/electrification-bus/python-service-discovery-client/discussions) for:

- Open-ended questions about the library's design, scope, or intent.
- Proposed changes to the wire contract (record schema, topic structure) — worth
  aligning before writing code, since the contract is shared by publishers and clients.
- Address-classification or reachability-policy questions (IPv4/IPv6 preference,
  new scope categories).
- Thinking out loud about a change before scoping it.

Discussions are a good place to align on direction before something becomes a
concrete change. Aligned outcomes often turn into one or more Issues or pull requests.

### Issues

Use [Issues](https://github.com/electrification-bus/python-service-discovery-client/issues) for actionable changes:

- Bug reports with reproduction steps.
- Concrete feature requests with a clear scope and a use case.
- Documentation gaps where a specific change is intended.
- Discussion outcomes that have alignment and a clear scope.

If you're not sure whether something is an Issue or a Discussion, start with a
Discussion — we can convert it later.

### Pull requests

Pull requests are welcome.

- For small fixes (typos, docstring tweaks, low-risk bug fixes with a test), open a PR directly.
- For substantive changes (new public API, changes to the record contract or
  topic structure, new dependencies, changes to address classification), open a
  Discussion or Issue first so we can align on scope.
- **Stay generic.** No device-, vendor-, or deployment-specific logic. If a
  feature only makes sense for one product or integration, it belongs in that
  consumer, not here. When in doubt, ask in a Discussion.
- **The wire contract is shared.** Changes to
  [`record.schema.json`](src/ebus_service_discovery_client/record.schema.json) or
  the topic layout affect every publisher and consumer. Prefer additive changes;
  a breaking change needs a version bump of the contract and a migration plan.
- **Tests are required.** The suite is offline and mock-based (`pytest tests/`).
  New behavior needs a test; bug fixes need a regression test.
- **Keep comments to a minimum.** Write self-explanatory code; reserve comments
  for non-obvious *why* (a hidden constraint or a specific quirk).
- **The version lives in one place.** Bump `__version__` in
  `src/ebus_service_discovery_client/__init__.py` only — `pyproject.toml` reads it
  dynamically and `setup.py` reads it by regex, so there is nothing else to keep
  in sync. (The `setup.py` shim exists so legacy `setuptools<61` — pinned in some
  embedded builds — can build a wheel with correct metadata; its docstring explains why.)
- One commit per logical change is fine; we don't require squash or any particular branch naming.

## Releases

Releases to PyPI are automated via the [`Publish to PyPI`](.github/workflows/publish.yml)
GitHub Actions workflow, which runs on `v*` git tags using PyPI
[trusted publishing](https://docs.pypi.org/trusted-publishers/) (OIDC, no stored
token). The workflow refuses to publish a tag whose version disagrees with
`__version__`. Once a maintainer tags `vX.Y.Z`, the workflow tests and publishes.

## Code of conduct

Be respectful and constructive. We appreciate everyone who takes the time to file
an issue, start a discussion, or send a pull request.

## Maintenance posture

`ebus-service-discovery-client` is an active alpha library. Updates and
maintenance, including responses to issues filed on GitHub, will take place on an
"as time and resources permit" basis. It is maintained alongside
[`ebus-sdk`](https://github.com/electrification-bus/python-sdk),
[`ebus-mqtt-client`](https://github.com/electrification-bus/ebus-mqtt-client), and
the [Electrification Bus specification](https://github.com/electrification-bus/specification).

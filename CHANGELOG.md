# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-16

### Added

- `Record` and `Address` model for the v2 mDNS/DNS-SD service-discovery contract.
  Addresses are carried raw on the wire; scope / APIPA / link-local classification
  and reachability-preference ordering are derived client-side from the address
  value so the taxonomy can evolve without a contract change.
- Bundled draft 2020-12 JSON Schema (`record.schema.json`), exposed via
  `load_schema()`, plus an optional `validate_record()` helper gated on the
  `validation` extra (`jsonschema`).
- Percent-encoded topic derivation, freshness helpers (`age_seconds`,
  `is_stale`), and active/removed (tombstone) record states.

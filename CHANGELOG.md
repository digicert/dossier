# Changelog

All notable changes to this project will be documented in this file.

## 1.0.1 - 2026-04-23

### Added
- Code signing end-entity certificate type (`CODE_SIGNING_EE`) is now recognised and reported correctly.

### Changed
- CCADB client updated to use the V5 All Certificate Records CSV endpoint and the updated Full CRL field name.

### Fixed
- Revocation entries with no `CRLReason` extension are now reported as `unspecified` (implicit reason code 0) instead of being silently omitted.

## 1.0.0 - 2025-10-14

Initial release

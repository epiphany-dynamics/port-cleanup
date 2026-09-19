# Changelog

All notable changes to Port Cleanup are documented here. Versions follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [SemVer](https://semver.org/).

## [1.6.0] - 2026-09-18

### Added

- Jev / TypeSafe integration: typed, finite-choice verdict/reason judgments per listening process, with confidence thresholds and a material-missing-fact output when evidence is incomplete.
- One-click bulk scan with PID-namespaced dossier batching; one paid request per explicit click.
- Public open-source release on GitHub with notarized Developer ID DMG distribution.

### Changed

- Keychain reads now fail cleanly (`kSecUseAuthenticationUIFail`) instead of interrupting a scan with an authentication prompt; connect once and reuse the stored key with no per-request password prompt.
- Release tooling signs with Developer ID (hardened runtime), verifies Gatekeeper assessment, and packages a DMG via `scripts/build.py --dmg`.

### Security

- Browser provenance inventory is read-only with strict timeouts, size caps, and no redirects or credential access.
- Stop path re-verifies process identity twice before signalling; protected rows override Jev.

## [1.5.0]

### Added

- Initial macOS 13+ SwiftUI app: one-click scan, per-process local evidence dossier, evidence-first inspector, protected-row shield, and graceful TCP-only stop with explicit human confirmation.

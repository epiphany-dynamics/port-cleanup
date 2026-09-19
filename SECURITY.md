# Security Policy

## Supported versions

Only the latest tagged release is supported. Security fixes land on `main` and appear in the next release.

## Reporting

Email security@epiphanydynamics.ai with a description, affected version, and reproduction steps if available. Please do not open a public issue for an exploitable problem.

## Security model

- **Jev calls are explicit and paid.** Every TypeSafe API request is initiated by a user click. There is no background polling, retry, or automatic trigger. The TypeSafe key lives only in the local macOS Keychain and is never committed to this repository.
- **No secrets in source.** No API keys, tokens, credentials, or internal identifiers are tracked in this repo. Do not paste keys into issues, PRs, or logs.
- **No automatic process termination.** The app never kills a process automatically. Each stop requires selecting a row, pressing the stop button, and confirming the exact list. Before signalling, the app re-verifies UID, executable path, process start identity, working directory, shield status, and exact listening endpoints — twice.
- **Strict argument allowlist.** Startup arguments are reduced to a fixed safe subset before display or transmission. Raw command lines, environment values, full paths, and secrets are never shown or sent to AI.
- **Local-only history.** Cleanup history is stored only on this Mac.
- **Read-only browser inventory.** Page provenance uses read-only `/json/list` against a verified Chrome/Chromium headless process; no navigation or JavaScript evaluation is performed.

## Distribution

Releases are signed with a Developer ID certificate and notarized by Apple. Download DMGs from GitHub Releases only. Verify the SHA-256 printed in the release notes against your download.

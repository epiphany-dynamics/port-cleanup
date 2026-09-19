# Contributing to Port Cleanup

Thanks for helping improve Port Cleanup. Keep changes minimal, focused, and consistent with the existing style.

## Ground rules

- **Jev calls are user-triggered and paid.** Never add a background Jev request, retry loop, polling, or automatic trigger. Every TypeSafe API call must be initiated by an explicit user click. If you need more Jev context for a feature, discuss it in your issue/PR description first.
- **Secrets never go in source.** No API keys, tokens, credentials, or internal hostnames anywhere in the repo. Jev credentials live in the local macOS Keychain only.
- **No automatic process termination.** Never add force-kill, restart-manager override, automatic selection, or scheduled cleanup. The stop button plus explicit confirm is the only trigger, and every stop re-verifies process identity first.

## Development

```bash
swift run PortCoreTests
python3 scripts/build.py --ad-hoc --destination "$HOME/Desktop/Port Cleanup.app"
```

The app targets macOS 13+ and uses SwiftUI. Verify the behavior you changed with the built app or the read-only tools (`--scan`, `--inspect-port PORT`) before opening a PR.

## Pull requests

1. Open a short PR describing the change and what you verified.
2. Keep PRs scoped to one concern; do not refactor unrelated code.
3. Do not add new dependencies without discussion in the PR description first.
4. Do not add CI/CD configuration files without maintainer approval.

PRs are reviewed for correctness, safety-model consistency, and privacy impact. Changes that widen what is sent to Jev or loosen the confirmation gate get extra scrutiny.

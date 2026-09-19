# Port Cleanup

**A Jev-powered native macOS utility for evidence-backed, human-confirmed cleanup of stale listening ports.**

Port Cleanup tells you which listening ports are safe to stop — and which are not — before anything is touched. Every TCP listener gets a typed recommendation from Jev, the evidence behind it, and an explicit decision that only you can make. No process is ever stopped automatically.

> A product screenshot and short demo will be added in a later media update. Nothing visual is included in this release yet.

## Why Jev matters

The hard part of port cleanup is not listing ports. It is deciding, per process, whether stopping it is safe — which usually requires understanding what that process actually is: a dev server you started an hour ago, a browser harness from a closed session, or something your system genuinely depends on.

**Jev** is the judgment engine behind Port Cleanup. It is a System One model from **TypeSafe** that turns each process's locally collected dossier into a typed judgment — a finite verdict/reason pair plus confidence and the single most material missing fact when the evidence is incomplete. Instead of asking a general-purpose model to freeform an answer, Port Cleanup asks Jev one finite-choice question per process: is this safe to stop, keep, or your decision? The result is a validated, typed response the app can map to its own text, not raw model prose you have to trust.

That is the central differentiator: **local forensic evidence plus typed AI judgment, gated by explicit human confirmation.** The app collects everything it can prove on your Mac, Jev classifies what it sees, and you — not the model, not the app — trigger every stop.

## Safety model

- **No automatic action.** No background AI calls, no automatic selection, no scheduled cleanup, no force-kill. Each stop requires selecting a row, pressing the stop button, and confirming the exact list.
- **Re-verified before every signal.** Before a graceful stop the app re-checks UID, executable path, process start identity, working directory, shield status, and exact listening endpoints — then re-checks again immediately before signalling. A changed or protected process is skipped and reported.
- **Protected rows.** A shield remembers an executable + project folder + exact port set. It overrides Jev and blocks shutdown. A familiar product name alone is not a keep rule.
- **Strict argument allowlist.** Inspect reads only a safe subset of startup arguments (headless/debug/profile flags, Python module, first script argument, SSH local-forward metadata). Raw command lines, environment values, full paths, and secrets are never displayed or sent to AI.
- **Read-only browser inventory.** Page provenance uses a read-only `/json/list` request against a verified Chrome/Chromium headless process — no navigation, no JavaScript evaluation, no arbitrary HTTP probing.
- **Local history only.** Cleanup history (last 200 outcomes) stays on this Mac. Nothing is sent anywhere except the single Jev request you explicitly trigger.

## Evidence and human confirmation

One scan collects, per process: executable, working project, launchd registration, parent chain, safe startup-argument subset, live peers, browser-harness session provenance, and related preview servers. "Evidence & process details…" opens that already-collected dossier with no extra AI request and no extra cost.

Stopping a process is TCP-only, one row per PID, with no privileged helper, sudo, daemon, login item, or listening port opened by this app. The stop button is the only trigger, and the confirm dialog lists exactly what will be signalled.

## Connect once, decide every time

Jev is a paid, user-triggered service. Connect once with the app's one-time connect flow (or `--connect-jev-from-environment`); the TypeSafe key is stored in your macOS Keychain and never in this repository. After that, every Jev request reads the stored key directly — **no per-request password prompt**. Keychain reads fail cleanly instead of invoking the authentication UI, so a stale or denied item never interrupts a scan. If access ever goes stale (for example, after replacing the app identity), reconnect once.

One paid request per explicit click. No retry, no fallback, no background polling. API failure leaves local evidence intact and the decision with you.

Kill recommendations require confidence ≥ 0.8 and evidence the current provenance adapter supports. Unsupported claims fall back to "Your decision". Bulk mode batches verdict/reason pairs into one request, each pair restricted to its own PID-namespaced dossier.

## Installation

Download the notarized DMG from the [latest release](https://github.com/epiphany-dynamics/port-cleanup/releases/latest), open it, and drag Port Cleanup to Applications.

The app is signed with a Developer ID certificate and notarized by Apple, so macOS 13+ (Ventura) Gatekeeper accepts it without workaround steps.

## Local build and test

```bash
swift run PortCoreTests                    # assertion harness; no XCTest required
python3 scripts/build.py --ad-hoc --destination "$HOME/Desktop/Port Cleanup.app"
python3 scripts/build.py --destination "$HOME/Desktop/Port Cleanup.app"   # Developer ID-signed when installed
python3 scripts/build.py --identity "$IDENTITY" --dmg "$HOME/Desktop/Port Cleanup.dmg"
```

The build script compiles, bundles, signs with the installed Developer ID identity (`Developer ID Application: Epiphany Dynamics LLC (N7CB2S58ZF)`, overridable via `--identity` or `PORT_CLEANUP_CODESIGN_IDENTITY`), enables the hardened runtime, and verifies the signature and Gatekeeper assessment. `--ad-hoc` falls back to local ad-hoc signing. Read-only tools: `--scan`, `--inspect-port PORT`, `--render-preview PATH`, `--render-inspector PATH`. Adding `--interpret-once` or `--analyze-once` makes one paid Jev request and should only be used within authorized verification.

## Current limitations

- TCP listeners only. UDP, UNIX sockets, and privileged system processes are out of scope.
- Process identity is re-checked before signal, but macOS lacks an atomic pidfd-style checked kill; a tiny final race remains.
- No force-kill and no restart-manager override. A process that ignores SIGTERM is reported as not stopped, not killed.
- Launch-history correlation is a strong heuristic, not a kernel-recorded owner token.
- No automatic AI trigger, no automatic selection, no scheduled cleanup. You always decide.

## Project documents

- [LICENSE](LICENSE) — MIT
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute
- [SECURITY.md](SECURITY.md) — security model and reporting
- [CHANGELOG.md](CHANGELOG.md) — release history

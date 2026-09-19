# Port Cleanup

Native macOS utility that tells you which listening ports are safe to stop — and which are not. One scan, three clear verdicts per process (Stop, Keep open, or Your decision), with the evidence on screen. Never kills anything automatically.

## What it does

- **One-click bulk scan with Jev** — every current TCP listener gets a typed recommendation, a plain-language reason, and a material missing fact when the evidence is incomplete.
- **Rich local evidence** — executable, working project, launchd registration, parent chain, safe startup-argument subset, live peers, browser-harness session provenance, and related preview servers. All collected locally; nothing is sent anywhere.
- **Inspect before deciding** — "Evidence & process details…" opens the already-collected dossier with no extra AI request and no extra cost.
- **Your decision is the only trigger** — no automatic selection, no automatic stop, no background AI call. Each stop requires you to select a row, press the red button, and confirm the exact list.
- **Protected rows** — a shield remembers an executable + project folder + exact port set. It overrides Jev and blocks shutdown. A familiar product name alone is not a keep rule.

## Safety and privacy model

- One row per PID: stopping a process closes every socket it owns, TCP only. No privileged helper, sudo, daemon, login item, or listening port opened by this app.
- Before a graceful stop, the app re-checks UID, executable path, microsecond process start identity, current working directory, shield status, and exact listening endpoints. It re-checks again immediately before signalling. A changed or protected process is skipped and reported.
- Inspect reads a strict allowlist subset of startup arguments (headless/debug/profile flags, Python module, first script argument, utility role, SSH local-forward metadata). Raw command lines, environment values, full paths, and secrets are never displayed or sent to AI.
- Browser inventory is read-only `/json/list` against a verified Chrome/Chromium headless process. No navigation, JavaScript evaluation, or arbitrary HTTP probing. Two-second timeout, three-second resource limit, 256 KiB cap, no redirects, cookies, credentials, or proxy.
- Local page titles and origins are visible to Jev in minimized form. Full paths, raw arguments, remote page details, transcript and task text stay local.
- Cleanup history (last 200 outcomes) is stored only on this Mac.

## Jev / TypeSafe integration

Jev runs on TypeSafe's System One models (`jev-latest`, endpoint `https://api.typesafe.ai/v1/systemone`). One finite-choice question per process picks a combined verdict/reason (`kill_*`, `keep_*`, `review_*`); another identifies the single most material missing fact. Bulk mode batches those pairs into one request, each pair restricted to its own PID-namespaced dossier.

- Kill recommendations require confidence ≥ 0.8 and evidence that the current provenance adapter supports. Unsupported claims fall back to "Your decision".
- Displayed explanations are app-owned text mapped from validated typed responses, not raw model prose.
- One paid request per explicit click. No retry, no fallback, no background polling. API failure leaves local evidence intact. The key lives in macOS Keychain.
- On macOS 13+, `ViewState` is aliased to the supported `SwiftUI.State` property wrapper to avoid the unavailable SDK State macro plugin in Command Line Tools builds.

## Build and test

```bash
# Run these commands from the repository root.
swift run PortCoreTests                    # assertion harness; no XCTest on this Mac
python3 scripts/build.py --destination "$HOME/Desktop/Port Cleanup.app"
```

The build script compiles, bundles, ad-hoc signs, and verifies the local-only app. This is not a notarized public release. Read-only tools: `--scan`, `--inspect-port PORT`, `--render-preview PATH`, `--render-inspector PATH`. Adding `--interpret-once` or `--analyze-once` makes one paid request and should only be used within authorized verification.

## Current limitations

- TCP listeners only. UDP, UNIX sockets, and privileged system processes are out of scope.
- Process identity is re-checked before signal, but macOS lacks an atomic pidfd-style checked kill; a tiny final race remains.
- No force-kill and no restart-manager override. A process that ignores SIGTERM is reported as not stopped, not killed.
- Launch-history correlation is a strong heuristic, not a kernel-recorded owner token. Closed session does not prove task success, and later reuse by another task is not resolved.
- No automatic AI trigger, no automatic selection, no scheduled cleanup. You always decide.

## License

MIT — see [LICENSE](LICENSE).

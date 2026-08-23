# Roadmap — xways-bulk_extractor

Current version: **0.5.0** — the first stable release. The items below are
what is planned toward **1.0**.

Priorities are a guide, not a contract. Roughly: P1 = wanted for 1.0, P2 =
nice-to-have, P3 = only if upstream/usage forces it.

## Planned

### ~~P1 — bulk_extractor 2.2.0 integration~~ — delivered in v0.5.0

Upstream released **v2.2.0 on 2026-08-18** — the first release with an
**official precompiled Windows binary** (`bulk_extractor64.exe`, built by CI
via MinGW cross-compile) and with **E01 + raw-device input support on
Windows**. All findings below were verified 2026-08-19 against the release
artifact (SHA256 `dfcc678e…d74bd911`, matches the published `SHA256SUMS`),
not just the release notes — which turned out to be misleading in two places.

**Verified — already compatible, no code change needed:**

- Artifact name is exactly `bulk_extractor64.exe` → the bundled-binary
  auto-detect (exe next to the DLL) finds it as-is.
- The MinGW build has an **empty PE VERSIONINFO** → the identity gate passes
  via its second check: `--version` prints `bulk_extractor 2.2.0` (exit 0),
  which both the needle match and the version-string parser handle unchanged.
- **`base16` was NOT removed.** The release note "removed stale lightgrep
  base16 scanner" refers to internal lightgrep code; `-h` still lists
  `base16` as a disable-by-default scanner, and `-e base16` runs fine. Our
  checkbox stays valid.
- **Dedup default did not change in effect.** The new `--dedupe-mode`
  option defaults to `2 (legacy)` — same behavior as 2.1.x, now tunable.
- E01 input works natively: a test E01 was decompressed and scanned at its
  full logical size (no WSL involved).
- All 35 scanners in the then-hard-coded table still exist with unchanged
  defaults. *(Moot since v0.5.0 — the checklist is discovered from the binary.)*

**Delivered:**

- [x] Append the two **new scanners** to `kScanners`, both enabled by
  default upstream: `vin` (Vehicle Identification Numbers, Kam A. Woods) and
  `rtti` (RawTherapee 8-bit thumbnail carver). Per `-H`, each scanner's
  feature name equals its scanner name (`vin.txt` verified live), so the
  `FeatureToScanner` fall-through already labels their hits correctly — add
  explicit map entries anyway and update the "calibrated against BE 2.0.2"
  comments to 2.2.0. *(Done 2026-08-19. Deliberate non-feature: no
  version-gating on the new checkboxes — BE hard-errors loudly on `-x` of an
  unknown scanner name, verified `no such scanner` / exit 5.)*
- [x] **Output-dir semantics changed — update our guard.** 2.2.0 no longer
  *refuses* a non-empty output dir: rerunning into a completed run's dir
  exits 0 and silently processes nothing (restart logic sees the finished
  `report.xml`; existing feature files are left intact). That silent no-op
  is easier to misread than the old loud error, so the pre-flight
  non-empty-dir check (below) gets more important, and the new **`-Z`
  (zap)** flag — wipe the output dir before starting — is the natural
  opt-in remedy to offer. *(Comments/README/docs updated 2026-08-19; the
  pre-flight dialog check itself remains the P2 item below.)*
- [x] README refresh: official Windows 2.2.0 download (WSL no longer needed
  for E01 or for running ≥2.1; the "BE 2.0.2 is the only precompiled
  Windows build" claim is obsolete), bundled-binary guidance, version
  examples. *(Done 2026-08-19.)*
- [x] Manual (X-Ways GUI) verification. *(Done 2026-08-23 on X-Ways 21.8
  SR-5: identity gate logs "--version banner match" for the 2.2.0 exe; a
  `vin` hit produced its own `BE: vin` label; a 110,806-item selected-items
  run completed with exit 0, 19 per-scanner labels and zero write failures;
  the WSL 2.2.0 binary was exercised end-to-end as well.)*

Carried forward (now P2, below): exposing `--dedupe-mode` and `-Z`.

### P2 — Capture BE's output (remove its console window)

v0.5.0 delivered most of this: the worker thread, real **Cancel**, and an
in-dialog status/progress bar that already reports the export phase item by
item. What remains is the console window itself — BE is still spawned with
`CREATE_NEW_CONSOLE` so the analyst can watch it. Capturing its stdout/stderr
instead and driving the existing status bar from that would remove the extra
window, at the cost of the live scrollback (and of the "console closed"
failure mode, `0xC000013A`, which currently surfaces as an exit-code hint).

### P2 — Expose `--dedupe-mode` and `-Z`

Carried over from the 2.2.0 integration. Both are reachable today through the
**Extra arguments** field, so this is only about promoting them to real
controls: `--dedupe-mode` as a dropdown, `-Z` (zap) behind a confirmation —
it recursively deletes the output directory, which is why it is deliberately
absent from the extra-arguments cue-banner hint.

### P2 — Physical-disk EO source-path support

The "Active evidence object's source image" radio only works for image-backed
EOs (`.E01`, `.dd`, …). Physical-disk EOs return a `model+ID` string from
`XWF_GetEvObjProp` property 9 instead of a path, so the radio is disabled and the
analyst must fall back to "Pick file or directory" with the device path entered
manually. Investigate resolving a usable `\\.\PhysicalDriveN` path for those EOs
so the active-EO mode works for physical disks too.

BE 2.2.0 strengthens the case: its Windows builds now accept raw devices
directly (`C:`, `\\.\PhysicalDriveN`, `\\.\X:`, `\\?\Volume{GUID}` per its
help text), so once we can resolve the device path, native BE can consume it
without WSL. Needs elevation and a manual test against a real device.

### P2 — Tagging in non-selected-items modes

`Tag scanned source items` / `Tag items with feature hits` only work in
selected-items mode, where the `xwitem_<itemID>_` filename token maps BE hits
back to X-Ways item IDs. In active-EO and pick-path modes there is no usable
mapping from BE's offset-based feature paths back to item IDs. Explore whether
BE's forensic-path output can be resolved back to snapshot items (e.g. via
`XWF_GetItemInformation` offset lookups) to extend tagging to those modes.

### P2 — Pre-flight empty-output-dir check

**Partially addressed in v0.5.0** (2026-08-19, after observing the trap
live): Run now re-stamps a previously-used *auto-suggested* dir so every Run
gets a fresh timestamped dir. What remains of this item is the analyst-typed
custom path: detect a non-empty dir there before launch and prompt to pick a
new one (or clear it, e.g. via BE 2.2.0's `-Z`). The stakes changed with BE
2.2.0: older BE refused a non-empty dir with a loud console error, but 2.2.0's
restart logic **silently no-ops** when pointed at a completed run's dir
(exit 0, nothing processed) — an analyst reusing a dir gets stale results
with no warning. The suggested-fresh-subdir default already avoids this;
the pre-flight check closes the manual-path hole, optionally offering
BE 2.2.0's `-Z` (zap = wipe output dir first) behind a confirmation.

### ~~P3 — Scanner-list maintenance vs new BE versions~~ — resolved in v0.5.0

The checklist is now discovered from the selected binary (`-h` / `-H`), so
there is nothing to append when a new BE ships; the built-in table survives
only as the fallback when the probe fails. Free-form **Extra arguments**
cover future options without an X-Tension change. Remaining maintenance:
`FeatureToScanner` (label naming) when BE adds feature files whose names
don't match their scanner — unknown names already fall through unharmed.

### P3 — Report the carved-filename bug upstream

`feature_recorder.cpp` splits the input path with `rfind('/')`, which never
matches a Windows backslash, so on Windows the *entire* input path ends up
inside every carved filename (twice, for `evtx`). v0.5.0 works around it by
passing a relative path, but a one-line upstream fix (`find_last_of("/\\")`)
would remove the need for the workaround — and for the export name cap — for
every Windows user of bulk_extractor, not just this X-Tension. Not yet
reported; worth a minimal reproducer against 2.2.0.

## Shipped

Recent milestones (full detail in the README changelog):

- **v0.5.0** (2026-08-23) — first stable release.
  - Real in-DLL **Cancel**: the BE run moved to a joinable worker thread with
    a three-phase split that keeps every `XWF_*` call on X-Ways' own thread
    (A: input prep in IDOK → B: subprocess on the worker, cancellable via
    `TerminateProcess` → C: post-processing in `WM_APP_DONE`). The
    selected-items export pumps messages and is cancellable too.
  - **bulk_extractor 2.2.0** support, verified against the release artifact.
  - **Scanner list discovered from the binary** (`-h` / `-H`), with a
    built-in fallback; toggles persisted by name as a diff from the binary's
    own defaults; free-form **Extra arguments** field.
  - **Security fix**: the helper binary is identity-gated *before* it is ever
    executed (zero-execution PE/subsystem pre-check), verdicts cached per path.
  - **Correctness fix**: carved output no longer exceeds `MAX_PATH` — BE is
    given a relative input path and a working directory, which is what made
    large directory scans survivable (they previously aborted with exit 6).
  - Dialog rebuilt: binary group on top, scan-target summary, owner-draw
    status bar, tooltips, About and Open-output buttons, themed hover.
  - X-Tension-manager compatibility layer removed; VERSIONINFO added.
- **v0.4.0-beta** — helper-exe identity verification (PE VERSIONINFO + `--version`
  banner, in-dialog flash on rejection); Ctrl-to-save gesture (`SaveCfg`); fixed
  the bundled-binary resolver to look alongside the DLL (was a non-existent
  `bulk_extractor\` subfolder); beta designation; moved into its own repository.
- **v0.3.0** — Run BE via WSL; non-freezing UI (message-pumped wait loop);
  BE 2.1.x version-string + `*_carved` feature-file compatibility.
- **v0.2.4** — auto-cleanup of the selected-items export temp dir on BE success
  (`keep_temp_dir=true` to retain); virtual/unreadable items distinguished from
  real export failures.
- **v0.2.3** — `hVolume = NULL` (Case Root) guard; temp dir relocated to
  `<dll_dir>\temp\`; `XT_Finalize` persists snapshot changes; per-item progress to
  the Output window.

## Deliberately out of scope

- **`XWF_Mount` / `XWF_Unmount`** instead of per-item export. Reviewed 2026-05-13
  and rejected for bulk_extractor specifically: BE's only scope knob is the path
  it's pointed at, so mounting the whole snapshot would scan everything and undo
  the selected-items semantics this X-Tension exists for, and lose the
  `xwitem_<itemID>_` ID-embedding trick. See the README ("Why we extract instead
  of using `XWF_Mount`") for the full rationale.

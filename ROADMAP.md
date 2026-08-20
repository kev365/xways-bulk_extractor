# Roadmap — xways-bulk_extractor

Current version: **0.5.0-beta** (in development on `feature/in-dll-cancel`).
Functionally complete and exercised end-to-end on real cases; the items below
are what's planned before a stable **1.0**.

Priorities are a guide, not a contract. Roughly: P1 = wanted for 1.0, P2 =
nice-to-have, P3 = only if upstream/usage forces it.

## Planned

### P1 — bulk_extractor 2.2.0 integration

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
- All 35 scanners in `kScanners` still exist with unchanged defaults.

**To do:**

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
- [ ] Consider exposing `--dedupe-mode` and `-Z` in the dialog/cfg
  (default-off; `-Z` needs a confirm — it recursively deletes).
- [ ] Manual (X-Ways GUI) verification: identity gate should report
  "--version banner match" for the staged 2.2.0 exe; per-scanner label for a
  `vin` hit; a full selected-items run end-to-end.

### P2 — In-DLL progress (remove BE's console window)

v0.5.0-beta added the worker thread + real **Cancel** (see Shipped). What
remains of the original goal: capture BE's stdout/stderr instead of running
with `CREATE_NEW_CONSOLE`, and surface progress in the dialog (status line /
progress bar) so the extra console window disappears.

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

Detect a non-empty/own-prior-run output dir in the dialog before launch and
prompt to pick a new one (or clear it). The stakes changed with BE 2.2.0:
older BE refused a non-empty dir with a loud console error, but 2.2.0's
restart logic **silently no-ops** when pointed at a completed run's dir
(exit 0, nothing processed) — an analyst reusing a dir gets stale results
with no warning. The suggested-fresh-subdir default already avoids this;
the pre-flight check closes the manual-path hole, optionally offering
BE 2.2.0's `-Z` (zap = wipe output dir first) behind a confirmation.

### P3 — Scanner-list maintenance vs new BE versions

When a new BE ships, diff `bulk_extractor -h` (and `-H` for feature names)
against `kScanners` and append new entries. History: built against BE 2.0.2's
35 scanners, verified unchanged through 2.1.1; BE 2.2.0 added `vin` and
`rtti` (tracked in the P1 integration item above). New scanners a future BE
adds before we catch up run with their BE-side default and their feature
files still get labeled via the `FeatureToScanner` fall-through — the only
loss is the analyst can't toggle them from the dialog.

## Shipped

Recent milestones (full detail in the README changelog):

- **v0.5.0-beta** (in development) — real in-DLL **Cancel**: the BE run moved
  to a joinable worker thread with a three-phase split that keeps every
  `XWF_*` call on X-Ways' own thread (A: input prep in IDOK → B: subprocess
  on the worker, cancellable via `TerminateProcess` → C: post-processing in
  `WM_APP_DONE`); X-Tension-manager compatibility layer removed; VERSIONINFO
  resource added.
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

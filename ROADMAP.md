# Roadmap — xways-bulk_extractor

Current version: **0.4.0-beta**. Functionally complete and exercised end-to-end
on real cases; the items below are what's planned before a stable **1.0**.

Priorities are a guide, not a contract. Roughly: P1 = wanted for 1.0, P2 =
nice-to-have, P3 = only if upstream/usage forces it.

## Planned

### P1 — In-DLL progress + Cancel button

Today BE runs in a separate console window (`CREATE_NEW_CONSOLE`) so the analyst
sees BE's own progress prints; cancelling means closing that console or killing
the process. Since v0.3.0 the X-Ways main window no longer freezes during a run
(the wait loop pumps messages), but there is still no in-DLL Cancel.

Goal: run BE on a worker thread, capture its stdout/stderr, surface progress in
a modeless dialog (or the existing status line), and offer a real **Cancel**
button that terminates the child cleanly. This also removes the extra console
window from the analyst's screen.

### P2 — Physical-disk EO source-path support

The "Active evidence object's source image" radio only works for image-backed
EOs (`.E01`, `.dd`, …). Physical-disk EOs return a `model+ID` string from
`XWF_GetEvObjProp` property 9 instead of a path, so the radio is disabled and the
analyst must fall back to "Pick file or directory" with the device path entered
manually. Investigate resolving a usable `\\.\PhysicalDriveN` path for those EOs
so the active-EO mode works for physical disks too.

### P2 — Tagging in non-selected-items modes

`Tag scanned source items` / `Tag items with feature hits` only work in
selected-items mode, where the `xwitem_<itemID>_` filename token maps BE hits
back to X-Ways item IDs. In active-EO and pick-path modes there is no usable
mapping from BE's offset-based feature paths back to item IDs. Explore whether
BE's forensic-path output can be resolved back to snapshot items (e.g. via
`XWF_GetItemInformation` offset lookups) to extend tagging to those modes.

### P2 — Pre-flight empty-output-dir check

BE refuses to run if the output directory already contains a previous BE run;
right now the analyst only learns this from the error in BE's console and has to
re-run pointing at a fresh directory. Detect a non-empty/own-prior-run output dir
in the dialog before launch and prompt to pick a new one (or clear it).

### P3 — Scanner-list maintenance vs new BE versions

`kScanners` is built against BE 2.0.2's 35 scanners (verified unchanged through
2.1.1). Any scanners a future BE adds won't appear as checkboxes — they'd run
with their BE-side default and emit feature files normally; the only loss is the
analyst can't toggle them off from the dialog. When a new BE ships, diff
`bulk_extractor -h` against `kScanners` and append the new entries.

### P3 — Native Windows BE 2.1.x

The bundled Windows binary is BE **2.0.2** (the only precompiled Windows build in
existence as of 2026-05-02; upstream notes 2.1 "does not build on Windows"). WSL
mode already runs whatever 2.1.x the analyst builds. If/when a native Windows
2.1.x build appears upstream, drop it over the bundled binary (same path) — the
resolver picks it up automatically; no code change required.

## Shipped

Recent milestones (full detail in the README changelog):

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

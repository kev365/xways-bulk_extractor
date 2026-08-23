# Changelog — xways-bulk_extractor

All notable changes to this X-Tension. Versions are `MAJOR.MINOR.PATCH`;
everything before 0.5.0 was pre-release. Dates are the date the work landed.

The README describes the **current** state of the X-Tension — what the dialog
does, how to install it, what its limits are. This file is the history behind
it.

## 0.5.0 — 2026-08-23

- **Real in-DLL Cancel.** The BE run moved off the UI thread onto a joinable worker with a three-phase split that keeps every `XWF_*` call on X-Ways' own thread: input prep runs in the Run handler, only the BE subprocess runs on the worker (cancellable — the Cancel button terminates the child within ~100 ms), and post-processing (evidence object, labels, temp cleanup) runs back on the UI thread when the worker reports done. The dialog stays responsive throughout; closing it mid-run is blocked, and Cancel shows a "Cancelling…" status until the child is reaped.
- **bulk_extractor 2.2.0 support** (all findings verified against the official 2.2.0 Windows release binary, not just the release notes):
  - Two new scanner checkboxes: **`vin`** (Vehicle Identification Numbers) and **`rtti`** (RawTherapee 8-bit thumbnail carver) — both enabled by default upstream, checklist now 37 scanners. Note: unchecking either while running a pre-2.2.0 BE fails the run (BE hard-errors on `-x` of a name it doesn't know: `no such scanner`).
  - 2.2.0 is the **first upstream release with an official precompiled Windows binary** (`bulk_extractor64.exe`) — and it reads E01 images and raw devices natively, so WSL is no longer required for E01 or ≥2.1 features. The MinGW-built exe has an empty PE `VERSIONINFO`; the identity gate passes it via its `--version` banner check.
  - `base16` was **not** removed (the release note about the "stale lightgrep base16 scanner" refers to internal code) and the new `--dedupe-mode` defaults to legacy behavior — both verified, no changes needed.
  - **Output-dir caveat**: 2.2.0 no longer refuses a non-empty output dir; rerunning into a completed run's dir exits 0 having silently processed nothing (its restart logic sees the finished `report.xml`). Keep using a fresh dir per run — the suggested timestamped default already does this.
- **Output dir re-stamped on every Run.** The auto-suggested `bulk_extractor_<stamp>` dir used to be timestamped once at dialog open, so a second Run in the same dialog session reused the first run's dir — pre-2.2.0 BE refuses that loudly; BE 2.2.0 silently no-ops (exit 0, nothing processed — observed live). Run now detects a previously-used auto-suggested dir and swaps in a fresh timestamp (with a same-second collision guard). Analyst-typed custom paths are never rewritten.
- **Scanner list discovered from the binary.** The Scanners checklist is no longer a hard-coded table: on dialog open (and whenever the binary changes — Browse, typed path, WSL toggle) the X-Tension runs the selected binary's `-h` for names + default states and `-H` for tooltip descriptions, so new upstream scanners appear without an update and `-e`/`-x` is never emitted for a scanner the binary lacks. Native probes are synchronous (~0.2 s); WSL probes run in the background ("Scanners (discovering…)"). The built-in table is only a fallback ("Scanners (built-in list)") when the probe fails, with the reason logged.
- **Scanner toggles persist.** Ctrl+Run now writes `scanners_enable=` / `scanners_disable=` — by name, and only where you differ from the selected binary's own defaults — so a BE upgrade doesn't drag stale defaults along. Unknown names are ignored with a Messages line.
- **Extra arguments field.** Free-form options appended verbatim after the scanner flags and `-R`, before the input path (e.g. `-S jpeg_carve_mode=2`, `--dedupe-mode 0`, `-f <regex>`); persisted as `extra_args=`. Run warns if it contains an option the dialog already sets.
- **The bulk_extractor binary is never executed before it passes the identity gate.** A zero-execution pre-check now runs first — MZ/PE signature, not a DLL, console subsystem — so a GUI executable at the configured path is rejected *without being launched*. Previously the capability probe (`-h`) and the `--version` banner check ran against whatever sat at that path: pointing `be_binary` at `notepad.exe` opened roughly five Notepad windows per dialog open. Verdicts are now cached per path (size + write time), the gate runs before any capability probe, and a rejection logs once per (path, reason) rather than on every re-check.
- **Carved output filenames no longer blow past `MAX_PATH`.** bulk_extractor names every carved file after the input path exactly as passed on the command line, so an absolute path put ~48 characters of 8.3 gibberish inside each name — twice, for `evtx` — which capped exported names at 26 characters and aborted whole runs with exit 6. Native runs now spawn BE with its **working directory set to the input** and pass a **relative** path (`.`, or the bare file name), collapsing that embedded prefix to two characters. Measured on a 110,806-file run: longest carved path 203 of 259 characters, zero write failures, and no exported name truncated. See "Known issues" for the measurements and the `zip_carved` caveat.
- **`Browse...` works in WSL mode.** A Linux-style path seeded into `GetOpenFileNameW` fails with `FNERR_INVALIDFILENAME` and shows *no dialog at all*; the picker now opens at `\\wsl.localhost\` instead, and any picker failure is logged with `CommDlgExtendedError()`.
- **Clearer diagnostics.** Unknown scanner names from the cfg cite the offending line (`unknown scanner 'bogus' ignored (bulk_extractor.cfg line 37)`), and the extra-arguments conflict prompt now names the dialog setting the flag would override rather than just the flag.
- **Dialog polish.** The "Selected items: N" readout is hidden unless that input source is chosen (it previously read as though that count applied to whichever source was active); the WSL checkbox and status bar repaint before the version probe blocks, so toggling no longer feels dead.
- **X-Tension-manager compatibility layer removed** (that project is retired); the DLL now exports only the standard `XT_*` entry points, and carries a proper `VERSIONINFO` resource.

## 0.4.0-beta — 2026-06-06

- **Beta designation.** Version string is now `0.4.0-beta` (shown in the About box, the missing-pointer diagnostics, and the cfg header). No functional change from 0.4.0 — the suffix just marks the public-beta milestone as this X-Tension moves into its own repository.
- **Helper-exe identity verification.** The resolved Windows `bulk_extractor64.exe` is identity-checked before it is spawned — PE `VERSIONINFO` substring (`InternalName` / `OriginalFilename` / `ProductName` / `FileDescription`) **or** `--version` banner, needle `bulk_extractor` (case-insensitive). Applied at every resolution site (dialog field, cfg, bundled, Browse..., and the headless RVS path). A rejected file is refused hard; in dialog mode it surfaces inline as a bold-red, briefly-flashing `Not a valid bulk_extractor.exe file` on the status line (no MessageBox) and disables Run until a valid Browse pick clears it. WSL mode is exempt (the Linux binary can't be inspected from the Windows side).
- **Ctrl-to-save gesture.** Holding **Ctrl** swaps the Run button to a blue **"Save"** (writes the current dialog state to the `bulk_extractor.cfg` sidecar next to the DLL, skipping Run-only validation) and Close to **"Save as..."** (a `GetSaveFileNameW` export). Backed by a new `SaveCfg` helper. Enter still triggers Run via `DM_SETDEFID`.
- **Bundled-binary path fix.** The bundled-default resolver now looks for `bulk_extractor64.exe` **alongside the DLL** (`<dll_dir>\bulk_extractor64.exe`), matching `build.bat`'s deploy layout and the project convention. It previously looked in a `bulk_extractor\` subfolder that `build.bat` never created, so the bundled default silently failed and analysts had to fall back to a cfg/dialog override. **Migration:** if you previously placed the binary in a `bulk_extractor\` subfolder, move it next to the DLL (or just re-run `build.bat`).

## 0.3.0 — 2026-05-05

- **Run via WSL** checkbox in the dialog. Detected once at first dialog open via `wsl --status` → `wsl which bulk_extractor` → `wsl bulk_extractor -V`. Status readout next to the checkbox shows the detected version (`WSL bulk_extractor v2.1.1 detected`) or the "not detected" reason.
- **BE-binary edit holds a Linux path** when WSL mode is on (e.g. `/usr/bin/bulk_extractor`); toggling the checkbox swaps it with the Windows path. Both paths are kept in `Settings` so the analyst can flip back and forth without losing typing.
- **Path translation** at run time. `wsl.exe -e <linuxBe> -o /mnt/c/...output ...` — Windows paths are mapped to `/mnt/c/...` for BE; output flows back to the same Windows location, transparent to the rest of the post-processing.
- **Browse... handles WSL UNCs.** When picking a binary in WSL mode, `\\wsl$\<distro>\usr\bin\bulk_extractor` returned by the picker is automatically converted to `/usr/bin/bulk_extractor` before going into the field.
- New sidecar config keys: `use_wsl=true` (pre-checks the dialog box, honored only if detection succeeds) and `wsl_be_binary=/path/...` (overrides auto-detected Linux path).
- **Version-string parser handles BE 2.1.x** (`bulk_extractor 2.1.1`) in addition to BE 2.0.x (`bulk_extractor version 2.0.4`). Falls back to scanning for the first whitespace-delimited token that starts with a digit and contains a `.`.
- **UI no longer freezes during long BE runs.** The synchronous `WaitForSingleObject(beProcess, INFINITE)` was upgraded to `MsgWaitForMultipleObjects` + `PeekMessage` pump, so X-Ways' main window keeps painting / responding to clicks while BE grinds. Previously a multi-GB run made X-Ways show "(Not Responding)" until BE finished.

## 0.2.4 — 2026-05-03

- **Auto-cleanup of selected-items temp dir.** Previously `<dll_dir>\temp\` accumulated one `be_input_<stamp>_*` per run, each holding full-byte copies of the selected items (sensitive content sitting outside the case + indefinite disk growth). v0.2.4 deletes the temp dir recursively when BE returned exit code 0; keeps it on BE-failure so the analyst can inspect what was sent. Override with `keep_temp_dir=true` in `bulk_extractor.cfg` if you want to preserve every export for cross-checking against feature-file hits.
- **Virtual / unreadable items distinguished from real export failures.** Items like `Free space` (synthetic / computed) report `XWF_GetItemSize > 0` but `XWF_Read` returns 0 bytes immediately. v0.2.3 logged these as `export FAILED:` (misleading) and counted them in the failure tally. v0.2.4 detects "first-chunk zero-read" and logs `skipped (virtual / unreadable)` instead, doesn't tag them as scanned, and surfaces a separate "(N virtual / unreadable items skipped)" line in the run summary.

## 0.2.3 — 2026-05-03

- **`hVolume = NULL` guard.** Per 21.4 SR-5, X-Ways passes a `NULL` volume handle when the X-Tension is invoked from the **Case Root** window. Previously the selected-items export would AV. v0.2.3 detects this and shows the analyst a friendly "use the partition / image directory browser instead" dialog.
- **Temp dir moved to `<dll_dir>\temp\`.** Previously used `XWF_GetEvObjProp(.., 12, ..)` (the X-Ways evidence working directory) — but X-Ways periodically tries to delete unrecognised files there, causing modal "Cannot delete" warnings during selected-items export. New base avoids the conflict.
- **`XT_Finalize` returns `0x02`** after the run mutated snapshot state (added Labels, attached output evidence object). Per 21.3 Preview 3, X-Ways persists those changes automatically — saves the analyst a manual save step.
- **`XWF_AddToReportTable` flags = `0x01`** (`AddReportTableFlags::CreatedByApplication`, per the xwf-api-rs community bindings). Marks the auto-tagged Labels as application-created vs examiner-created — visually distinct in the Labels picker.
- **Per-item progress to the Output window** (`XWF_OutputMessage` flag `0x08`, v20.6+). Keeps the Messages window clean; only run start, errors, and summary tallies stay there. Older X-Ways builds ignore the flag harmlessly.

---

### Appendix — bulk_extractor 2.1.x compatibility (verified 2026-05-05)

The Windows side ships BE 2.0.2 (bundled binary) and the WSL side runs whatever the analyst built — verified working against **BE 2.1.1** built from `master` on Ubuntu 24.04. End-to-end run (8 NTFS items including bootmgr, MFT, pagefile.sys) returned exit code 0, produced feature files, and surfaced 10 per-scanner labels across 18 tagged items.

- **Cmdline flags** — `-o`, `-j`, `-M`, `-R`, `-e`, `-x` all behave the same as 2.0.x. No changes needed.
- **New `*_carved` feature files in 2.1.x** — `ntfslogfile_carved`, `ntfsmft_carved`, `ntfsusn_carved`, `winpe_carved` appear alongside the parent recorders. These surface as `bulk_extractor: ntfslogfile_carved` etc. via the per-scanner-label code, which derives labels from feature filenames — no `FeatureToScanner` table change required.
- **Scanner toggle list** — discovered from the selected binary since v0.5.0 (`-h`), so a 2.1.1 binary shows its 36 scanners and a 2.2.0 binary its 37; the built-in table is only a fallback. *(Historical: the table was built against 2.0.2's 35 scanners and verified unchanged through 2.1.1.)*

Feature files the label mapper doesn't know surface as labels under their own name (`FeatureToScanner` falls through), so nothing needs maintaining when BE adds feature outputs.

Feature files the label mapper doesn't recognise surface as labels under their
own name (`FeatureToScanner` falls through), so nothing needs maintaining when
bulk_extractor adds feature outputs.

### Earlier releases

0.2.2 and earlier predate this changelog; see the git history.

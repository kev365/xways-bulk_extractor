# bulk_extractor X-Tension

Wraps Simson Garfinkel's [bulk_extractor](https://github.com/simsong/bulk_extractor) as an X-Ways Forensics X-Tension. Exposes a settings dialog (parented to X-Ways' main window), runs `bulk_extractor64.exe` (Windows) **or `bulk_extractor` via WSL** against the chosen input, and (optionally) feeds the output back into X-Ways.

> **Status: 0.5.0-beta.** Functionally complete and exercised end-to-end on real cases, but still pre-1.0 — see [ROADMAP.md](ROADMAP.md) for what's planned before a stable release.

## v0.5.0-beta changes (2026-08-19 — in-DLL Cancel + BE 2.2.0)

- **Real in-DLL Cancel.** The BE run moved off the UI thread onto a joinable worker with a three-phase split that keeps every `XWF_*` call on X-Ways' own thread: input prep runs in the Run handler, only the BE subprocess runs on the worker (cancellable — the Cancel button terminates the child within ~100 ms), and post-processing (evidence object, labels, temp cleanup) runs back on the UI thread when the worker reports done. The dialog stays responsive throughout; closing it mid-run is blocked, and Cancel shows a "Cancelling…" status until the child is reaped.
- **bulk_extractor 2.2.0 support** (all findings verified against the official 2.2.0 Windows release binary, not just the release notes):
  - Two new scanner checkboxes: **`vin`** (Vehicle Identification Numbers) and **`rtti`** (RawTherapee 8-bit thumbnail carver) — both enabled by default upstream, checklist now 37 scanners. Note: unchecking either while running a pre-2.2.0 BE fails the run (BE hard-errors on `-x` of a name it doesn't know: `no such scanner`).
  - 2.2.0 is the **first upstream release with an official precompiled Windows binary** (`bulk_extractor64.exe`) — and it reads E01 images and raw devices natively, so WSL is no longer required for E01 or ≥2.1 features. The MinGW-built exe has an empty PE `VERSIONINFO`; the identity gate passes it via its `--version` banner check.
  - `base16` was **not** removed (the release note about the "stale lightgrep base16 scanner" refers to internal code) and the new `--dedupe-mode` defaults to legacy behavior — both verified, no changes needed.
  - **Output-dir caveat**: 2.2.0 no longer refuses a non-empty output dir; rerunning into a completed run's dir exits 0 having silently processed nothing (its restart logic sees the finished `report.xml`). Keep using a fresh dir per run — the suggested timestamped default already does this.
- **X-Tension-manager compatibility layer removed** (that project is retired); the DLL now exports only the standard `XT_*` entry points, and carries a proper `VERSIONINFO` resource.

## v0.4.0-beta changes (2026-06-06)

- **Beta designation.** Version string is now `0.4.0-beta` (shown in the About box, the missing-pointer diagnostics, and the cfg header). No functional change from 0.4.0 — the suffix just marks the public-beta milestone as this X-Tension moves into its own repository.
- **Helper-exe identity verification.** The resolved Windows `bulk_extractor64.exe` is identity-checked before it is spawned — PE `VERSIONINFO` substring (`InternalName` / `OriginalFilename` / `ProductName` / `FileDescription`) **or** `--version` banner, needle `bulk_extractor` (case-insensitive). Applied at every resolution site (dialog field, cfg, bundled, Browse..., and the headless RVS path). A rejected file is refused hard; in dialog mode it surfaces inline as a bold-red, briefly-flashing `Not a valid bulk_extractor.exe file` on the status line (no MessageBox) and disables Run until a valid Browse pick clears it. WSL mode is exempt (the Linux binary can't be inspected from the Windows side).
- **Ctrl-to-save gesture.** Holding **Ctrl** swaps the Run button to a blue **"Save"** (writes the current dialog state to the `bulk_extractor.cfg` sidecar next to the DLL, skipping Run-only validation) and Close to **"Save as..."** (a `GetSaveFileNameW` export). Backed by a new `SaveCfg` helper. Enter still triggers Run via `DM_SETDEFID`.
- **Bundled-binary path fix.** The bundled-default resolver now looks for `bulk_extractor64.exe` **alongside the DLL** (`<dll_dir>\bulk_extractor64.exe`), matching `build.bat`'s deploy layout and the project convention. It previously looked in a `bulk_extractor\` subfolder that `build.bat` never created, so the bundled default silently failed and analysts had to fall back to a cfg/dialog override. **Migration:** if you previously placed the binary in a `bulk_extractor\` subfolder, move it next to the DLL (or just re-run `build.bat`).

## v0.3.0 changes (2026-05-05 — WSL bulk_extractor support)

- **Run via WSL** checkbox in the dialog. Detected once at first dialog open via `wsl --status` → `wsl which bulk_extractor` → `wsl bulk_extractor -V`. Status readout next to the checkbox shows the detected version (`WSL bulk_extractor v2.1.1 detected`) or the "not detected" reason.
- **BE-binary edit holds a Linux path** when WSL mode is on (e.g. `/usr/bin/bulk_extractor`); toggling the checkbox swaps it with the Windows path. Both paths are kept in `Settings` so the analyst can flip back and forth without losing typing.
- **Path translation** at run time. `wsl.exe -e <linuxBe> -o /mnt/c/...output ...` — Windows paths are mapped to `/mnt/c/...` for BE; output flows back to the same Windows location, transparent to the rest of the post-processing.
- **Browse... handles WSL UNCs.** When picking a binary in WSL mode, `\\wsl$\<distro>\usr\bin\bulk_extractor` returned by the picker is automatically converted to `/usr/bin/bulk_extractor` before going into the field.
- New sidecar config keys: `use_wsl=true` (pre-checks the dialog box, honored only if detection succeeds) and `wsl_be_binary=/path/...` (overrides auto-detected Linux path).
- **Version-string parser handles BE 2.1.x** (`bulk_extractor 2.1.1`) in addition to BE 2.0.x (`bulk_extractor version 2.0.4`). Falls back to scanning for the first whitespace-delimited token that starts with a digit and contains a `.`.
- **UI no longer freezes during long BE runs.** The synchronous `WaitForSingleObject(beProcess, INFINITE)` was upgraded to `MsgWaitForMultipleObjects` + `PeekMessage` pump, so X-Ways' main window keeps painting / responding to clicks while BE grinds. Previously a multi-GB run made X-Ways show "(Not Responding)" until BE finished.

## Setting up bulk_extractor in WSL

The X-Tension auto-detects whatever BE the analyst has installed in WSL — nothing is bundled or pre-built.

> **Note:** since BE 2.2.0 ships an official Windows binary with native E01 and raw-device support, WSL mode is optional — useful mainly if you prefer a distro-packaged or self-built BE.

`bulk-extractor` is **not in current Ubuntu repos** (it was removed in 22.04+ and Debian 11+), so `apt install` won't work on a fresh WSL install. The reliable path is **build from source**. Recipe distilled from [upstream's install wiki](https://github.com/simsong/bulk_extractor/wiki/Installing-bulk_extractor):

The recipe below installs:

- **flex, libre2-dev, libssl-dev** — required by BE's configure (it errors out if any are missing).
- **libsqlite3-dev** — lets BE emit sqlite-backed feature files in addition to plain text.
- **libbz2-dev** — adds bzip2 support to libewf, so E01 images compressed with bzip2 (EnCase 7+ option) work alongside the default zlib-compressed ones.
- **libewf** (built from libyal source, since the apt package is a 2014-era release) — adds direct `.E01` support so BE can be pointed at an EnCase image.

### From the WSL terminal directly (simplest)

```bash
sudo apt update
sudo apt install -y autoconf automake g++ flex libbz2-dev libre2-dev libsqlite3-dev libssl-dev libtool make pkg-config wget zlib1g-dev git

# libewf — 20240506 experimental release from libyal
# https://github.com/libyal/libewf/releases
cd ~
wget https://github.com/libyal/libewf/releases/download/20240506/libewf-experimental-20240506.tar.gz
tar xzf libewf-experimental-20240506.tar.gz
cd libewf-20240506
./configure
make -j$(nproc)
sudo make install
sudo ldconfig

# bulk_extractor itself
git clone --recursive https://github.com/simsong/bulk_extractor.git ~/bulk_extractor
cd ~/bulk_extractor
./bootstrap.sh
./configure
make -j$(nproc)
sudo make install

bulk_extractor -V
which bulk_extractor
```

Tested on Ubuntu 24.04 (WSL) on 2026-05-05. ~10–15 minutes total on a typical machine; libewf is the longer of the two builds.

### From a PowerShell prompt (one-shot via `wsl -e`)

PowerShell will mangle `$(nproc)` if you wrap the command in **double** quotes — it tries to evaluate `nproc` as a PowerShell command. Use **single** quotes to pass the bash one-liner through verbatim:

```powershell
wsl -e bash -c 'sudo apt update && sudo apt install -y autoconf automake g++ flex libbz2-dev libre2-dev libsqlite3-dev libssl-dev libtool make pkg-config wget zlib1g-dev git'

wsl -e bash -c 'cd ~ && wget https://github.com/libyal/libewf/releases/download/20240506/libewf-experimental-20240506.tar.gz && tar xzf libewf-experimental-20240506.tar.gz && cd libewf-20240506 && ./configure && make -j$(nproc) && sudo make install && sudo ldconfig'

wsl -e bash -c 'git clone --recursive https://github.com/simsong/bulk_extractor.git ~/bulk_extractor && cd ~/bulk_extractor && ./bootstrap.sh && ./configure && make -j$(nproc) && sudo make install'

wsl -e bulk_extractor -V
wsl -e which bulk_extractor
```

Lands at `/usr/local/bin/bulk_extractor`. ~10–15 minutes on a typical machine. After install, reload the X-Tension dialog — the "WSL bulk_extractor v2.1.x detected" status appears, and `Run via WSL` becomes selectable.

To pin a specific release instead of `master` (run after the clone above):

```bash
cd ~/bulk_extractor
git checkout v2.1.0
git submodule update --init --recursive
./bootstrap.sh && ./configure && make -j$(nproc) && sudo make install
```

If a previous build attempt left a partial clone, `rm -rf ~/bulk_extractor` and retry — `git clone` refuses to overwrite an existing directory.

### WSL distro choice

The X-Tension uses `wsl.exe -e ...` which targets the analyst's **default** distro (set with `wsl --set-default <name>`). No distro-specific code in the X-Tension. Setup docs target Ubuntu since that's the default for fresh WSL installs.

### BE 2.2.0 compatibility (verified 2026-08-19)

Verified against the official v2.2.0 Windows release binary (SHA256-checked
against the published `SHA256SUMS`), exercised directly rather than trusting
the release notes:

- **Scanner set**: all 35 pre-2.2.0 scanners unchanged (defaults included —
  `base16` still exists, still default-off). Two additions, both default-on:
  `vin` and `rtti`. `kScanners` and `FeatureToScanner` updated; per `-H`, each
  new scanner's feature name equals its scanner name (`vin.txt` confirmed live
  with test VINs), so hit labels come out as `bulk_extractor: vin` / `rtti`.
- **Identity gate / version parse**: the MinGW-built exe ships an empty PE
  `VERSIONINFO`, so verification passes via the `--version` banner
  (`bulk_extractor 2.2.0`, same shape as 2.1.x — parser unchanged).
- **E01 + raw devices, natively on Windows**: a test E01 was decompressed and
  scanned at full logical size without WSL; the help text documents raw-device
  inputs (`\\.\PhysicalDriveN`, `\\.\X:`, `\\?\Volume{GUID}`).
- **Output-dir semantics changed**: instead of refusing a non-empty output
  dir, 2.2.0's restart logic exits 0 and silently processes nothing when the
  dir holds a completed run (existing feature files are left intact). Use a
  fresh dir per run; the new `-Z` (zap) flag wipes the dir first if you truly
  want to reuse one.
- **`--dedupe-mode`** is new but defaults to `2` (legacy) — behavior matches
  2.1.x unless overridden.

### BE 2.1.x compatibility (verified 2026-05-05)

The Windows side ships BE 2.0.2 (bundled binary) and the WSL side runs whatever the analyst built — verified working against **BE 2.1.1** built from `master` on Ubuntu 24.04. End-to-end run (8 NTFS items including bootmgr, MFT, pagefile.sys) returned exit code 0, produced feature files, and surfaced 10 per-scanner labels across 18 tagged items.

- **Cmdline flags** — `-o`, `-j`, `-M`, `-R`, `-e`, `-x` all behave the same as 2.0.x. No changes needed.
- **New `*_carved` feature files in 2.1.x** — `ntfslogfile_carved`, `ntfsmft_carved`, `ntfsusn_carved`, `winpe_carved` appear alongside the parent recorders. These surface as `bulk_extractor: ntfslogfile_carved` etc. via the per-scanner-label code, which derives labels from feature filenames — no `FeatureToScanner` table change required.
- **Scanner toggle list** — `kScanners` was built against 2.0.2's 35 scanners; 2.1.1 keeps the same set, so the checkbox grid covers it. (2.2.0 added `vin` and `rtti` — both now in the checklist, see the 2.2.0 section above.) Scanners a future BE adds before the list is updated simply don't appear as checkboxes — they run with their BE-side default and emit feature files normally; the only consequence is the analyst can't toggle them from the dialog. Detect with: diff `bulk_extractor -h` against `kScanners` and append entries.

If a feature filename appears that you want to *suppress* via the dialog (rather than just label after the fact), add it to `kScanners`. Otherwise it'll surface as a label transparently and there's nothing to do.

## v0.2.4 changes (2026-05-03 — followups from first end-to-end run)

- **Auto-cleanup of selected-items temp dir.** Previously `<dll_dir>\temp\` accumulated one `be_input_<stamp>_*` per run, each holding full-byte copies of the selected items (sensitive content sitting outside the case + indefinite disk growth). v0.2.4 deletes the temp dir recursively when BE returned exit code 0; keeps it on BE-failure so the analyst can inspect what was sent. Override with `keep_temp_dir=true` in `bulk_extractor.cfg` if you want to preserve every export for cross-checking against feature-file hits.
- **Virtual / unreadable items distinguished from real export failures.** Items like `Free space` (synthetic / computed) report `XWF_GetItemSize > 0` but `XWF_Read` returns 0 bytes immediately. v0.2.3 logged these as `export FAILED:` (misleading) and counted them in the failure tally. v0.2.4 detects "first-chunk zero-read" and logs `skipped (virtual / unreadable)` instead, doesn't tag them as scanned, and surfaces a separate "(N virtual / unreadable items skipped)" line in the run summary.

## v0.2.3 changes (2026-05-03 — folded findings from xways_recon_probe)

- **`hVolume = NULL` guard.** Per 21.4 SR-5, X-Ways passes a `NULL` volume handle when the X-Tension is invoked from the **Case Root** window. Previously the selected-items export would AV. v0.2.3 detects this and shows the analyst a friendly "use the partition / image directory browser instead" dialog.
- **Temp dir moved to `<dll_dir>\temp\`.** Previously used `XWF_GetEvObjProp(.., 12, ..)` (the X-Ways evidence working directory) — but X-Ways periodically tries to delete unrecognised files there, causing modal "Cannot delete" warnings during selected-items export. New base avoids the conflict.
- **`XT_Finalize` returns `0x02`** after the run mutated snapshot state (added Labels, attached output evidence object). Per 21.3 Preview 3, X-Ways persists those changes automatically — saves the analyst a manual save step.
- **`XWF_AddToReportTable` flags = `0x01`** (`AddReportTableFlags::CreatedByApplication`, per the xwf-api-rs community bindings). Marks the auto-tagged Labels as application-created vs examiner-created — visually distinct in the Labels picker.
- **Per-item progress to the Output window** (`XWF_OutputMessage` flag `0x08`, v20.6+). Keeps the Messages window clean; only run start, errors, and summary tallies stay there. Older X-Ways builds ignore the flag harmlessly.

## What's in the dialog (v0.2.0)

- **Input source** — radio: active EO source image / external file or directory / selected items in directory browser. The active-EO radio auto-disables (with a hint explaining *why*) when the active EO doesn't expose a parseable source path — common for physical-disk EOs which return `model+ID` from `XWF_GetEvObjProp` property 9 instead of a path. The raw property-9 value is logged to the X-Ways messages window every run for diagnosis.
- **Output directory** — defaults to `<case dir>\bulk_extractor_<timestamp>` (or `%TEMP%\...` if no case is open).
- **bulk_extractor binary** — auto-filled with the bundled binary path; overridable here, or via `bulk_extractor.cfg` `be_binary=...`.
- **Threads (-j)** — dropdown listing 1..N where N = system cores; default selected = max(1, N/2) so the analyst keeps headroom for X-Ways and the OS while BE is grinding.
- **Max recursion (-M)** — defaults to 12 (BE's own default).
- **Scanners** — one checkbox per BE scanner (37 total in 3 columns as of BE 2.2.0), pre-checked to match BE's defaults. Toggle any to override; "Reset to defaults" restores BE defaults. The X-Tension only emits `-e` / `-x` flags for scanners that diverge from defaults, so the cmdline stays readable in the messages-window log.
- **Output handling** — four checkboxes:
  - Add output dir as evidence (default on).
  - Open in Explorer when done.
  - Tag scanned source items as `bulk_extractor scanned` (selected-items mode only, default on) — every successfully exported item gets the tag, so even partial runs leave an audit trail.
  - Tag items with feature hits as `bulk_extractor hits` (selected-items mode only, default on) — subset of "scanned" where bulk_extractor found ≥1 feature; mapped via the `xwitem_<itemID>_` token in the temp filenames.

## Inputs

Three input modes, picked in the dialog:

1. **Active evidence object's source image** — resolved via `XWF_GetEvObjProp(hEvidence, 9, ...)`. Works for image-backed evidence (`.E01`, `.dd`, etc.); does not work for physical-disk evidence (`XWF_GetEvObjProp` returns the model+ID rather than a path). The dialog disables this radio when no parseable source path is available.
2. **Pick file or directory** — standard Win32 file/folder pickers.
3. **Use selected items in directory browser** — invoked via right-click → Run X-Tension. Selected items are exported to a temp dir as `xwitem_<itemID>_<safe_leaf>.bin`, BE runs on the temp dir with `-R`, then we walk feature files looking for the `xwitem_NNN_` token to map hits back to source item IDs.

## Outputs

Three checkboxes in the dialog (default = first only):

- **Add output directory to X-Ways case as evidence object** — calls `XWF_CreateEvObj(nType=3, ...)` (Directory). Lets X-Ways index the feature files alongside the rest of the case.
- **Open output folder in Explorer when done** — `ShellExecuteW`.
- **Tag scanned source items** (selected-items mode only) — every successfully exported item is tagged with the report table `bulk_extractor scanned` at export time. Audit trail of "what did we run BE on, when".
- **Tag items with feature hits** (selected-items mode only) — items whose exported temp file appears in any feature file get tagged with the report table `bulk_extractor hits`. Subset of "scanned".

## Bundle layout

```text
xtensions\                                  <- copied into <X-Ways install>\xtensions\
└── xways-bulk_extractor\
    ├── xways-bulk_extractor.dll
    ├── xways-bulk_extractor.cfg            (optional sidecar overrides)
    ├── xways-bulk_extractor.cfg.example    (documents every cfg key)
    └── bulk_extractor64.exe                (upstream binary, alongside the DLL — v2.2.0+ recommended)
```

### Sourcing `bulk_extractor64.exe`

The ~97 MB binary is **not committed to this repo** (`.gitignore`'d to keep the
clone size sane); fresh checkouts need to download it once. Since **v2.2.0**
(2026-08-18) upstream publishes an official precompiled Windows binary with
each GitHub release — verify its SHA-256 against the release's `SHA256SUMS`:

- Upstream project: <https://github.com/simsong/bulk_extractor>
- Windows binary download: <https://github.com/simsong/bulk_extractor/releases/latest> (`bulk_extractor64.exe` asset)
- Expected install path: `xtensions/xways-bulk_extractor/bulk_extractor64.exe` (alongside the built DLL).

(Historical: before 2.2.0 the only precompiled Windows binary was a v2.0.2
build hosted on the Digital Corpora S3 bucket — no longer recommended.)

When a newer Windows build ships, drop it in the same path and the X-Tension
picks it up automatically (see priority chain below). To pin to an
out-of-tree binary, use the dialog field or `be_binary=` in
`bulk_extractor.cfg`.

The DLL resolves the BE binary via this priority chain (highest wins):

1. Path entered in the dialog field.
2. `be_binary=...` in `bulk_extractor.cfg`.
3. `<dll_dir>\bulk_extractor64.exe` (the bundled default — alongside the DLL).

A future BE Windows release just drops in: replace the `.exe` (same path) and run again. Or pin to a different location via the cfg or dialog.

### Sidecar cfg keys (optional)

`bulk_extractor.cfg` next to the DLL — `key=value`, one per line, `#` for comments:

```ini
# Override path to bulk_extractor64.exe
be_binary=C:\Tools\bulk_extractor\v2.1.x\bulk_extractor64.exe

# Override the default output directory (otherwise uses <case dir>\bulk_extractor_<stamp>)
default_output_dir=E:\BE_output

# v0.2.4: keep the selected-items export temp dir after a successful BE run.
# Default behaviour is to auto-delete on BE-success (since the temp dir holds
# full-byte copies of the selected items — sensitive content + accumulating
# disk usage). Set this to true if you want to inspect the exported
# xwitem_*.bin files post-run (e.g. to cross-check BE feature hits against
# the raw bytes).
keep_temp_dir=false
```

## Bundled bulk_extractor version

The recommended `bulk_extractor64.exe` is the official **v2.2.0** release asset from GitHub — the first upstream release with a precompiled Windows binary (CI-built via MinGW cross-compile; statically linked, no DLL dependencies, empty PE `VERSIONINFO` so the identity gate uses its `--version` banner). It reads E01 images and raw devices natively.

- File: `xtensions\xways-bulk_extractor\bulk_extractor64.exe`
- Source: <https://github.com/simsong/bulk_extractor/releases/tag/v2.2.0>
- Size: 97,268,659 bytes
- SHA-256: `DFCC678EE3B7DA111E8FBA6259C4E842FFFFCBE42DD96E6C6E6CC238D74BD911`

(The previous recommendation was the v2.0.2 build from the Digital Corpora S3 bucket, 90,072,666 bytes, SHA-256 `01364D33C0A0AF86DEAD0B56794E5A098BD10280174FD0D67537BAFEB500A4A0` — still works with this X-Tension, but lacks E01/raw-device input and the `vin`/`rtti` scanners.)

To upgrade later: drop a newer `bulk_extractor64.exe` over the bundled one, or point the cfg / dialog at a different path.

## Building

From the **x64 Native Tools Command Prompt for VS 2019/2022**:

```bat
cd x-tensions\xways-bulk_extractor
build.bat
```

`build.bat` runs `rc.exe` on the dialog template, `cl.exe` on the source, links to `xways-bulk_extractor.dll`, and stages a fresh copy under `xtensions\xways-bulk_extractor\` for deployment.

## Deployment

Copy the `xtensions\xways-bulk_extractor\` folder into `<X-Ways install>\xtensions\`. The DLL resolves the bundled BE binary relative to its own directory (`GetModuleFileNameW`), so the `bulk_extractor64.exe` sitting next to it is found automatically.

## Why we extract instead of using `XWF_Mount`

X-Ways v21.1 Beta 2 added `XWF_Mount` / `XWF_Unmount` (drive-letter mount of the volume snapshot, designed exactly to avoid the WriteFile-per-item pattern this X-Tension uses). Reviewed 2026-05-13 — **not a fit for bulk_extractor**, kept for the record so this doesn't get re-evaluated every release:

- BE's only "scope" knob is the path it's pointed at. `-R` walks every file under that path. Pointing BE at a mounted whole snapshot scans everything, not just the analyst's selection — undoing the selected-items semantics this X-Tension exists for.
- Restoring selection semantics on top of Mount would require either (a) per-file BE invocations, which loses BE's parallel scanning advantages on a single big disk, or (b) post-hoc path-based filtering of BE output, which loses the `xwitem_<itemID>_` ID-embedding trick that maps hits back to X-Ways item IDs.
- BE-on-active-EO mode already operates directly on the `.E01`/`.dd` — Mount adds nothing there.

Net: the export pattern's WriteFile cost is real but the selection-fidelity + ID-mapping wins outweigh it for BE specifically — Mount is the right tool for wrappers around single-path scanners (hindsight, plaso, ual-timeliner, capa, yara), not for selection-scoped ones like this.

## Current limitations

See [ROADMAP.md](ROADMAP.md) for the planned work behind these.

- **No in-DLL Cancel button.** BE runs in a new console window (`CREATE_NEW_CONSOLE`) so the analyst sees BE's own progress prints; to cancel, close the console window or kill the process. (Since v0.3.0 the X-Ways main window no longer freezes during a run — the wait loop pumps messages — but there is still no in-DLL Cancel.)
- **Source-path mode only works for image-backed EOs.** Physical-disk EOs return a model+ID string from `XWF_GetEvObjProp` property 9, not a path. The radio is disabled in that case; use "Pick file or directory" with the device path manually.
- **Tag-source-items is selected-items-mode only.** Other modes have no usable mapping from BE's offset paths back to X-Ways item IDs.
- **No pre-flight check that the output dir is empty.** BE will refuse to run if the dir already contains a BE run; analyst sees the error in the BE console and re-runs with a different dir.

## References

- **X-Tension API** — the authoritative `X-Tension.h` header and function docs at [x-ways.net/forensics/x-tensions](https://www.x-ways.net/forensics/x-tensions/). All `XWF_*` calls used here are verified against it.
- Entry points / action codes, `XWF_GetEvObjProp` property numbers (9 = source notation, 12 = working dir), and the `hMainWnd`-parented Win32 dialog pattern follow the conventions documented in the author's X-Ways X-Tension project notes.

## Upstream

- [bulk_extractor on GitHub](https://github.com/simsong/bulk_extractor)
- [v2.0.0 Windows binary zip (digitalcorpora S3)](https://digitalcorpora.s3.amazonaws.com/downloads/bulk_extractor/bulk_extractor-2.0.0-windows.zip)
- [digitalcorpora announcement](https://digitalcorpora.org/2023/03/26/compiled-bulk_extractor-2-0-ready-for-download/)

# bulk_extractor X-Tension

Wraps Simson Garfinkel's [bulk_extractor](https://github.com/simsong/bulk_extractor) as an X-Ways Forensics X-Tension. Exposes a settings dialog (parented to X-Ways' main window), runs `bulk_extractor64.exe` (Windows) **or `bulk_extractor` via WSL** against the chosen input, and (optionally) feeds the output back into X-Ways.

> **Status: 0.5.0 — first stable release.** Exercised end-to-end on real cases, including a 110,000-item selected-items run and both native and WSL bulk_extractor 2.2.0 binaries. Known gaps are listed under [Current limitations](#current-limitations); the release history is in [CHANGELOG.md](CHANGELOG.md).

## What's in the dialog

- **Input source** — radio: active EO source image / external file or directory / selected items in directory browser. The active-EO radio auto-disables (with a hint explaining *why*) when the active EO doesn't expose a parseable source path — common for physical-disk EOs which return `model+ID` from `XWF_GetEvObjProp` property 9 instead of a path. The raw property-9 value is logged to the X-Ways messages window every run for diagnosis.
- **Output directory** — defaults to `<case dir>\bulk_extractor_<timestamp>` (or `%TEMP%\...` if no case is open).
- **bulk_extractor binary** — auto-filled with the bundled binary path; overridable here, or via `bulk_extractor.cfg` `be_binary=...`.
- **Threads (-j)** — dropdown listing 1..N where N = system cores; default selected = max(1, N/2) so the analyst keeps headroom for X-Ways and the OS while BE is grinding.
- **Max recursion (-M)** — defaults to 12 (BE's own default).
- **Scanners** — one checkbox per scanner **reported by the selected binary** (`bulk_extractor -h`; 37 for BE 2.2.0, 4 columns, alphabetical down each column), pre-checked to that binary's own defaults, tooltips from `-H`. "Reset to defaults" restores them. The X-Tension only emits `-e` / `-x` for scanners that diverge from the binary's defaults, so the cmdline stays readable and a flag is never sent for a scanner the binary doesn't know. Title reads "Scanners (built-in list)" if the probe failed, "Scanners (discovering…)" while a WSL probe runs.
- **Extra arguments** — appended verbatim after the scanner flags and `-R`, before the input path; for `-S` options, `--dedupe-mode`, `-f`/`-F` find patterns, and future flags. Run warns about `-o/-e/-x/-R/-j/-M` collisions.
- **Output handling** — four checkboxes:
  - Add output dir as evidence (default on).
  - Open in Explorer when done.
  - Label scanned source items `BE scanned` (selected-items mode only, default on) — every successfully exported item gets the label, so even partial runs leave an audit trail.
  - Label items with feature hits per scanner — `BE: email`, `BE: net`, `BE: vin`, … (selected-items mode only, default on) — subset of "scanned" where bulk_extractor found ≥1 feature; mapped via the `xwitem_<itemID>_` token in the temp filenames.

## Inputs

Three input modes, picked in the dialog:

1. **Active evidence object's source image** — resolved via `XWF_GetEvObjProp(hEvidence, 9, ...)`. Works for image-backed evidence (`.E01`, `.dd`, etc.); does not work for physical-disk evidence (`XWF_GetEvObjProp` returns the model+ID rather than a path). The dialog disables this radio when no parseable source path is available.
2. **Pick file or directory** — standard Win32 file/folder pickers.
3. **Use selected items in directory browser** — invoked via right-click → Run X-Tension. Selected items are exported to a temp dir as `xwitem_<itemID>_<safe_leaf>.bin`, BE runs on the temp dir with `-R`, then we walk feature files looking for the `xwitem_NNN_` token to map hits back to source item IDs.

## Outputs

Three checkboxes in the dialog (default = first only):

- **Add output directory to X-Ways case as evidence object** — calls `XWF_CreateEvObj(nType=3, ...)` (Directory). Lets X-Ways index the feature files alongside the rest of the case.
- **Open output folder in Explorer when done** — `ShellExecuteW`.
- **Label scanned source items** (selected-items mode only) — every successfully exported item gets the label `BE scanned` at export time. Audit trail of "what did we run BE on, when".
- **Label items with feature hits** (selected-items mode only) — items whose exported temp file appears in a feature file get one label per scanner that hit (`BE: email`, `BE: net`, …). Subset of "scanned".

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

The ~97 MB binary is **not included in this repo or its releases** — download
it once from upstream. Since **v2.2.0**
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

# Keep the selected-items export temp dir after a successful BE run.
# Default behaviour is to auto-delete on BE-success (since the temp dir holds
# full-byte copies of the selected items — sensitive content + accumulating
# disk usage). Set this to true if you want to inspect the exported
# xwitem_*.bin files post-run (e.g. to cross-check BE feature hits against
# the raw bytes).
keep_temp_dir=false

# Scanner toggles by NAME, only where they differ from the selected
# binary's own defaults (written by Ctrl+Run). Unknown names are ignored.
scanners_enable=base16,wordlist
scanners_disable=vcard_carved

# Free-form extra bulk_extractor options (spliced before the input path)
extra_args=-S jpeg_carve_mode=2
```

## bulk_extractor 2.2.0 compatibility (verified 2026-08-19)

Verified against the official v2.2.0 Windows release binary (SHA256-checked
against the published `SHA256SUMS`), exercised directly rather than trusting
the release notes:

- **Scanner set**: all 35 pre-2.2.0 scanners unchanged (defaults included —
  `base16` still exists, still default-off). Two additions, both default-on:
  `vin` and `rtti`, so the checklist shows 37. Per `-H`, each new scanner's
  feature name equals its scanner name (`vin.txt` confirmed live with test
  VINs), so hit labels come out as `BE: vin` / `BE: rtti`. The checklist is
  read from the binary at dialog open, so this required no scanner-table edit.
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

## Setting up bulk_extractor in WSL

Optional, and **not the recommended path**. bulk_extractor 2.2.0 ships an official Windows binary with native E01 and raw-device support — use that (it is what the X-Tension bundles and resolves by default). WSL support predates the Windows binary and is kept because it already exists and works; it only makes sense if you prefer a distro-packaged or self-built BE. The X-Tension auto-detects whatever BE the analyst has installed in WSL — nothing is bundled or pre-built for it.

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

## Why we extract instead of using `XWF_Mount`

X-Ways v21.1 Beta 2 added `XWF_Mount` / `XWF_Unmount` (drive-letter mount of the volume snapshot, designed exactly to avoid the WriteFile-per-item pattern this X-Tension uses). Reviewed 2026-05-13 — **not a fit for bulk_extractor**, kept for the record so this doesn't get re-evaluated every release:

- BE's only "scope" knob is the path it's pointed at. `-R` walks every file under that path. Pointing BE at a mounted whole snapshot scans everything, not just the analyst's selection — undoing the selected-items semantics this X-Tension exists for.
- Restoring selection semantics on top of Mount would require either (a) per-file BE invocations, which loses BE's parallel scanning advantages on a single big disk, or (b) post-hoc path-based filtering of BE output, which loses the `xwitem_<itemID>_` ID-embedding trick that maps hits back to X-Ways item IDs.
- BE-on-active-EO mode already operates directly on the `.E01`/`.dd` — Mount adds nothing there.

Net: the export pattern's WriteFile cost is real but the selection-fidelity + ID-mapping wins outweigh it for BE specifically — Mount is the right tool for wrappers around single-path scanners (hindsight, plaso, ual-timeliner, capa, yara), not for selection-scoped ones like this.

## Known issues

### bulk_extractor exit 6 "Disk write error ... Disk is probably full" on directory scans (Windows)

**Upstream bug, mitigated here since v0.5.0.** bulk_extractor names every
carved file after the forensic path, and `feature_recorder.cpp` strips the
directory part with `rfind('/')` — forward slash only. On Windows the recursed
path uses backslashes, so in `-R` (directory) mode the carved-file name embeds
the *entire* input path. `<output dir>\<carver>_carved\000\<that name>` runs
past `MAX_PATH`, the open fails, and BE aborts with exit 6 and the misleading
"disk full" message the moment any carver fires. Reproduced 2026-08-21 on a
5,446-file selected-items export with BE 2.2.0 (`alerts.txt` in the output dir
records the exact `cannot open file for writing: ...` path).

Mitigation: in native mode the X-Tension spawns bulk_extractor with its
**working directory set to the input** and passes a **relative** input path
(`.` for a directory, the bare file name otherwise). Because BE embeds the
input path exactly as given, the prefix inside every carved filename collapses
from the full path to two characters. Measured on BE 2.2.0, same corpus and
scanners:

| input passed to BE | longest carved name |
| --- | --- |
| `-R C:\tmp\nametest\in` | `C__tmp_nametest_in_xwitem_0__MFT.bin____-24576.mft` (50) |
| working dir + `-R .` | `._xwitem_0__MFT.bin____-24576.mft` (33) |

Exit code, feature-file contents and the `xwitem_<id>` mapping token are
unchanged, and BE writes nothing into the working directory. The one cost is
that BE's own `report.xml` records `<image_filename>` as the relative path, so
the X-Tension logs the absolute input next to the command line.

Verified at scale 2026-08-23 on a 110,806-file directory scan: **0 disk-write
exceptions**, longest carved path 203 characters (56 under the limit). Note the
worst case is not `evtx_carved` but `zip_carved`, which appends the path *inside
the archive* to the carved name (`…-ZIP-0_tools_chocolateyInstall_helpers_…`) —
that suffix is bounded only by BE's `zip_name_len_max` (default 1024), so a
deeply-nested archive entry remains the one shape that could still exceed
`MAX_PATH`. The export budget below assumes a ~40-character suffix, which is the
evtx worst case, not the zip one; the headroom the relative input buys is what
covers the difference.

Belt and braces: the output directory is still passed in 8.3 short form, and
exported temp-file leaf names are still capped — but the cap is now computed
against the *relative* input, so it lands around 70 characters instead of 26
and effectively never truncates a real filename. The case-facing paths
(evidence object, labels, Open output) stay long throughout. A one-line
upstream fix (`find_last_of("/\\")`) would remove the need for any of this;
not yet reported upstream.

## Current limitations

- **bulk_extractor still runs in its own console window.** BE is spawned with `CREATE_NEW_CONSOLE` so the analyst can watch its progress prints. Cancel works from the dialog (v0.5.0 terminates the child within ~100 ms), but BE's output is not yet captured into the dialog itself. Closing that console window out from under a run kills BE — the exit code is reported as `0xC000013A` with a hint saying so.
- **Source-path mode only works for image-backed EOs.** Physical-disk EOs return a model+ID string from `XWF_GetEvObjProp` property 9, not a path. The radio is disabled in that case; use "External file or directory" with the device path entered manually.
- **Labelling is selected-items-mode only.** Other modes have no usable mapping from BE's offset-based forensic paths back to X-Ways item IDs.
- **No pre-flight check that a manually-typed output dir is empty.** The auto-suggested directory is re-stamped on every Run, so the default path is always fresh. A custom path is not checked — and note BE 2.2.0 does not refuse a reused directory the way older versions did: its restart logic sees the finished `report.xml` and exits 0 having silently processed nothing.

## References

- **X-Tension API** — the authoritative `X-Tension.h` header and function docs at [x-ways.net/forensics/x-tensions](https://www.x-ways.net/forensics/x-tensions/). All `XWF_*` calls used here are verified against it.
- Entry points / action codes, `XWF_GetEvObjProp` property numbers (9 = source notation, 12 = working dir), and the `hMainWnd`-parented Win32 dialog pattern follow the conventions documented in the author's X-Ways X-Tension project notes.

## Upstream

- [bulk_extractor on GitHub](https://github.com/simsong/bulk_extractor)
- [v2.0.0 Windows binary zip (digitalcorpora S3)](https://digitalcorpora.s3.amazonaws.com/downloads/bulk_extractor/bulk_extractor-2.0.0-windows.zip)
- [digitalcorpora announcement](https://digitalcorpora.org/2023/03/26/compiled-bulk_extractor-2-0-ready-for-download/)

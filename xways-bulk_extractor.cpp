// =============================================================================
//  bulk_extractor — wraps Simson Garfinkel's bulk_extractor as an X-Tension.
//
//  Three input modes (chosen in the settings dialog):
//    1. Active evidence object's source image  — resolved via
//       XWF_GetEvObjProp(hEvidence, 9, ...) which returns "[D:\path\foo.E01]"
//       for image-backed evidence. Bracket-stripped, then existence-checked.
//       Physical-disk evidence (no parseable source path) falls through with
//       an error asking the analyst to pick a path manually.
//    2. Pick file or directory                 — Win32 file/folder pickers.
//    3. Use selected items in directory browser — selected items are exported
//       to a unique temp dir as `xwitem_<itemID>_<safe_leaf>.bin`, BE runs
//       on the temp dir (-R), then we walk feature files looking for the
//       `xwitem_NNN_` token to map hits back to item IDs.
//
//  Three output integrations (toggleable, default = first only):
//    - Add the output directory to the X-Ways case as a Directory-typed
//      evidence object via XWF_CreateEvObj(nType=3, ...).
//    - Open output folder in Explorer when done (ShellExecuteW).
//    - Tag source items that had any feature hit via XWF_AddToReportTable
//      (selected-items mode only — only mode where temp→itemID mapping exists).
//
//  Bundled BE binary: <dll_dir>\bulk_extractor64.exe (alongside the DLL, per
//    the project deployment convention — see CLAUDE.md + build.bat).
//    Override layers (highest wins): dialog field > sidecar cfg "be_binary=..."
//    > bundled default. New BE builds drop in by replacing the .exe (or by
//    pointing the cfg / dialog at a different location).
//
//  Sidecar cfg (optional): bulk_extractor.cfg next to the DLL. key=value, one
//    per line, # for comments. Recognised keys: be_binary, default_output_dir.
//
//  v1 limitations (documented in README):
//    - BE runs in a new console window (CREATE_NEW_CONSOLE) so progress is
//      visible. No in-DLL progress dialog; cancel = close the console window.
//    - Source-path resolution for "Active evidence object" mode only works
//      for image-backed EOs. Physical disks need explicit path picking.
//
//  References:
//    docs/xtension-invocation.md          — entry points, action codes, sidecar
//    docs/xways-getprop-reference.md      — property 9 = source notation;
//                                            property 12 = working dir
//    docs/xways-user-input-and-dialogs.md — Win32 dialog parented to hMainWnd
//    references/api/XWF_API-source-2024-05-31/src/X-Tension.h — SDK signatures
// =============================================================================

#include <windows.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <commctrl.h>
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cwctype>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "resource.h"

// v0.4.0: helper-exe identity verification reads the PE VERSIONINFO resource.
#pragma comment(lib, "Version.lib")

// --- Identity ---------------------------------------------------------------
static const wchar_t* NAME         = L"bulk_extractor";
static const wchar_t* VERSION      = L"0.5.0-beta";
static const wchar_t* DESCRIPTION  = L"Run bulk_extractor on an image, path, or selected items; ingest results.";
static const wchar_t* REPORT_TABLE_SCANNED = L"bulk_extractor scanned";
static const wchar_t* REPORT_TABLE_HITS    = L"bulk_extractor hits";

// Per project convention: VERBOSE on during development. Flip before sharing.
static constexpr bool VERBOSE = true;

// --- Helper-exe identity verification (v0.4.0) -----------------------------
//   Case-insensitive substring we require in the resolved native binary's PE
//   VERSIONINFO or `--version` banner before we'll spawn it with the BE CLI
//   shape (-o / -e / -x / -R). WSL mode is exempt — the Linux binary can't be
//   inspected from the Windows side (same exemption the FileExists gate makes).
static const wchar_t* kHelperIdentityNeedle = L"bulk_extractor";

// --- Ctrl-to-save / flash-rejection dialog state (v0.4.0) ------------------
//   g_runCtrlDown is polled every 100 ms via kCtrlPollTimerId so the Run /
//   Cancel button labels + Run's blue tint track the Ctrl key without focus
//   tricks. kHelperFlashTimerId drives the bold-red rejection flash on the
//   IDC_STATIC_BE_STATUS line (~2 s of alternating bright/dark red, then
//   solid red until a valid Browse pick clears it).
static constexpr UINT_PTR kCtrlPollTimerId    = 0xBE10;
static constexpr UINT_PTR kHelperFlashTimerId = 0xBE12;
static constexpr int      kHelperFlashTickCount = 8;   // ~2 s at 250 ms
static bool               g_runCtrlDown        = false;

// --- XT_Prepare nOpType (canonical per X-Tension.h:422-427) ----------------
enum : DWORD {
    XT_ACTION_RUN = 0,
    XT_ACTION_RVS = 1,
    XT_ACTION_LSS = 2,
    XT_ACTION_PSS = 3,
    XT_ACTION_DBC = 4,
    XT_ACTION_SHC = 5,
};

// --- bulk_extractor scanners (defaults verified against BE 2.2.0 `-h`) -----
//   List + default states re-verified 2026-08-19 against the official 2.2.0
//   Windows binary: all pre-2.2.0 entries unchanged; 2.2.0 added `rtti` and
//   `vin` (both enabled by default upstream). Caveat: BE hard-errors on -e/-x
//   with a name it doesn't know ("no such scanner", exit 5, verified), so
//   UNchecking a 2.2.0-only scanner while running a pre-2.2.0 BE fails the
//   run — loudly and self-explanatorily, hence no version-gating here.
//   Order = the order they appear in the dialog (3 columns x ceil(N/3) rows).
//   defaultEnabled flag drives both initial dialog state and the -e/-x logic
//   in RunBulkExtractor (we only emit a flag when the user diverges from the
//   default — keeps cmdlines short and matches BE's expectation that
//   unflagged = default).
struct ScannerInfo {
    const wchar_t* name;
    bool           defaultEnabled;
    const wchar_t* tip;   // tooltip — description per `bulk_extractor -H` (2.2.0)
};

static const ScannerInfo kScanners[] = {
    {L"accts",          true , L"Scans for credit card numbers, track-2 data, PII (SSN, Canadian SIN) and phone numbers"},
    {L"aes",            true , L"Searches for AES key schedules (128/192/256-bit keys in memory or swap)"},
    {L"base16",         false, L"Base16 (hex-encoded) data scanner"},
    {L"base64",         true , L"Scans for Base64-encoded data and recurses into it"},
    {L"elf",            true , L"Finds ELF (Linux/Unix executable) headers"},
    {L"email",          true , L"Scans for email addresses, domains, URLs, RFC822 headers, etc."},
    {L"evtx",           true , L"Scans for Windows EVTX chunks and carves valid EVTX files"},
    {L"exif",           true , L"Searches for EXIF sections in JPEGs; also carves JPEG files (must be enabled for JPEG carving)"},
    {L"facebook",       true , L"Searches for Facebook HTML and JSON tags"},
    {L"find",           true , L"Simple search for user-supplied patterns (-f / -F)"},
    {L"gps",            true , L"Garmin trackpoint XML / GPS coordinates"},
    {L"gzip",           true , L"Searches for GZIP-compressed data and recurses into it"},
    // Note (v0.2.15): `hex` is NOT a BE scanner — verified against
    // `bulk_extractor64.exe -h` (BE 2.0.2). It's a feature-file output
    // channel that multiple scanners write hex-encoded content to. v0.2.14
    // mistakenly listed it as a scanner; reverted here. The
    // FeatureToScanner mapping still has an entry for "hex" so the label
    // stays meaningful when BE produces hex.txt.
    {L"hiberfile",      false, L"Scans for Microsoft XPress-compressed data (hiberfil.sys). Off by default"},
    {L"httplogs",       true , L"Extracts web-server access-log fragments"},
    {L"json",           true , L"Scans for JSON-encoded data"},
    {L"kml_carved",     true , L"Scans for and carves KML (Google Earth) files"},
    {L"msxml",          true , L"Extracts text from Microsoft Office XML files"},
    {L"net",            true , L"Scans for IP packets: URLs, domains, IPs, MACs, TCP (also feeds url/domain/ip feature files)"},
    {L"ntfsindx",       true , L"Scans for NTFS $INDEX_ALLOCATION (INDX) records"},
    {L"ntfslogfile",    true , L"Scans for NTFS $LogFile RCRD records"},
    {L"ntfsmft",        true , L"Scans for NTFS MFT records"},
    {L"ntfsusn",        true , L"Scans for USN_RECORD v2/v4 change-journal records"},
    {L"outlook",        false, L"Outlook compressible encryption. Very CPU intensive -- off by default"},
    {L"pdf",            true , L"Extracts text from PDF files"},
    {L"rar",            true , L"RAR volume locator and component decompresser"},
    {L"rtti",           true , L"Carves 8-bit RawTherapee thumbnail images (BE 2.2.0+)"},   // BE 2.2.0+: RawTherapee 8-bit thumbnail carver
    {L"sqlite",         true , L"Scans for and carves SQLite3 databases"},
    {L"utmp",           true , L"Scans for utmp/wtmp login records"},
    {L"vcard_carved",   true , L"Scans for and carves vCard data"},
    {L"vin",            true , L"Scans for Vehicle Identification Numbers (BE 2.2.0+)"},   // BE 2.2.0+: Vehicle Identification Numbers
    {L"windirs",        true , L"Scans Microsoft directory structures (FAT32 / exFAT entries)"},
    {L"winlnk",         true , L"Searches for Windows LNK (shortcut) files"},
    {L"winpe",          true , L"Scans for Windows PE (executable) headers"},
    {L"winprefetch",    true , L"Searches for Windows Prefetch files"},
    {L"wordlist",       false, L"Builds a word list from all text found (for password cracking). Off by default"},
    {L"xor",            false, L"Optimistic XOR de-obfuscator. Off by default"},
    {L"zip",            true , L"Scans for ZIP archives and components and recurses into them"},
};
static constexpr int kNumScanners = sizeof(kScanners) / sizeof(kScanners[0]);

// --- XWF_CreateEvObj nType values (per live API page) ----------------------
enum : DWORD {
    EVOBJ_TYPE_FILE      = 0,
    EVOBJ_TYPE_IMAGE     = 1,
    EVOBJ_TYPE_MEMDUMP   = 2,
    EVOBJ_TYPE_DIRECTORY = 3,
    EVOBJ_TYPE_DISK      = 4,
};

// --- XWF_AddToReportTable nFlags (per xwf-api-rs `AddReportTableFlags`) ----
//   bit 0x01 marks the label as "created by the application" rather than
//   "created by the examiner" — the right semantic for an automated tool
//   that's auto-tagging items. Visually distinct in X-Ways' Labels picker.
enum : DWORD {
    REPORT_TABLE_FLAG_CREATED_BY_APP = 0x01,
};

// --- Function pointer typedefs ---------------------------------------------
typedef VOID   (__stdcall *pfn_XWF_OutputMessage)(const wchar_t*, DWORD);
typedef DWORD  (__stdcall *pfn_XWF_GetItemCount)(LPVOID);
typedef const wchar_t* (__stdcall *pfn_XWF_GetItemName)(LONG);
typedef LONG   (__stdcall *pfn_XWF_GetItemParent)(LONG);
typedef INT64  (__stdcall *pfn_XWF_GetItemSize)(LONG);
typedef VOID   (__stdcall *pfn_XWF_GetVolumeName)(HANDLE, wchar_t*, DWORD);
typedef BOOL   (__stdcall *pfn_XWF_AddToReportTable)(LONG, const wchar_t*, DWORD);
typedef BOOL   (__stdcall *pfn_XWF_Label)(LONG, const wchar_t*, DWORD); // 21.7 SR-4+ rename
typedef HANDLE (__stdcall *pfn_XWF_OpenItem)(HANDLE, LONG, DWORD);
typedef VOID   (__stdcall *pfn_XWF_Close)(HANDLE);
typedef DWORD  (__stdcall *pfn_XWF_Read)(HANDLE, INT64, BYTE*, DWORD);
typedef INT64  (__stdcall *pfn_XWF_GetEvObjProp)(HANDLE, DWORD, PVOID);
typedef INT64  (__stdcall *pfn_XWF_GetCaseProp)(LPVOID, LONG, PVOID, LONG);
typedef HANDLE (__stdcall *pfn_XWF_CreateEvObj)(DWORD, LONG, LPWSTR, PVOID);
typedef HANDLE (__stdcall *pfn_XWF_GetEvObj)(DWORD);
typedef INT64  (__stdcall *pfn_XWF_GetProp)(HANDLE, DWORD, PVOID);
typedef HANDLE (__stdcall *pfn_XWF_OpenEvObj)(HANDLE, DWORD);
typedef VOID   (__stdcall *pfn_XWF_CloseEvObj)(HANDLE);

static pfn_XWF_OutputMessage    XWF_OutputMessage    = nullptr;
static pfn_XWF_GetItemCount     XWF_GetItemCount     = nullptr;
static pfn_XWF_GetItemName      XWF_GetItemName      = nullptr;
static pfn_XWF_GetItemParent    XWF_GetItemParent    = nullptr;
static pfn_XWF_GetItemSize      XWF_GetItemSize      = nullptr;
static pfn_XWF_GetVolumeName    XWF_GetVolumeName    = nullptr;
static pfn_XWF_AddToReportTable XWF_AddToReportTable = nullptr;
static pfn_XWF_Label            XWF_Label            = nullptr;
static pfn_XWF_OpenItem         XWF_OpenItem         = nullptr;
static pfn_XWF_Close            XWF_Close            = nullptr;
static pfn_XWF_Read             XWF_Read             = nullptr;
static pfn_XWF_GetEvObjProp     XWF_GetEvObjProp     = nullptr;
static pfn_XWF_GetCaseProp      XWF_GetCaseProp      = nullptr;
static pfn_XWF_CreateEvObj      XWF_CreateEvObj      = nullptr;
static pfn_XWF_GetEvObj         XWF_GetEvObj         = nullptr;
static pfn_XWF_GetProp          XWF_GetProp          = nullptr;
static pfn_XWF_OpenEvObj        XWF_OpenEvObj        = nullptr;
static pfn_XWF_CloseEvObj       XWF_CloseEvObj       = nullptr;

// HMODULE for our own DLL — captured in DllMain. Used to resolve paths
// relative to the DLL (sidecar cfg + bundled BE binary).
static HMODULE g_hSelf     = nullptr;
static HWND    g_hMainWnd  = nullptr;

// --- In-DLL Cancel / worker-thread state (v0.5.0) --------------------------
//   The settings dialog hosts the bulk_extractor run on a JOINABLE
//   std::thread (g_workerThread) reaped in WM_APP_DONE and, as a safety net,
//   in XT_Done -- the DLL can never unload with the worker alive. These
//   atomics bridge the X-Ways UI thread and the worker. g_dlgHwnd is the
//   PostMessage target (null when no dialog is up -> the Post helpers
//   no-op). g_workerActive blocks WM_CLOSE while running and
//   gates the Ctrl-to-save poll. g_cancelRequested is the cooperative-abort
//   flag: IDCANCEL sets it during a run; the worker's 100 ms wait loop sees
//   it, TerminateProcess()es the BE child (the worker owns the process
//   handle, so there is no cross-thread handle-lifetime race), and unwinds
//   through WM_APP_DONE code 1.
//   THREADING GATE (P1): the worker runs ONLY the subprocess phase
//   (ExecuteBeRun) -- every XWF_* call stays on X-Ways' own thread: input
//   prep (item extraction + tag-scanned labels) in IDOK before the worker
//   starts, post-processing (CreateEvObj + Label tagging + temp cleanup) in
//   the WM_APP_DONE handler after it finishes. kElapsedTimerId drives the 1 s
//   "Running... mm:ss" status clock (distinct from kCtrlPollTimerId 0xBE10 /
//   kHelperFlashTimerId 0xBE12).
static constexpr UINT_PTR  kElapsedTimerId = 0xBE14;
static std::atomic<bool>   g_workerActive{false};
static std::atomic<bool>   g_cancelRequested{false};
static std::thread         g_workerThread;   // joinable; see comment above
static HWND                g_dlgHwnd = nullptr;
static ULONGLONG           g_runStartTick = 0;

// SEH-protected wide-string copy from a foreign pointer. Pure POD locals so
// MSVC doesn't reject __try with C2712 (no C++ object unwinding required).
// Returns chars copied (excluding terminator), or -1 on AV / bad pointer.
static int SafeWcsCopyFromPtr(INT64 rv, wchar_t* dst, size_t maxChars) {
    if (rv <= 0x10000 || rv >= 0x7FFFFFFFFFFFLL || maxChars == 0) return -1;
    __try {
        const wchar_t* src = (const wchar_t*)(uintptr_t)rv;
        size_t i = 0;
        while (i < maxChars - 1 && src[i] != L'\0') { dst[i] = src[i]; ++i; }
        dst[i] = L'\0';
        return (int)i;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (maxChars > 0) dst[0] = L'\0';
        return -1;
    }
}

// Forward declarations for the WSL detection / path-translation helpers
// (definitions live further down near RunBulkExtractor; used earlier by
// the WM_INITDIALOG / WM_COMMAND handlers).
struct WslInfo {
    bool wsl_present  = false;
    bool be_available = false;
    std::wstring be_path;
    std::wstring be_version;
};
static const WslInfo& DetectWslOnce();
static std::wstring   WindowsPathToWsl(const std::wstring& win);
static std::wstring   WslUncToLinuxPath(const std::wstring& win);

// --- Logging helpers --------------------------------------------------------
//   Log()        — important info (run start, errors, summary tallies). Goes
//                  to the X-Ways Messages window where the analyst always sees
//                  it.
//   LogVerbose() — per-item progress. v0.2.3 routes these to the **Output
//                  window** via OutputMessage flag 0x08 (added v20.6) so the
//                  Messages window stays clean. Falls back gracefully on
//                  older X-Ways builds — the flag is just ignored.
static void Log(const std::wstring& m) {
    std::wstring s = L"["; s += NAME; s += L"] "; s += m;
    if (XWF_OutputMessage) XWF_OutputMessage(s.c_str(), 0);
}
static void LogVerbose(const std::wstring& m) {
    if (!VERBOSE) return;
    std::wstring s = L"["; s += NAME; s += L"] "; s += m;
    if (XWF_OutputMessage) XWF_OutputMessage(s.c_str(), 0x08);
}

// --- Worker -> dialog bridge (PostMessage only) -----------------------------
//   Guarded on g_dlgHwnd (null when no dialog is up -> no-op).
//   WM_APP_STATUS takes ownership of a heap wchar_t* the handler delete[]s.
static void PostWorkerStatus(const std::wstring& text) {
    if (!g_dlgHwnd) return;
    wchar_t* buf = new wchar_t[text.size() + 1];
    wmemcpy(buf, text.c_str(), text.size() + 1);
    PostMessageW(g_dlgHwnd, WM_APP_STATUS, 0, (LPARAM)buf);
}

// code: 0 = ok, 1 = cancelled, 2 = failed.
static void PostWorkerDone(int code) {
    if (g_dlgHwnd) PostMessageW(g_dlgHwnd, WM_APP_DONE, (WPARAM)code, 0);
}

template <typename T>
static T Resolve(HMODULE h, const char* name, int& missing) {
    T p = reinterpret_cast<T>(GetProcAddress(h, name));
    if (!p) ++missing;
    return p;
}

static int RetrieveFunctionPointers() {
    HMODULE h = GetModuleHandleW(nullptr);
    int n = 0;
    XWF_OutputMessage    = Resolve<pfn_XWF_OutputMessage   >(h, "XWF_OutputMessage", n);
    XWF_GetItemCount     = Resolve<pfn_XWF_GetItemCount    >(h, "XWF_GetItemCount", n);
    XWF_GetItemName      = Resolve<pfn_XWF_GetItemName     >(h, "XWF_GetItemName", n);
    XWF_GetItemParent    = Resolve<pfn_XWF_GetItemParent   >(h, "XWF_GetItemParent", n);
    XWF_GetItemSize      = Resolve<pfn_XWF_GetItemSize     >(h, "XWF_GetItemSize", n);
    XWF_GetVolumeName    = Resolve<pfn_XWF_GetVolumeName   >(h, "XWF_GetVolumeName", n);
    XWF_AddToReportTable = Resolve<pfn_XWF_AddToReportTable>(h, "XWF_AddToReportTable", n);
    // XWF_Label is OPTIONAL — 21.7 SR-4+ rename of XWF_AddToReportTable.
    // Do NOT count it as missing; plain GetProcAddress, no missing counter.
    XWF_Label = reinterpret_cast<pfn_XWF_Label>(GetProcAddress(h, "XWF_Label"));
    XWF_OpenItem         = Resolve<pfn_XWF_OpenItem        >(h, "XWF_OpenItem", n);
    XWF_Close            = Resolve<pfn_XWF_Close           >(h, "XWF_Close", n);
    XWF_Read             = Resolve<pfn_XWF_Read            >(h, "XWF_Read", n);
    XWF_GetEvObjProp     = Resolve<pfn_XWF_GetEvObjProp    >(h, "XWF_GetEvObjProp", n);
    XWF_GetCaseProp      = Resolve<pfn_XWF_GetCaseProp     >(h, "XWF_GetCaseProp", n);
    XWF_CreateEvObj      = Resolve<pfn_XWF_CreateEvObj     >(h, "XWF_CreateEvObj", n);
    XWF_GetEvObj         = Resolve<pfn_XWF_GetEvObj        >(h, "XWF_GetEvObj", n);
    XWF_GetProp          = Resolve<pfn_XWF_GetProp         >(h, "XWF_GetProp", n);
    XWF_OpenEvObj        = Resolve<pfn_XWF_OpenEvObj       >(h, "XWF_OpenEvObj", n);
    XWF_CloseEvObj       = Resolve<pfn_XWF_CloseEvObj      >(h, "XWF_CloseEvObj", n);
    return n;
}

// --- Path / string helpers --------------------------------------------------
static std::wstring GetSelfDirectory() {
    wchar_t path[MAX_PATH] = {0};
    GetModuleFileNameW(g_hSelf, path, MAX_PATH);
    wchar_t* lastSlash = wcsrchr(path, L'\\');
    if (lastSlash) *lastSlash = L'\0';
    return std::wstring(path);
}

static bool FileExists(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}
static bool DirExists(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY);
}

static std::wstring TrimW(const std::wstring& s) {
    size_t lo = 0, hi = s.size();
    while (lo < hi && iswspace(s[lo])) ++lo;
    while (hi > lo && iswspace(s[hi - 1])) --hi;
    return s.substr(lo, hi - lo);
}

// X-Ways hands back some paths in Win32 extended form ("\\?\C:\..." /
// "\\?\UNC\server\share\...") — observed from XWF_GetCaseProp(6, case dir)
// and XWF_GetProp(vol, 8, EO file-path) on a CLI-created case (2026-08-19,
// 21.8 SR-5). Functional, but ugly in the dialog fields and unnecessary
// below MAX_PATH — strip the prefix from paths we display or build on.
static std::wstring StripExtendedPathPrefix(std::wstring s) {
    if (s.rfind(L"\\\\?\\UNC\\", 0) == 0)  return L"\\\\" + s.substr(8);
    if (s.rfind(L"\\\\?\\", 0) == 0)       return s.substr(4);
    return s;
}

// v0.5.0: the status line is an owner-drawn static (the bottom progress bar),
// so setting its text must also invalidate it — SetDlgItemText alone doesn't
// repaint an SS_OWNERDRAW control reliably. All status writes go through here.
static void SetBeStatus(HWND hDlg, const wchar_t* text) {
    SetDlgItemTextW(hDlg, IDC_STATIC_BE_STATUS, text ? text : L"");
    HWND h = GetDlgItem(hDlg, IDC_STATIC_BE_STATUS);
    if (h) InvalidateRect(h, nullptr, FALSE);
}

// Convert UTF-8 to wide.
static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int wlen = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(wlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), wlen);
    return w;
}

// Replace anything not [A-Za-z0-9._-] with '_' (for safe temp filenames).
static std::wstring SanitizeForFilename(const std::wstring& s) {
    std::wstring r;
    r.reserve(s.size());
    for (wchar_t c : s) {
        bool ok = (c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z') ||
                  (c >= L'0' && c <= L'9') ||
                  c == L'.' || c == L'_' || c == L'-';
        r.push_back(ok ? c : L'_');
    }
    if (r.empty()) r = L"item";
    return r;
}

// --- Sidecar config ---------------------------------------------------------
//   Optional bulk_extractor.cfg next to the DLL. Recognised keys:
//     be_binary           — override path to bulk_extractor64.exe
//     default_output_dir  — initial value for the output-dir field in the dialog
//     keep_temp_dir       — true/false (default false). When false, the
//                           selected-items export temp dir is auto-deleted on
//                           BE-success. Set to true if you want to inspect
//                           the exported xwitem_*.bin files post-run (useful
//                           when cross-checking BE feature-file hits against
//                           the raw bytes).
struct CfgValues {
    std::wstring be_binary;
    std::wstring default_output_dir;
    bool         keep_temp_dir = false;
    // v0.3.0: WSL.
    bool         use_wsl_default = false;   // pre-checks the "Run via WSL" box on dialog open
    std::wstring wsl_be_binary;              // Linux path override (e.g. /usr/local/bin/bulk_extractor)
};

static CfgValues LoadCfg(const std::wstring& selfDir) {
    CfgValues out;
    std::wstring cfgPath = selfDir + L"\\bulk_extractor.cfg";
    if (!FileExists(cfgPath)) return out;

    std::ifstream f(cfgPath);
    if (!f) return out;

    std::string line;
    while (std::getline(f, line)) {
        // Strip leading whitespace and comments.
        size_t i = 0;
        while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) ++i;
        if (i >= line.size() || line[i] == '#' || line[i] == ';') continue;
        size_t eq = line.find('=', i);
        if (eq == std::string::npos) continue;

        std::string key = line.substr(i, eq - i);
        std::string val = line.substr(eq + 1);
        // Trim
        auto trim = [](std::string& s) {
            size_t lo = 0, hi = s.size();
            while (lo < hi && (s[lo] == ' ' || s[lo] == '\t' || s[lo] == '\r')) ++lo;
            while (hi > lo && (s[hi - 1] == ' ' || s[hi - 1] == '\t' || s[hi - 1] == '\r')) --hi;
            s = s.substr(lo, hi - lo);
        };
        trim(key); trim(val);

        if      (key == "be_binary")          out.be_binary          = Utf8ToWide(val);
        else if (key == "default_output_dir") out.default_output_dir = Utf8ToWide(val);
        else if (key == "wsl_be_binary")      out.wsl_be_binary      = Utf8ToWide(val);
        else if (key == "keep_temp_dir") {
            // Accept yes/true/1/on as truthy; everything else (including
            // empty) keeps the default of "false / auto-clean".
            out.keep_temp_dir = (val == "true" || val == "yes" ||
                                 val == "1"    || val == "on");
        }
        else if (key == "use_wsl") {
            out.use_wsl_default = (val == "true" || val == "yes" ||
                                   val == "1"    || val == "on");
        }
    }
    return out;
}

// Convert wide to UTF-8 (mirror of Utf8ToWide for the cfg writer).
static std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                                  nullptr, 0, nullptr, nullptr);
    std::string s(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                        s.data(), len, nullptr, nullptr);
    return s;
}

// --- Sidecar config writer (v0.4.0) ----------------------------------------
//   Counterpart to LoadCfg. Writes an analyst-friendly `key = value` file with
//   a UTF-8 BOM + CRLF so Notepad opens it cleanly. Persists exactly the keys
//   LoadCfg reads — EXCEPT default_output_dir: per the project output-dir
//   convention the run output is auto-suggested per-run as
//   <caseRoot>\xways-bulk_extractor\bulk_extractor_<stamp>, so pinning a single
//   dir in cfg would defeat the timestamped-subdir scheme (and BE mishandles a
//   reused output dir: pre-2.2.0 refuses loudly; 2.2.0's restart logic exits 0
//   having silently processed nothing). The dialog's scanner toggles /
//   threads / tagging are NOT cfg-backed in LoadCfg, so they're intentionally
//   left out to keep this a faithful round-trip of the existing cfg surface.
//
//   Atomic-ish: any existing cfg is rotated to <path>.bak before the overwrite
//   so a botched write is recoverable.
static bool SaveCfg(const std::wstring& path, const CfgValues& cfg) {
    if (FileExists(path)) {
        std::wstring bak = path + L".bak";
        DeleteFileW(bak.c_str());
        MoveFileW(path.c_str(), bak.c_str());  // preserves timestamps, fast same-volume
    }

    auto bs = [](bool b) -> const wchar_t* { return b ? L"true" : L"false"; };

    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t ts[64];
    swprintf_s(ts, L"%04u-%02u-%02u %02u:%02u:%02u",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    std::wstring o;
    o += L"# bulk_extractor.cfg\r\n";
    o += L"# =============================================================================\r\n";
    o += L"# Auto-managed by the xways-bulk_extractor X-Tension. Values reflect the\r\n";
    o += L"# compiled defaults on first run, then the dialog state on each Ctrl+Run /\r\n";
    o += L"# Ctrl+Close (Save as...). All keys are optional; delete a line to fall back\r\n";
    o += L"# to the compiled default. Edits take effect on the next dialog open.\r\n";
    o += L"# Last written: "; o += ts; o += L"\r\n";
    o += L"# =============================================================================\r\n\r\n";

    o += L"# ----- Native Windows bulk_extractor binary --------------------------------\r\n";
    o += L"# Absolute path to bulk_extractor64.exe. Empty = the X-Tension looks in\r\n";
    o += L"#   <dll-dir>\\bulk_extractor64.exe\r\n";
    o += L"# The resolved binary is identity-verified (PE VERSIONINFO or --version banner\r\n";
    o += L"# must contain \"bulk_extractor\") before it is ever launched.\r\n";
    o += L"be_binary=";  o += cfg.be_binary;  o += L"\r\n\r\n";

    o += L"# ----- WSL bulk_extractor (Linux) ------------------------------------------\r\n";
    o += L"# Linux-side path (e.g. /usr/bin/bulk_extractor) used when 'Run via WSL' is\r\n";
    o += L"# checked. Empty = auto-detected from `wsl -e which bulk_extractor`.\r\n";
    o += L"wsl_be_binary=";  o += cfg.wsl_be_binary;  o += L"\r\n";
    o += L"# Pre-check the 'Run via WSL' box on dialog open (only honored if WSL +\r\n";
    o += L"# bulk_extractor are actually detected).\r\n";
    o += L"use_wsl=";  o += bs(cfg.use_wsl_default);  o += L"\r\n\r\n";

    o += L"# ----- Selected-items temp dir ---------------------------------------------\r\n";
    o += L"# Keep the exported xwitem_*.bin temp dir after a successful run (default\r\n";
    o += L"# false = auto-clean). true/yes/1/on are truthy.\r\n";
    o += L"keep_temp_dir=";  o += bs(cfg.keep_temp_dir);  o += L"\r\n\r\n";

    o += L"# ----- Output directory (NOT persisted) ------------------------------------\r\n";
    o += L"# Per project convention the run output auto-resolves per-run to\r\n";
    o += L"#   <case dir>\\xways-bulk_extractor\\bulk_extractor_<timestamp>\\\r\n";
    o += L"# so it is intentionally not pinned here. Set default_output_dir below only\r\n";
    o += L"# if you want to override that for every run (uncomment + edit).\r\n";
    o += L"# default_output_dir=\r\n";

    FILE* fp = nullptr;
    if (_wfopen_s(&fp, path.c_str(), L"wb") != 0 || !fp) return false;
    const unsigned char bom[] = {0xEF, 0xBB, 0xBF};
    fwrite(bom, 1, 3, fp);
    std::string utf8 = WideToUtf8(o);
    fwrite(utf8.data(), 1, utf8.size(), fp);
    fclose(fp);
    return true;
}

// =============================================================================
//  Helper-exe identity verification (v0.4.0)
// =============================================================================
//   Defense-in-depth: this X-Tension only spawns subprocesses with the
//   bulk_extractor CLI shape (-o / -e / -x / -M / -R). Feeding it some other
//   exe (analyst pointed Browse... at the wrong binary, or a rogue file got
//   dropped in the deploy folder) would invoke that exe with arguments it
//   doesn't understand. We require positive identity evidence before accepting
//   a native-Windows exe as the helper.
//
//   Match logic (OR — either is sufficient):
//     1. PE VERSIONINFO carries the needle in InternalName / OriginalFilename
//        / ProductName / FileDescription.
//     2. `<exe> --version` first non-empty line contains the needle (with the
//        usage/error banner filtered out so a non-recognizing exe can't pass).
//   Applied at every native resolution site (cfg / bundled / Browse...) and in
//   the dialog's typed-path / picked-file handlers. WSL paths skip this — see
//   kHelperIdentityNeedle.
//
//   See "Helper-exe identity verification" in CLAUDE.md.

// Drain a pipe's full contents into a UTF-8 string (capped at 16 KB so a
// chatty exe can't blow up memory; keeps reading past the cap to avoid the
// child blocking on a full pipe).
static void DrainPipe(HANDLE hRead, std::string& out) {
    constexpr size_t kCap = 16 * 1024;
    char buf[4096];
    DWORD n = 0;
    while (ReadFile(hRead, buf, sizeof(buf), &n, nullptr) && n > 0) {
        if (out.size() < kCap) {
            size_t room = kCap - out.size();
            out.append(buf, (n < room) ? n : room);
        }
    }
}

// First non-empty, trimmed line of a wide string (empty if none).
static std::wstring FirstNonEmptyLine(const std::wstring& s) {
    size_t pos = 0;
    while (pos < s.size()) {
        size_t end = s.find(L'\n', pos);
        std::wstring line = TrimW(s.substr(pos, (end == std::wstring::npos ? s.size() : end) - pos));
        if (!line.empty()) return line;
        if (end == std::wstring::npos) break;
        pos = end + 1;
    }
    return {};
}

// Run `<exe> --version`, capture stdout+stderr, return the first non-empty
// line. Returns empty on a usage/error banner (meaning --version isn't
// recognized) or on a >10 s hang.
static std::wstring DetectHelperVersionFromFlag(const std::wstring& exePath) {
    HANDLE hReadOut = nullptr, hWriteOut = nullptr;
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(&hReadOut, &hWriteOut, &sa, 0)) return {};
    SetHandleInformation(hReadOut, HANDLE_FLAG_INHERIT, 0);

    HANDLE hNullIn = CreateFileW(L"NUL", GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 &sa, OPEN_EXISTING, 0, nullptr);
    if (hNullIn == INVALID_HANDLE_VALUE) {
        CloseHandle(hReadOut); CloseHandle(hWriteOut);
        return {};
    }

    std::wstring cmdline = L"\"" + exePath + L"\" --version";
    std::vector<wchar_t> mut(cmdline.begin(), cmdline.end());
    mut.push_back(L'\0');

    STARTUPINFOW si = {};
    si.cb         = sizeof(si);
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdInput  = hNullIn;
    si.hStdOutput = hWriteOut;
    si.hStdError  = hWriteOut;
    PROCESS_INFORMATION pi = {};

    BOOL ok = CreateProcessW(nullptr, mut.data(), nullptr, nullptr,
                             TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(hWriteOut);
    CloseHandle(hNullIn);
    if (!ok) { CloseHandle(hReadOut); return {}; }

    std::string captured;
    std::thread drainer([&captured, hReadOut]() { DrainPipe(hReadOut, captured); });

    DWORD waitRc = WaitForSingleObject(pi.hProcess, 10000);  // 10 s cap
    if (waitRc == WAIT_TIMEOUT) TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    drainer.join();
    CloseHandle(hReadOut);

    std::wstring line = FirstNonEmptyLine(Utf8ToWide(captured));
    std::wstring lowered = line;
    for (auto& c : lowered) c = (wchar_t)towlower(c);
    if (lowered.rfind(L"usage:", 0) == 0) return {};
    if (lowered.find(L"error:") != std::wstring::npos) return {};
    if (lowered.find(L"unrecognized arguments") != std::wstring::npos) return {};
    return line;
}

// True if the exe's PE VERSIONINFO carries needleLower (already lowercased) in
// any of the standard string fields.
static bool PeIdentityContains(const std::wstring& exePath, const wchar_t* needleLower) {
    DWORD handle = 0;
    DWORD size = GetFileVersionInfoSizeW(exePath.c_str(), &handle);
    if (size == 0) return false;
    std::vector<BYTE> buf(size);
    if (!GetFileVersionInfoW(exePath.c_str(), handle, size, buf.data())) return false;

    struct LCP { WORD wLanguage; WORD wCodePage; };
    LCP* lcp = nullptr;
    UINT lcpLen = 0;
    if (!VerQueryValueW(buf.data(), L"\\VarFileInfo\\Translation",
                        (LPVOID*)&lcp, &lcpLen) || !lcp || lcpLen < sizeof(LCP))
        return false;

    const wchar_t* fields[] = {
        L"InternalName", L"OriginalFilename", L"ProductName", L"FileDescription"
    };
    for (const wchar_t* f : fields) {
        wchar_t sub[100];
        swprintf_s(sub, L"\\StringFileInfo\\%04x%04x\\%s",
                   lcp->wLanguage, lcp->wCodePage, f);
        wchar_t* val = nullptr;
        UINT vlen = 0;
        if (VerQueryValueW(buf.data(), sub, (LPVOID*)&val, &vlen) && val) {
            std::wstring s = val;
            for (auto& c : s) c = (wchar_t)towlower(c);
            if (s.find(needleLower) != std::wstring::npos) return true;
        }
    }
    return false;
}

// OR of the two checks. outDetail gets a human-readable reason either way (for
// the Messages log + the rejection display).
static bool VerifyHelperIdentity(const std::wstring& exePath,
                                 const wchar_t* needle,
                                 std::wstring& outDetail) {
    std::wstring needleLower = needle;
    for (auto& c : needleLower) c = (wchar_t)towlower(c);

    bool pe = PeIdentityContains(exePath, needleLower.c_str());
    bool flag = false;
    std::wstring vline = DetectHelperVersionFromFlag(exePath);
    if (!vline.empty()) {
        std::wstring lower = vline;
        for (auto& c : lower) c = (wchar_t)towlower(c);
        if (lower.find(needleLower) != std::wstring::npos) flag = true;
    }

    if (pe && flag)  outDetail = L"PE VERSIONINFO + --version banner match";
    else if (pe)     outDetail = L"PE VERSIONINFO match";
    else if (flag)   outDetail = L"--version banner match";
    else             outDetail = L"no \"" + std::wstring(needle) +
                                  L"\" marker in PE VERSIONINFO or --version output";
    return pe || flag;
}

// --- Item path / export helpers (selected-items mode) ----------------------
static std::wstring BuildItemFullPath(LONG itemID) {
    if (!XWF_GetItemName || !XWF_GetItemParent) return {};
    std::wstring path;
    LONG cur = itemID;
    for (int depth = 0; depth < 64 && cur >= 0; ++depth) {
        const wchar_t* name = XWF_GetItemName(cur);
        if (name && *name) path = std::wstring(L"\\") + name + path;
        LONG parent = XWF_GetItemParent(cur);
        if (parent < 0 || parent == cur) break;
        cur = parent;
    }
    return path.empty() ? std::wstring(L"\\") : path;
}

// Outcome of a per-item export: distinguishes "real failure" (couldn't write,
// couldn't open the item) from "virtual / unreadable item" (X-Ways reports a
// size > 0 but XWF_Read immediately yields 0 bytes — e.g. the synthetic
// "Free space" item carved by X-Ways for the unallocated regions of an NTFS
// volume). v0.2.4 distinguishes the two so the verbose log message reads
// "skipped (virtual)" instead of the misleading "export FAILED" for items
// that simply have no readable backing.
enum class ExportOutcome {
    Ok,
    VirtualOrEmpty,
    Failed,
};

static ExportOutcome ExportItemToFile(HANDLE hVolume, LONG itemID,
                                       const std::wstring& destPath) {
    if (!XWF_OpenItem || !XWF_Read || !XWF_Close || !XWF_GetItemSize) {
        return ExportOutcome::Failed;
    }

    INT64 size = XWF_GetItemSize(itemID);
    if (size < 0) return ExportOutcome::Failed;

    HANDLE hItem = XWF_OpenItem(hVolume, itemID, 0);
    if (!hItem || hItem == INVALID_HANDLE_VALUE) return ExportOutcome::Failed;

    HANDLE hFile = CreateFileW(destPath.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        XWF_Close(hItem);
        return ExportOutcome::Failed;
    }

    constexpr DWORD kChunk = 64 * 1024;
    std::vector<BYTE> buf(kChunk);
    INT64 offset = 0;
    ExportOutcome outcome = ExportOutcome::Ok;
    while (offset < size) {
        DWORD want = (DWORD)((kChunk < (DWORD)(size - offset)) ? kChunk : (DWORD)(size - offset));
        DWORD got = XWF_Read(hItem, offset, buf.data(), want);
        if (got == 0) {
            // First-chunk zero-read on a positive-sized item = virtual /
            // unreadable. Mid-stream zero-read = real read failure.
            outcome = (offset == 0) ? ExportOutcome::VirtualOrEmpty
                                    : ExportOutcome::Failed;
            break;
        }
        DWORD written = 0;
        if (!WriteFile(hFile, buf.data(), got, &written, nullptr) || written != got) {
            outcome = ExportOutcome::Failed;
            break;
        }
        offset += got;
    }

    CloseHandle(hFile);
    XWF_Close(hItem);
    // If we declared the item virtual, delete the empty/partial output file
    // we just wrote — leaves no trace and avoids confusing BE with a 0-byte
    // input.
    if (outcome == ExportOutcome::VirtualOrEmpty) {
        DeleteFileW(destPath.c_str());
    }
    return outcome;
}

// Pick a base for the temp dir.
//
// v0.2.3: switched away from the X-Ways evidence working directory
// (XWF_GetEvObjProp property 12). xways_recon_probe v0.3.x found that
// X-Ways periodically tries to delete unrecognised files from that
// directory mid-run — when our exported `xwitem_*.bin` files were held
// open by CreateFileW, the delete attempt failed and X-Ways popped a
// modal "Cannot delete" warning the analyst had to dismiss. Pattern
// documented at docs/xways-probing-techniques.md §6.
//
// New priority chain: <dll_dir>\temp\ > %TEMP% > C:\Temp\.
static std::wstring PickTempBase(HANDLE /*hEvidence*/) {
    std::wstring dllDir = GetSelfDirectory();
    if (!dllDir.empty()) {
        std::wstring tmp = dllDir + L"\\temp";
        CreateDirectoryW(tmp.c_str(), nullptr);  // ERROR_ALREADY_EXISTS is fine
        if (DirExists(tmp)) return tmp;
    }
    wchar_t base[MAX_PATH] = {0};
    DWORD n = GetTempPathW(MAX_PATH, base);
    if (n > 0 && n <= MAX_PATH) return std::wstring(base);
    return L"C:\\Temp\\";
}

// Recursive directory delete (single-level + nested files). Best-effort —
// returns true if the dir is gone after the call. Used by the v0.2.4
// auto-cleanup of the selected-items export temp dir on BE-success.
static bool DeleteDirRecursive(const std::wstring& dir) {
    if (!DirExists(dir)) return true;  // already gone
    std::wstring pattern = dir + L"\\*";
    WIN32_FIND_DATAW fd = {};
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        return RemoveDirectoryW(dir.c_str()) != 0;
    }
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        std::wstring child = dir + L"\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            DeleteDirRecursive(child);
        } else {
            // Clear read-only flag if set, then delete.
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_READONLY) {
                SetFileAttributesW(child.c_str(), FILE_ATTRIBUTE_NORMAL);
            }
            DeleteFileW(child.c_str());
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return RemoveDirectoryW(dir.c_str()) != 0;
}

static std::wstring CreateUniqueTempDir(HANDLE hEvidence, const wchar_t* suffix) {
    std::wstring base = PickTempBase(hEvidence);
    if (!base.empty() && base.back() != L'\\') base += L'\\';

    SYSTEMTIME st; GetSystemTime(&st);
    wchar_t stamp[64];
    swprintf_s(stamp, L"be_%s_%04u%02u%02u_%02u%02u%02u_%08lX",
               suffix, st.wYear, st.wMonth, st.wDay,
               st.wHour, st.wMinute, st.wSecond, GetTickCount());
    std::wstring full = base + stamp;
    if (!CreateDirectoryW(full.c_str(), nullptr)) {
        if (GetLastError() != ERROR_ALREADY_EXISTS) return {};
    }
    return full;
}

// --- Default output-dir guess ----------------------------------------------
//   Project convention: analyst-facing output goes under
//   <caseRoot>\xways-bulk_extractor\ so reports stay grouped per X-Tension
//   instead of piling at the case root. bulk_extractor itself needs a fresh
//   subdir per run (pre-2.2.0 refuses an existing output dir; 2.2.0 treats it
//   as a completed restart and silently does nothing), so we nest a
//   timestamped "bulk_extractor_<stamp>" inside the project folder.
//   See "Output convention" in CLAUDE.md.
static const wchar_t* kProjectOutputSubdir = L"xways-bulk_extractor";

static std::wstring SuggestOutputDir() {
    wchar_t caseDir[MAX_PATH * 2] = {0};
    if (XWF_GetCaseProp) {
        XWF_GetCaseProp(nullptr, 6, caseDir, MAX_PATH * 2);
    }
    std::wstring base = caseDir[0] ? StripExtendedPathPrefix(std::wstring(caseDir))
                                   : std::wstring();
    if (base.empty()) {
        wchar_t tmp[MAX_PATH] = {0};
        DWORD n = GetTempPathW(MAX_PATH, tmp);
        if (n > 0 && n <= MAX_PATH) base = tmp;
        else                        base = L"C:\\Temp\\";
    }
    if (!base.empty() && base.back() != L'\\') base += L'\\';

    SYSTEMTIME st; GetSystemTime(&st);
    wchar_t stamp[64];
    swprintf_s(stamp, L"bulk_extractor_%04u%02u%02u_%02u%02u%02u",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return base + kProjectOutputSubdir + L"\\" + stamp;
}

// v0.5.0: re-stamp a reused auto-suggested output dir at Run time. The
// suggestion above is timestamped once when the dialog opens, so a second Run
// in the same dialog session would reuse the first run's dir — which
// pre-2.2.0 BE refuses loudly and BE 2.2.0 silently no-ops on (its restart
// logic sees the completed report.xml, exits 0, and processes nothing;
// observed live 2026-08-19). Only leaves matching our exact
// "bulk_extractor_<YYYYMMDD>_<HHMMSS>" suggestion pattern are touched, and
// only when the dir already exists — an analyst-typed custom path is never
// rewritten. Returns true if `dir` was replaced with a fresh sibling.
static bool RestampSuggestedOutputDir(std::wstring& dir) {
    static const wchar_t kLeafPrefix[]  = L"bulk_extractor_";
    static constexpr size_t kPrefixLen  = 15;              // wcslen(kLeafPrefix)
    static constexpr size_t kLeafLen    = kPrefixLen + 8 + 1 + 6;
    const std::wstring trimmed = TrimW(dir);
    size_t slash = trimmed.find_last_of(L'\\');
    if (slash == std::wstring::npos) return false;
    const std::wstring leaf = trimmed.substr(slash + 1);
    if (leaf.size() != kLeafLen) return false;
    if (_wcsnicmp(leaf.c_str(), kLeafPrefix, kPrefixLen) != 0) return false;
    for (size_t i = kPrefixLen; i < kLeafLen; ++i) {
        if (i == kPrefixLen + 8) { if (leaf[i] != L'_') return false; }
        else if (!iswdigit(leaf[i]))                    return false;
    }
    if (!DirExists(trimmed)) return false;  // unused suggestion — keep it
    SYSTEMTIME st; GetSystemTime(&st);
    wchar_t stamp[64];
    swprintf_s(stamp, L"bulk_extractor_%04u%02u%02u_%02u%02u%02u",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    std::wstring fresh = trimmed.substr(0, slash + 1) + stamp;
    // Same-second collision guard (Run clicked twice within one second, or a
    // leftover dir): append _2.._9 until the name is unused.
    for (int n = 2; DirExists(fresh) && n <= 9; ++n) {
        fresh = trimmed.substr(0, slash + 1) + stamp + L"_" + std::to_wstring(n);
    }
    if (DirExists(fresh) || fresh == trimmed) return false;
    dir = fresh;
    return true;
}

// =============================================================================
//  Settings + dialog
// =============================================================================
enum class InputMode { ActiveEoImage, PickPath, SelectedItems };

struct Settings {
    InputMode    inputMode      = InputMode::PickPath;
    std::wstring inputPath;          // file or dir for PickPath; resolved-source for ActiveEoImage
    std::wstring outputDir;
    std::wstring beBinary;
    int          threads         = 0;        // 0 = let BE decide; otherwise emit -j N
    int          threadsMax      = 0;        // populated from GetSystemInfo; drives the dropdown range
    int          maxRecurse      = 12;       // BE default
    std::vector<bool> scannerOn;             // parallel to kScanners; size == kNumScanners
    bool         addToCase       = true;
    bool         openFolder      = false;
    bool         tagScanned      = true;   // every successfully exported item -> "bulk_extractor scanned"
    bool         tagHits         = true;   // subset with feature hits          -> "bulk_extractor hits"
    bool         tagHitsPerFeature = false; // v0.2.11: extra labels per-feature -> "bulk_extractor: <name>"
    bool         keepTempDir     = false;  // v0.2.4: keep selected-items temp dir after BE-success
    // v0.3.0: WSL bulk_extractor support.
    bool         useWsl          = false;  // run BE via WSL instead of native Windows binary
    std::wstring wslBeBinary;               // Linux-side path, e.g. "/usr/bin/bulk_extractor"

    // Filled by the caller before showing dialog:
    bool         hasActiveEoImage = false;   // controls whether the EO radio is enabled
    std::wstring eoUnavailableReason;        // shown next to the EO radio when disabled
    int          selectedCount    = 0;       // shows next to the selected radio
    bool         selectionMode    = false;   // controls whether the Selected radio is enabled / preselected
};


static void DlgGetText(HWND h, int id, std::wstring& out) {
    HWND c = GetDlgItem(h, id);
    int len = GetWindowTextLengthW(c);
    out.assign((size_t)len, L'\0');
    if (len > 0) GetWindowTextW(c, out.data(), len + 1);
}

static int DlgGetInt(HWND h, int id, int defaultVal) {
    BOOL ok = FALSE;
    UINT v = GetDlgItemInt(h, id, &ok, FALSE);
    return ok ? (int)v : defaultVal;
}

// Browse helpers (file and folder).
static bool BrowseForFile(HWND parent, std::wstring& path) {
    wchar_t buf[MAX_PATH * 2] = {0};
    if (!path.empty()) wcsncpy_s(buf, path.c_str(), MAX_PATH * 2 - 1);
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = parent;
    ofn.lpstrFile   = buf;
    ofn.nMaxFile    = MAX_PATH * 2;
    ofn.lpstrFilter = L"All files\0*.*\0Image files (*.dd;*.E01;*.raw;*.img)\0*.dd;*.E01;*.raw;*.img\0";
    ofn.Flags       = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetOpenFileNameW(&ofn)) return false;
    path = buf;
    return true;
}

static bool BrowseForFolder(HWND parent, std::wstring& path) {
    BROWSEINFOW bi = {};
    bi.hwndOwner = parent;
    bi.lpszTitle = L"Choose folder";
    bi.ulFlags   = BIF_RETURNONLYFSDIRS | BIF_USENEWUI;
    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (!pidl) return false;
    wchar_t buf[MAX_PATH * 2] = {0};
    if (SHGetPathFromIDListW(pidl, buf)) path = buf;
    CoTaskMemFree(pidl);
    return !path.empty();
}

// --- In-dialog helper-rejection display (v0.4.0) ---------------------------
//   When the resolved/picked NATIVE bulk_extractor binary fails identity
//   verification, we surface it ON the dialog (no MessageBox): the BE-binary
//   edit keeps the rejected path, and IDC_STATIC_BE_STATUS becomes a bold-red
//   "Not a valid bulk_extractor.exe file" that flashes bright/dark red for
//   ~2 s then stays solid red. Run is disabled until a valid Browse pick (or a
//   re-typed valid path) clears the state. The dialog is modal + single-
//   instance, so this state lives in module statics (same model as
//   g_runCtrlDown) rather than a heap DlgState.
static bool   g_helperRejected   = false;
static int    g_helperFlashTicks = 0;        // counts down; >0 means flashing
static HFONT  g_boldFont         = nullptr;  // for the rejection message
static const wchar_t* kHelperRejectionMessage = L"Not a valid bulk_extractor.exe file";

static void EnsureBoldFont(HWND hDlg) {
    if (g_boldFont) return;
    HDC hdc = GetDC(hDlg);
    int dpiY = hdc ? GetDeviceCaps(hdc, LOGPIXELSY) : 96;
    if (hdc) ReleaseDC(hDlg, hdc);
    LOGFONTW lf = {};
    lf.lfHeight  = -MulDiv(9, dpiY, 72);
    lf.lfWeight  = FW_BOLD;
    lf.lfCharSet = DEFAULT_CHARSET;
    wcscpy_s(lf.lfFaceName, LF_FACESIZE, L"MS Shell Dlg");
    g_boldFont = CreateFontIndirectW(&lf);
}

static void ShowHelperRejection(HWND hDlg, const std::wstring& path,
                                const std::wstring& detail) {
    EnsureBoldFont(hDlg);
    g_helperRejected   = true;
    g_helperFlashTicks = kHelperFlashTickCount;

    if (!path.empty()) SetDlgItemTextW(hDlg, IDC_EDIT_BE_BIN, path.c_str());
    SetBeStatus(hDlg, kHelperRejectionMessage);
    HWND hStat = GetDlgItem(hDlg, IDC_STATIC_BE_STATUS);
    if (hStat && g_boldFont) SendMessageW(hStat, WM_SETFONT, (WPARAM)g_boldFont, TRUE);

    SetTimer(hDlg, kHelperFlashTimerId, 250, nullptr);
    if (hStat) InvalidateRect(hStat, nullptr, TRUE);

    // No valid helper -> Run can't be useful.
    EnableWindow(GetDlgItem(hDlg, IDOK), FALSE);

    Log(L"REJECTED bulk_extractor binary (" + path + L") — " + detail);
    (void)detail;
}

static void ClearHelperRejection(HWND hDlg) {
    if (g_helperRejected) {
        g_helperRejected   = false;
        g_helperFlashTicks = 0;
        KillTimer(hDlg, kHelperFlashTimerId);
    }
    SetBeStatus(hDlg, L"");
    HWND hStat = GetDlgItem(hDlg, IDC_STATIC_BE_STATUS);
    if (hStat) {
        HFONT base = (HFONT)SendMessageW(hDlg, WM_GETFONT, 0, 0);
        if (base) SendMessageW(hStat, WM_SETFONT, (WPARAM)base, TRUE);
        InvalidateRect(hStat, nullptr, TRUE);
    }
    EnableWindow(GetDlgItem(hDlg, IDOK), TRUE);
}

// Collect the cfg-backed fields from the dialog into a CfgValues for SaveCfg.
//   The BE-binary edit holds the Linux path in WSL mode and the Windows path
//   otherwise; we keep the *other* mode's value from the live Settings (which
//   the IDC_CHK_USE_WSL handler keeps in sync as the analyst toggles). Fields
//   without a dialog control (keep_temp_dir, default_output_dir) are carried
//   from the live Settings so a Ctrl-save preserves them.
static CfgValues CollectCfgFromDialog(HWND hDlg, const Settings* s) {
    CfgValues cfg;
    bool nowWsl = IsDlgButtonChecked(hDlg, IDC_CHK_USE_WSL) == BST_CHECKED;
    std::wstring beField;
    DlgGetText(hDlg, IDC_EDIT_BE_BIN, beField);
    if (nowWsl) {
        cfg.wsl_be_binary = TrimW(beField);
        cfg.be_binary     = s ? TrimW(s->beBinary) : std::wstring();
    } else {
        cfg.be_binary     = TrimW(beField);
        cfg.wsl_be_binary = s ? TrimW(s->wslBeBinary) : std::wstring();
    }
    cfg.use_wsl_default = nowWsl;
    cfg.keep_temp_dir   = s ? s->keepTempDir : false;
    // default_output_dir is intentionally NOT persisted (output-dir convention).
    return cfg;
}

// --- Run context --------------------------------------------------------------
//   Carries the handles + selected-item list from XT_Prepare/XT_ProcessItem
//   through RunFlow into the worker. Defined here (ahead of SettingsDlgProc)
//   because the v0.5.0 dialog handlers reference g_run / g_workerCtx in the
//   IDOK and WM_APP_DONE paths, so the type + globals must be in scope before
//   the dialog proc.
struct RunCtx {
    HANDLE hVolume   = nullptr;
    HANDLE hEvidence = nullptr;
    bool   selectionMode    = false;
    std::vector<LONG> selected;  // populated by XT_ProcessItem under DBC

    // v0.2.3: track whether the run mutated snapshot state (added Labels,
    // created an evidence object). XT_Finalize returns 0x02 if so to ask
    // X-Ways to persist the volume snapshot — saves the analyst a manual
    // save step. Per 21.3 Preview 3 forum announcement; see
    // docs/xtension-invocation.md "Return values".
    bool didMutate = false;
};

static RunCtx g_run;

// Worker-owned copies of the run inputs. The dialog's Settings* points at
// ShowSettingsDialog's stack &s; the detached worker outlives that scope, so
// IDOK copies the resolved settings + run context here before spawning the
// thread.
static RunCtx   g_workerCtx;
static Settings g_workerSettings;

// --- Split run phases (threading gate) --------------------------------------
//   A: PrepareRunInput -- XWF reads + tag-scanned labels (X-Ways thread ONLY)
//   B: ExecuteBeRun    -- validate/spawn/wait bulk_extractor (worker-safe)
//   C: PostProcessRun  -- XWF mutations + temp cleanup (X-Ways thread ONLY)
struct RunPrep {
    std::wstring inputForBE;
    std::wstring tempInputDir;      // SelectedItems only; empty otherwise
    bool         didMutate = false; // tag-scanned labels applied during export
};
enum class RunOutcome { PrereqFailed, RanOk, RanFailed };
static bool       PrepareRunInput(const RunCtx& ctx, const Settings& s, RunPrep& prep);
static RunOutcome ExecuteBeRun(const Settings& s, const RunPrep& prep,
                               bool pumpMessages, DWORD& exitCodeOut);
static void       PostProcessRun(const Settings& s, const RunPrep& prep,
                                 bool beRanOk, bool* outDidMutate);
static RunPrep g_workerPrep;  // dialog path: filled by IDOK, read by worker + WM_APP_DONE

// Enable/disable controls based on the selected input radio.
static void UpdateInputState(HWND hDlg, const Settings* s) {
    bool isPick     = IsDlgButtonChecked(hDlg, IDC_RADIO_INPUT_PICK)     == BST_CHECKED;
    EnableWindow(GetDlgItem(hDlg, IDC_EDIT_INPUT_PATH),       isPick);
    EnableWindow(GetDlgItem(hDlg, IDC_BTN_BROWSE_INPUT_FILE), isPick);
    EnableWindow(GetDlgItem(hDlg, IDC_BTN_BROWSE_INPUT_DIR),  isPick);

    bool isSelected = IsDlgButtonChecked(hDlg, IDC_RADIO_INPUT_SELECTED) == BST_CHECKED;
    EnableWindow(GetDlgItem(hDlg, IDC_CHK_TAG_SCANNED), isSelected);
    EnableWindow(GetDlgItem(hDlg, IDC_CHK_TAG_HITS),    isSelected);
    if (!isSelected) {
        CheckDlgButton(hDlg, IDC_CHK_TAG_SCANNED, BST_UNCHECKED);
        CheckDlgButton(hDlg, IDC_CHK_TAG_HITS,    BST_UNCHECKED);
    }
    // Per-feature sub-option: only meaningful when TAG_HITS is both enabled
    // (selected-items mode) AND checked.
    bool hitsChecked = IsDlgButtonChecked(hDlg, IDC_CHK_TAG_HITS) == BST_CHECKED;
    EnableWindow(GetDlgItem(hDlg, IDC_CHK_TAG_HITS_PER_FEATURE), isSelected && hitsChecked);
    if (!(isSelected && hitsChecked)) {
        CheckDlgButton(hDlg, IDC_CHK_TAG_HITS_PER_FEATURE, BST_UNCHECKED);
    }

    // Disable radios that aren't applicable in this invocation context.
    if (s) {
        EnableWindow(GetDlgItem(hDlg, IDC_RADIO_INPUT_EVOIMAGE), s->hasActiveEoImage ? TRUE : FALSE);
        EnableWindow(GetDlgItem(hDlg, IDC_RADIO_INPUT_SELECTED), s->selectionMode    ? TRUE : FALSE);
    }
}

// Settings controls disabled while a run is in flight, re-enabled by the
// WM_APP_DONE handler. Centralized so StartBeWorker and WM_APP_DONE stay in
// sync (mirrors ual-timeliner's kRunLockIds). Scanner checkboxes (IDC_SCANNER_BASE
// .. IDC_SCANNER_BASE+kNumScanners) are disabled separately via a loop (there
// are up to kNumScanners of them, created programmatically).
static const int kRunLockIds[] = {
    IDC_RADIO_INPUT_EVOIMAGE, IDC_RADIO_INPUT_PICK, IDC_RADIO_INPUT_SELECTED,
    IDC_EDIT_INPUT_PATH, IDC_BTN_BROWSE_INPUT_FILE, IDC_BTN_BROWSE_INPUT_DIR,
    IDC_EDIT_OUTPUT_DIR, IDC_BTN_BROWSE_OUTPUT,
    IDC_EDIT_BE_BIN, IDC_BTN_BROWSE_BE, IDC_CHK_USE_WSL,
    IDC_COMBO_THREADS, IDC_EDIT_MAXRECURSE,
    IDC_BTN_RESET_SCANNERS, IDC_BTN_TOGGLE_ALL,
    IDC_CHK_ADD_TO_CASE, IDC_CHK_OPEN_FOLDER,
    IDC_CHK_TAG_SCANNED, IDC_CHK_TAG_HITS, IDC_CHK_TAG_HITS_PER_FEATURE,
};

// Forward declaration — definition lives after the split run phases (the
// worker lambda inside StartBeWorker calls ExecuteBeRun).
static void StartBeWorker(HWND hDlg);

// Forward declaration — defined with the post-processing helpers below; the
// dialog's Open-output button uses it too.
static void OpenInExplorer(const std::wstring& path);

// v0.5.0: the blue readout next to the WSL checkbox is mode-aware — it
// describes the binary a Run would actually use. Native mode probes the
// exe's `--version` banner (cached per path — the probe spawns a process);
// WSL mode shows the one-time WSL detection status, as before.
static void UpdateBinaryStatusReadout(HWND hDlg, const std::wstring& nativePath) {
    wchar_t verBuf[160] = {0};
    bool wslMode = IsDlgButtonChecked(hDlg, IDC_CHK_USE_WSL) == BST_CHECKED;
    if (wslMode) {
        const WslInfo& wsl = DetectWslOnce();
        if      (!wsl.wsl_present)   wcscpy_s(verBuf, L"WSL not detected");
        else if (!wsl.be_available)  wcscpy_s(verBuf, L"bulk_extractor not found in WSL");
        else if (!wsl.be_version.empty())
            swprintf_s(verBuf, L"WSL bulk_extractor v%s", wsl.be_version.c_str());
        else                         wcscpy_s(verBuf, L"WSL bulk_extractor detected");
    } else {
        std::wstring path = TrimW(nativePath);
        if (path.empty() || !FileExists(path)) {
            wcscpy_s(verBuf, L"no binary selected");
        } else {
            static std::wstring s_cachePath, s_cacheBanner;
            if (path != s_cachePath) {
                s_cachePath   = path;
                s_cacheBanner = DetectHelperVersionFromFlag(path);
            }
            if (!s_cacheBanner.empty())
                swprintf_s(verBuf, L"%s detected", s_cacheBanner.c_str());
            else
                wcscpy_s(verBuf, L"version unknown");
        }
    }
    SetDlgItemTextW(hDlg, IDC_STATIC_WSL_VERSION, verBuf);
}

// v0.5.0: paint the bottom status/progress bar (IDC_STATIC_BE_STATUS,
// SS_OWNERDRAW). States, in priority order:
//   helper rejected -> red fill (bright/dark alternating during the flash
//                      window) + dark-red text;
//   worker running  -> grey track with a sliding light-blue marquee block
//                      (advanced by the 100 ms elapsed timer) + dark text;
//   finished text   -> soft green fill ("Done...") or amber ("Cancelled." /
//                      "Failed...") + dark text;
//   idle/empty      -> bare track.
static void DrawStatusBar(const DRAWITEMSTRUCT* dis) {
    HDC hdc = dis->hDC;
    RECT rc = dis->rcItem;
    wchar_t txt[256] = {0};
    GetWindowTextW(dis->hwndItem, txt, 256);
    const bool running  = g_workerActive.load();
    const bool rejected = g_helperRejected;
    const bool hasText  = txt[0] != 0;

    HBRUSH hbrTrack = CreateSolidBrush(RGB(228, 228, 228));
    FillRect(hdc, &rc, hbrTrack);
    DeleteObject(hbrTrack);
    RECT inner = rc;
    InflateRect(&inner, -1, -1);

    auto fill = [&](const RECT& r, COLORREF c) {
        HBRUSH b = CreateSolidBrush(c);
        FillRect(hdc, &r, b);
        DeleteObject(b);
    };

    if (rejected) {
        bool bright = (g_helperFlashTicks == 0) || ((g_helperFlashTicks & 1) == 0);
        fill(inner, bright ? RGB(255, 200, 200) : RGB(238, 160, 160));
    } else if (running) {
        int w = inner.right - inner.left;
        int blockW = w / 5; if (blockW < 8) blockW = 8;
        int span = w + blockW;
        int x = (int)((GetTickCount64() / 20) % (ULONGLONG)span) - blockW;
        RECT blk = inner;
        blk.left  = inner.left + x;
        blk.right = blk.left + blockW;
        if (blk.left  < inner.left)  blk.left  = inner.left;
        if (blk.right > inner.right) blk.right = inner.right;
        if (blk.right > blk.left) fill(blk, RGB(150, 200, 245));
    } else if (hasText) {
        bool bad = wcsncmp(txt, L"Failed", 6) == 0 || wcsncmp(txt, L"Cancelled", 9) == 0;
        fill(inner, bad ? RGB(250, 224, 170) : RGB(200, 232, 204));
    }
    DrawEdge(hdc, &rc, BDR_SUNKENOUTER, BF_RECT);

    if (hasText) {
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, rejected ? RGB(150, 0, 0) : RGB(24, 24, 24));
        HFONT hf  = (HFONT)SendMessageW(GetParent(dis->hwndItem), WM_GETFONT, 0, 0);
        HFONT old = hf ? (HFONT)SelectObject(hdc, hf) : nullptr;
        RECT rt = inner; rt.left += 6; rt.right -= 4;
        DrawTextW(hdc, txt, -1, &rt,
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
        if (old) SelectObject(hdc, old);
    }
}

// v0.5.0: tooltips. One TOOLTIPS_CLASS window per dialog instance (it is a
// child-owned popup, destroyed with the dialog), tools registered per control
// with TTF_SUBCLASS so no message-loop plumbing is needed. Text pointers must
// be static storage — we only ever pass literals / kScanners entries.
static HWND CreateDlgTooltips(HWND hDlg) {
    static bool s_ccInit = false;
    if (!s_ccInit) {
        INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_BAR_CLASSES | ICC_WIN95_CLASSES };
        InitCommonControlsEx(&icc);
        s_ccInit = true;
    }
    HWND tt = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr,
                              WS_POPUP | TTS_ALWAYSTIP | TTS_NOPREFIX,
                              CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
                              hDlg, nullptr, g_hSelf, nullptr);
    if (tt) {
        SendMessageW(tt, TTM_SETMAXTIPWIDTH, 0, 340);              // wrap long tips
        SendMessageW(tt, TTM_SETDELAYTIME, TTDT_AUTOPOP, 20000);   // stay up 20 s
    }
    return tt;
}
static void AddTip(HWND tt, HWND hDlg, int ctlId, const wchar_t* text) {
    HWND h = GetDlgItem(hDlg, ctlId);
    if (!tt || !h || !text) return;
    TOOLINFOW ti = {};
    ti.cbSize   = sizeof(ti);
    ti.uFlags   = TTF_IDISHWND | TTF_SUBCLASS;
    ti.hwnd     = hDlg;
    ti.uId      = (UINT_PTR)h;
    ti.lpszText = const_cast<wchar_t*>(text);
    SendMessageW(tt, TTM_ADDTOOLW, 0, (LPARAM)&ti);
}
static void InstallDlgTooltips(HWND hDlg) {
    HWND tt = CreateDlgTooltips(hDlg);
    if (!tt) return;
    struct { int id; const wchar_t* tip; } const kTips[] = {
        { IDC_RADIO_INPUT_EVOIMAGE,
          L"Scan the active evidence object's backing source (E01 / raw image, or a directory-type "
          L"evidence object). Disabled when X-Ways can't resolve a source path, e.g. physical disks." },
        { IDC_RADIO_INPUT_PICK,
          L"Scan an external file or directory of your choosing \u2014 exported data, or data not in the case." },
        { IDC_EDIT_INPUT_PATH,
          L"File or directory bulk_extractor will scan. Directories are scanned recursively (-R)." },
        { IDC_BTN_BROWSE_INPUT_FILE, L"Pick a file to scan." },
        { IDC_BTN_BROWSE_INPUT_DIR,  L"Pick a directory to scan recursively." },
        { IDC_RADIO_INPUT_SELECTED,
          L"Export the items selected in the directory browser to a temp folder and scan that. "
          L"Only available when the X-Tension is invoked from a right-click selection." },
        { IDC_CHK_TAG_SCANNED,
          L"Label every successfully exported item \"bulk_extractor scanned\", so even partial runs "
          L"leave an audit trail." },
        { IDC_CHK_TAG_HITS,
          L"Label items where bulk_extractor found at least one feature \"bulk_extractor hits\"." },
        { IDC_CHK_TAG_HITS_PER_FEATURE,
          L"Also add one label per scanner that hit, e.g. \"bulk_extractor: email\", "
          L"\"bulk_extractor: net\"." },
        { IDC_STATIC_WSL_VERSION,
          L"Version of the binary a Run would use, probed via --version." },
        { IDC_CHK_USE_WSL,
          L"Run a Linux bulk_extractor through WSL instead of the Windows binary. Windows paths are "
          L"translated to /mnt/<drive>/... automatically. Greyed out when WSL or a bulk_extractor "
          L"inside it isn't detected." },
        { IDC_EDIT_BE_BIN,
          L"Path to bulk_extractor64.exe (or the Linux binary in WSL mode). Auto-filled from the cfg "
          L"sidecar or the copy next to the DLL." },
        { IDC_BTN_BROWSE_BE,
          L"Pick the bulk_extractor binary. Windows binaries are identity-checked (PE VERSIONINFO or "
          L"--version banner) before they're accepted." },
        { IDC_BTN_RESET_SCANNERS, L"Restore bulk_extractor's default scanner set." },
        { IDC_BTN_TOGGLE_ALL,
          L"Check every scanner \u2014 or uncheck them all if they're already all checked." },
        { IDC_EDIT_OUTPUT_DIR,
          L"Where bulk_extractor writes its feature files and report.xml. A fresh timestamped folder "
          L"is suggested per run; a reused folder makes bulk_extractor refuse (pre-2.2.0) or silently "
          L"skip the run (2.2.0)." },
        { IDC_BTN_BROWSE_OUTPUT, L"Pick an output directory." },
        { IDC_CHK_ADD_TO_CASE,
          L"Attach the output directory to the case as a Directory evidence object when the run finishes." },
        { IDC_CHK_OPEN_FOLDER, L"Open the output directory in Explorer when the run finishes." },
        { IDC_COMBO_THREADS,
          L"Worker threads for bulk_extractor (-j). The default leaves half the cores free for X-Ways." },
        { IDC_EDIT_MAXRECURSE,
          L"Maximum recursion depth into nested / compressed data (-M). bulk_extractor's default is 12." },
        { IDC_STATIC_BE_STATUS, L"Run status and progress." },
        { IDC_BTN_ABOUT,       L"About this X-Tension." },
        { IDC_BTN_OPEN_OUTPUT,
          L"Open the output directory in Explorer (its parent folder before the first run)." },
        { IDOK,
          L"Start bulk_extractor. Hold Ctrl to save the current settings to bulk_extractor.cfg instead." },
        { IDCANCEL,
          L"Close the dialog. While a run is active: stop bulk_extractor. Hold Ctrl to save the "
          L"settings to a file of your choosing." },
    };
    for (const auto& t : kTips) AddTip(tt, hDlg, t.id, t.tip);
    for (int i = 0; i < kNumScanners; ++i) AddTip(tt, hDlg, IDC_SCANNER_BASE + i, kScanners[i].tip);
}

// --- About dialog (v0.5.0) --------------------------------------------------
//   Mirrors xways-ual-timeliner / xways-updater: bold title, description,
//   bold "Author:" prefix, clickable URL pushbuttons + a "Buy me a coffee"
//   CTA. Fonts are created in WM_INITDIALOG and freed in WM_DESTROY.
struct AboutDlgFonts {
    HFONT hTitleBold  = nullptr;
    HFONT hPrefixBold = nullptr;
};

static INT_PTR CALLBACK AboutDlgProc(HWND hDlg, UINT msg, WPARAM wp, LPARAM /*lp*/) {
    AboutDlgFonts* fonts = (AboutDlgFonts*)GetWindowLongPtrW(hDlg, GWLP_USERDATA);
    switch (msg) {
    case WM_INITDIALOG: {
        fonts = new AboutDlgFonts;
        SetWindowLongPtrW(hDlg, GWLP_USERDATA, (LONG_PTR)fonts);

        HFONT hf = (HFONT)SendMessageW(hDlg, WM_GETFONT, 0, 0);
        LOGFONTW lf{};
        if (hf) GetObjectW(hf, sizeof(lf), &lf);
        LOGFONTW lfTitle = lf;
        lfTitle.lfWeight = FW_BOLD;
        lfTitle.lfHeight = (LONG)(lf.lfHeight * 1.20);
        fonts->hTitleBold = CreateFontIndirectW(&lfTitle);
        LOGFONTW lfBold = lf; lfBold.lfWeight = FW_BOLD;
        fonts->hPrefixBold = CreateFontIndirectW(&lfBold);

        SetDlgItemTextW(hDlg, IDC_ABOUT_TITLE,
                        (std::wstring(L"xways-bulk_extractor  ") + VERSION).c_str());
        SetDlgItemTextW(hDlg, IDC_ABOUT_DESC, DESCRIPTION);
        SetDlgItemTextW(hDlg, IDC_ABOUT_LABEL_AUTHOR_PREFIX, L"Author:");
        SetDlgItemTextW(hDlg, IDC_ABOUT_AUTHOR,
            L"Kevin Stokes - Digital Detective and Cyber Sleuth");
        // U+2665 BLACK HEART SUIT \u2014 set programmatically so we don't depend
        // on rc.exe's input codepage to encode it correctly.
        SetDlgItemTextW(hDlg, IDC_ABOUT_BTN_COFFEE,
            L"\u2665 Love this? How about a coffee \u2665");

        if (fonts->hTitleBold)
            SendDlgItemMessageW(hDlg, IDC_ABOUT_TITLE, WM_SETFONT,
                                (WPARAM)fonts->hTitleBold, TRUE);
        if (fonts->hPrefixBold)
            SendDlgItemMessageW(hDlg, IDC_ABOUT_LABEL_AUTHOR_PREFIX, WM_SETFONT,
                                (WPARAM)fonts->hPrefixBold, TRUE);
        return TRUE;
    }
    case WM_COMMAND: {
        WORD id = LOWORD(wp);
        const wchar_t* url = nullptr;
        if      (id == IDC_ABOUT_LINK_GITHUB)   url = L"https://github.com/kev365/xways-bulk_extractor";
        else if (id == IDC_ABOUT_LINK_TOOL)     url = L"https://github.com/simsong/bulk_extractor";
        else if (id == IDC_ABOUT_LINK_LINKEDIN) url = L"https://www.linkedin.com/in/dfir-kev";
        else if (id == IDC_ABOUT_BTN_COFFEE)    url = L"https://buymeacoffee.com/dfirkev";
        if (url) {
            ShellExecuteW(hDlg, L"open", url, nullptr, nullptr, SW_SHOWNORMAL);
            return TRUE;
        }
        if (id == IDOK || id == IDCANCEL) {
            EndDialog(hDlg, id);
            return TRUE;
        }
        break;
    }
    case WM_CLOSE:
        EndDialog(hDlg, IDCANCEL);
        return TRUE;
    case WM_DESTROY:
        if (fonts) {
            if (fonts->hTitleBold)  DeleteObject(fonts->hTitleBold);
            if (fonts->hPrefixBold) DeleteObject(fonts->hPrefixBold);
            delete fonts;
            SetWindowLongPtrW(hDlg, GWLP_USERDATA, 0);
        }
        break;
    }
    return FALSE;
}

static void ShowAboutDialog(HWND parent) {
    DialogBoxParamW(g_hSelf, MAKEINTRESOURCEW(IDD_ABOUT), parent, AboutDlgProc, 0);
}

static INT_PTR CALLBACK SettingsDlgProc(HWND hDlg, UINT msg, WPARAM wp, LPARAM lp) {
    static Settings* s = nullptr;
    switch (msg) {
    case WM_INITDIALOG: {
        // ShowSettingsDialog passes a Settings* via DialogBoxParamW's lParam.
        s = reinterpret_cast<Settings*>(lp);
        if (!s) return TRUE;

        // v0.2.13: append the X-Tension version to the dialog title bar
        // (project convention — makes it obvious which build the analyst
        // is running, useful for bug reports). Pattern propagated to the
        // cpp template at templates/x-tensions/cpp/.
        {
            wchar_t title[256] = {0};
            GetWindowTextW(hDlg, title, 256);
            std::wstring augmented = title;
            augmented += L"  (v";
            augmented += VERSION;
            augmented += L")";
            SetWindowTextW(hDlg, augmented.c_str());
        }

        // v0.2.17: bold + slightly larger (11pt) font for GROUPBOX titles.
        // v0.2.18: also a 10pt bold for field labels (output dir, BE binary,
        //          Threads, Max recursion).
        // Visual hierarchy: section headers (11pt bold) > field labels
        // (10pt bold) > body text (10pt regular) > scanner checkboxes (9pt).
        // RC dialog templates carry only one font directive, so per-control
        // fonts are sent at runtime via WM_SETFONT.
        {
            static HFONT s_groupTitleFont = nullptr;  // 11pt bold
            static HFONT s_labelFont      = nullptr;  // 10pt bold
            if (!s_groupTitleFont || !s_labelFont) {
                HDC hdc = GetDC(hDlg);
                int dpiY = hdc ? GetDeviceCaps(hdc, LOGPIXELSY) : 96;
                if (hdc) ReleaseDC(hDlg, hdc);

                LOGFONTW lf = {};
                lf.lfWeight  = FW_BOLD;
                lf.lfCharSet = DEFAULT_CHARSET;
                wcscpy_s(lf.lfFaceName, LF_FACESIZE, L"MS Shell Dlg");

                if (!s_groupTitleFont) {
                    lf.lfHeight = -MulDiv(11, dpiY, 72);
                    s_groupTitleFont = CreateFontIndirectW(&lf);
                }
                if (!s_labelFont) {
                    lf.lfHeight = -MulDiv(10, dpiY, 72);
                    s_labelFont = CreateFontIndirectW(&lf);
                }
            }
            if (s_groupTitleFont) {
                static const int kGroupIds[] = {
                    IDC_GROUP_INPUT, IDC_GROUP_SCANNERS, IDC_GROUP_OUTPUT,
                };
                for (int id : kGroupIds) {
                    HWND grp = GetDlgItem(hDlg, id);
                    if (grp) SendMessageW(grp, WM_SETFONT,
                                          (WPARAM)s_groupTitleFont, TRUE);
                }
            }
            if (s_labelFont) {
                static const int kLabelIds[] = {
                    IDC_LABEL_OUTPUT, IDC_LABEL_BE_BIN,
                    IDC_LABEL_THREADS, IDC_LABEL_MAXRECURSE,
                    // v0.3.0: WSL-version status text rendered bold to match
                    // the field-label weight; the WM_CTLCOLORSTATIC handler
                    // below paints it blue so it reads as a positive status
                    // signal ("we found something"), not a heading.
                    IDC_STATIC_WSL_VERSION,
                };
                for (int id : kLabelIds) {
                    HWND lbl = GetDlgItem(hDlg, id);
                    if (lbl) SendMessageW(lbl, WM_SETFONT,
                                          (WPARAM)s_labelFont, TRUE);
                }
            }
        }

        // Radio: pick the most useful default given context.
        int radio = IDC_RADIO_INPUT_PICK;
        if      (s->selectionMode)       radio = IDC_RADIO_INPUT_SELECTED;
        else if (s->hasActiveEoImage)    radio = IDC_RADIO_INPUT_EVOIMAGE;
        CheckRadioButton(hDlg, IDC_RADIO_INPUT_EVOIMAGE, IDC_RADIO_INPUT_SELECTED, radio);

        if (s->selectedCount > 0) {
            wchar_t buf[64];
            swprintf_s(buf, L"  Selected items: %d", s->selectedCount);
            SetDlgItemTextW(hDlg, IDC_STATIC_SELECTED_COUNT, buf);
        }

        SetDlgItemTextW(hDlg, IDC_EDIT_INPUT_PATH,    s->inputPath.c_str());
        SetDlgItemTextW(hDlg, IDC_EDIT_OUTPUT_DIR,    s->outputDir.c_str());
        // BE binary edit: shows the Linux path when WSL mode is on, the
        // Windows path otherwise. Toggling the checkbox swaps which one is
        // displayed (handled in the IDC_CHK_USE_WSL command handler below).
        SetDlgItemTextW(hDlg, IDC_EDIT_BE_BIN,
                        s->useWsl ? s->wslBeBinary.c_str() : s->beBinary.c_str());
        SetDlgItemInt  (hDlg, IDC_EDIT_MAXRECURSE,    (UINT)s->maxRecurse, FALSE);
        CheckDlgButton(hDlg, IDC_CHK_ADD_TO_CASE, s->addToCase  ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(hDlg, IDC_CHK_OPEN_FOLDER, s->openFolder ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(hDlg, IDC_CHK_TAG_SCANNED, s->tagScanned ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(hDlg, IDC_CHK_TAG_HITS,    s->tagHits    ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(hDlg, IDC_CHK_TAG_HITS_PER_FEATURE, s->tagHitsPerFeature ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(hDlg, IDC_CHK_USE_WSL, s->useWsl ? BST_CHECKED : BST_UNCHECKED);

        // v0.3.0: WSL detection drives the "Run via WSL" checkbox enablement
        // + adjacent version readout. RunFlow has already populated
        // s->wslBeBinary from detection (or sidecar override) before
        // showing the dialog, so this block only handles the UI state.
        {
            const WslInfo& wsl = DetectWslOnce();
            BOOL canUseWsl = wsl.wsl_present && wsl.be_available;
            EnableWindow(GetDlgItem(hDlg, IDC_CHK_USE_WSL), canUseWsl);
            // If WSL isn't usable, defensively unset the useWsl flag so
            // the BE-binary edit doesn't show the (now-meaningless) Linux
            // path.
            if (!canUseWsl && s->useWsl) {
                CheckDlgButton(hDlg, IDC_CHK_USE_WSL, BST_UNCHECKED);
                SetDlgItemTextW(hDlg, IDC_EDIT_BE_BIN, s->beBinary.c_str());
            }
            // v0.5.0: readout follows the mode actually in effect (after the
            // defensive unset) — native shows the Windows binary's version.
            UpdateBinaryStatusReadout(hDlg, s->beBinary);
        }

        // EO-unavailable hint next to the disabled radio.
        if (!s->hasActiveEoImage && !s->eoUnavailableReason.empty()) {
            std::wstring hint = L"  (" + s->eoUnavailableReason + L")";
            SetDlgItemTextW(hDlg, IDC_STATIC_EO_HINT, hint.c_str());
        }

        // Threads dropdown: list 1..threadsMax, select s->threads (clamped).
        {
            HWND cb = GetDlgItem(hDlg, IDC_COMBO_THREADS);
            int maxT = s->threadsMax > 0 ? s->threadsMax : 1;
            SendMessageW(cb, CB_RESETCONTENT, 0, 0);
            for (int t = 1; t <= maxT; ++t) {
                wchar_t buf[8]; swprintf_s(buf, L"%d", t);
                SendMessageW(cb, CB_ADDSTRING, 0, (LPARAM)buf);
            }
            int want = s->threads;
            if (want < 1)    want = 1;
            if (want > maxT) want = maxT;
            SendMessageW(cb, CB_SETCURSEL, (WPARAM)(want - 1), 0);
        }

        // Scanner checkboxes — programmatically create AUTOCHECKBOX controls
        // inside the IDC_GROUP_SCANNERS rect. Layout: 3 columns, ceil(N/3) rows.
        //
        // v0.2.6 fixed a DPI/dialog-unit mismatch where the GROUPBOX was
        // DLU-sized (auto-scaled by Windows for DPI) but our checkboxes used
        // a fixed `rowH` in screen pixels — leaving a huge empty gap below
        // the last row on high-DPI displays. v0.2.6 onwards computes rowH
        // dynamically from the rendered group rect, so it fills regardless
        // of DPI or font size.
        //
        // v0.2.7 reverts to 3 columns now that v0.2.6's larger checkbox
        // font (9pt) makes labels readable even with denser horizontal
        // packing. The dialog's other controls also bumped to 10pt (.rc
        // FONT directive) — the scanner area stays at 9pt for visual
        // hierarchy ("section header text is larger than dense inner
        // controls" — standard Win32 UX).
        {
            HWND grp = GetDlgItem(hDlg, IDC_GROUP_SCANNERS);
            RECT rc; GetWindowRect(grp, &rc);
            POINT tl = {rc.left,  rc.top   }; ScreenToClient(hDlg, &tl);
            POINT br = {rc.right, rc.bottom}; ScreenToClient(hDlg, &br);
            HFONT dlgFont = (HFONT)SendMessageW(hDlg, WM_GETFONT, 0, 0);
            HINSTANCE hInst =
                (HINSTANCE)GetWindowLongPtrW(hDlg, GWLP_HINSTANCE);

            // Build a slightly larger font for the scanner checkboxes only.
            // Cached statically — created once per process, reused across
            // dialog opens. Slight one-time leak if the DLL unloads, but
            // that's millis of GDI memory; acceptable.
            static HFONT s_scannerFont = nullptr;
            if (!s_scannerFont) {
                LOGFONTW lf = {};
                HDC hdc = GetDC(hDlg);
                lf.lfHeight = -MulDiv(9, GetDeviceCaps(hdc, LOGPIXELSY), 72);
                ReleaseDC(hDlg, hdc);
                lf.lfWeight = FW_NORMAL;
                lf.lfCharSet = DEFAULT_CHARSET;
                wcscpy_s(lf.lfFaceName, LF_FACESIZE, L"MS Shell Dlg");
                s_scannerFont = CreateFontIndirectW(&lf);
            }
            HFONT cbFont = s_scannerFont ? s_scannerFont : dlgFont;

            // padTop = clearance from GROUPBOX top edge to first checkbox row.
            // Must accommodate the GROUPBOX title's full height (it renders
            // INSIDE the GROUPBOX from y=0 down to y=tmHeight). v0.2.17
            // bumped the title font to 11pt bold which is taller than the
            // dialog font; v0.2.17's padTop calc used the dialog font and
            // came out too small, leaving the first checkbox row crowding
            // the title bottom. v0.2.18 measures using the GROUPBOX's actual
            // current font (fetched via WM_GETFONT) — same font Windows uses
            // to draw the title — so the math matches what gets rendered.
            int padTop = 22;
            {
                HDC hdc = GetDC(hDlg);
                HFONT titleFont = (HFONT)SendMessageW(grp, WM_GETFONT, 0, 0);
                if (hdc && titleFont) {
                    HFONT old = (HFONT)SelectObject(hdc, titleFont);
                    TEXTMETRICW tm = {};
                    if (GetTextMetricsW(hdc, &tm)) {
                        // tmHeight covers ascender + descender; +10 px is the
                        // empty band between title bottom and first checkbox.
                        int derived = tm.tmHeight + 10;
                        if (derived > padTop) padTop = derived;
                    }
                    SelectObject(hdc, old);
                }
                if (hdc) ReleaseDC(hDlg, hdc);
            }

            const int padBot = 8, padLR = 12;
            const int nCols  = 4;   // v0.5.0: was 3
            const int nRowsPerCol = (kNumScanners + nCols - 1) / nCols;

            // v0.2.8: derive rowH from the checkbox font's actual measured
            // line height (TEXTMETRIC.tmHeight + small padding), not from
            // groupHeight/nRows. The latter produced wide-spaced rows (or a
            // clamped gap) on high-DPI displays where the GROUPBOX, sized in
            // DLU, scaled up far more than fixed pixel measurements assumed.
            int rowH = 24;  // fallback if metrics can't be obtained
            {
                HDC hdc = GetDC(hDlg);
                if (hdc) {
                    HFONT old = (HFONT)SelectObject(hdc, cbFont);
                    TEXTMETRICW tm = {};
                    if (GetTextMetricsW(hdc, &tm)) {
                        rowH = tm.tmHeight + 4;  // v0.5.0: 4 px (was 6) — denser 4-col grid
                    }
                    SelectObject(hdc, old);
                    ReleaseDC(hDlg, hdc);
                }
                if (rowH < 16) rowH = 16;  // legibility floor only
            }

            int innerW = (br.x - tl.x) - 2 * padLR;
            if (innerW < nCols) innerW = nCols;
            int colW = innerW / nCols;
            int xs = tl.x + padLR;
            int ys = tl.y + padTop;

            for (int i = 0; i < kNumScanners; ++i) {
                int row = i / nCols;
                int col = i % nCols;
                int x = xs + col * colW;
                int y = ys + row * rowH;
                HWND cb = CreateWindowExW(
                    0, L"BUTTON", kScanners[i].name,
                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                    x, y, colW - 4, rowH - 2,
                    hDlg, (HMENU)(INT_PTR)(IDC_SCANNER_BASE + i),
                    hInst, nullptr);
                if (cb) SendMessageW(cb, WM_SETFONT, (WPARAM)cbFont, TRUE);
                bool on = (i < (int)s->scannerOn.size())
                    ? s->scannerOn[i] : kScanners[i].defaultEnabled;
                CheckDlgButton(hDlg, IDC_SCANNER_BASE + i,
                               on ? BST_CHECKED : BST_UNCHECKED);
            }

            // v0.2.8 auto-fit: shrink the scanner GROUPBOX to its natural
            // height (12 rows of font-derived rowH + padding), then push
            // everything below up + shrink the dialog by the saved delta.
            // Eliminates the residual gap on any DPI/font combination.
            int natural_h = padTop + nRowsPerCol * rowH + padBot;
            int actual_h  = br.y - tl.y;
            int delta     = actual_h - natural_h;
            if (delta > 4) {
                SetWindowPos(grp, nullptr, 0, 0, br.x - tl.x, natural_h,
                             SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
                // Only controls BELOW the Scanner group need to shift up.
                // Reset/Toggle are to the RIGHT (parallel) so they're not
                // shifted. Tagging checkboxes are nested INSIDE the Input
                // source group at the top, also no shift.
                // v0.3.0: output-dir label/edit/browse moved INTO the
                // Output handling group, so they're now below the scanner
                // group and need to shift with it.
                static const int kShiftIds[] = {
                    IDC_GROUP_OUTPUT,
                    IDC_LABEL_OUTPUT, IDC_EDIT_OUTPUT_DIR, IDC_BTN_BROWSE_OUTPUT,
                    IDC_CHK_ADD_TO_CASE, IDC_CHK_OPEN_FOLDER,
                    IDC_LABEL_THREADS,    IDC_COMBO_THREADS,
                    IDC_LABEL_MAXRECURSE, IDC_EDIT_MAXRECURSE,
                    // v0.5.0 bottom bar: About / Open output / status line
                    // moved down here with Run/Cancel.
                    IDC_BTN_ABOUT, IDC_BTN_OPEN_OUTPUT, IDC_STATIC_BE_STATUS,
                    IDOK, IDCANCEL,
                };
                for (int id : kShiftIds) {
                    HWND h = GetDlgItem(hDlg, id);
                    if (!h) continue;
                    RECT r; GetWindowRect(h, &r);
                    POINT p = {r.left, r.top};
                    ScreenToClient(hDlg, &p);
                    SetWindowPos(h, nullptr, p.x, p.y - delta, 0, 0,
                                 SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
                }
                RECT rcDlg; GetWindowRect(hDlg, &rcDlg);
                SetWindowPos(hDlg, nullptr, 0, 0,
                             rcDlg.right  - rcDlg.left,
                             rcDlg.bottom - rcDlg.top - delta,
                             SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
            }
        }

        UpdateInputState(hDlg, s);

        // v0.4.0: helper-exe identity verification of the initial NATIVE
        // binary. WSL mode is exempt (the Linux binary can't be inspected from
        // Windows). If a non-empty native path is present but fails the gate,
        // surface the in-dialog flash rejection straight away so the analyst
        // can Browse... to a real bulk_extractor64.exe before Run.
        g_helperRejected   = false;
        g_helperFlashTicks = 0;

        // v0.5.0: capture the dialog HWND (the worker's PostMessage target) and
        // reset the run-state globals to idle so a re-opened dialog starts clean.
        g_dlgHwnd = hDlg;
        g_workerActive.store(false);
        g_cancelRequested.store(false);
        g_runStartTick = 0;

        SetBeStatus(hDlg, L"");
        if (!s->useWsl && !TrimW(s->beBinary).empty() && FileExists(s->beBinary)) {
            std::wstring idDetail;
            if (!VerifyHelperIdentity(s->beBinary, kHelperIdentityNeedle, idDetail)) {
                ShowHelperRejection(hDlg, s->beBinary, idDetail);
            }
        }

        // v0.4.0: Ctrl-to-save / Save-as gesture. Run + Cancel are BS_OWNERDRAW
        // (we paint them in WM_DRAWITEM); DM_SETDEFID flags Run as the default
        // action so Enter still triggers it without DEFPUSHBUTTON (which
        // conflicts with owner-draw). A 100 ms timer polls VK_CONTROL so the
        // labels + Run's blue tint update without focus tricks.
        SendMessageW(hDlg, DM_SETDEFID, IDOK, 0);
        g_runCtrlDown = false;
        SetDlgItemTextW(hDlg, IDOK,     L"Run");
        SetDlgItemTextW(hDlg, IDCANCEL, L"Cancel");
        SetTimer(hDlg, kCtrlPollTimerId, 100, nullptr);

        // v0.5.0: tooltips — after every control (incl. the programmatic
        // scanner checkboxes) exists.
        InstallDlgTooltips(hDlg);
        return TRUE;
    }
    case WM_CTLCOLORSTATIC: {
        HWND hCtl = (HWND)lp;
        WORD ctlId = (WORD)GetDlgCtrlID(hCtl);
        // v0.3.0: paint the WSL-version status label blue.
        if (ctlId == IDC_STATIC_WSL_VERSION) {
            HDC hdc = (HDC)wp;
            SetTextColor(hdc, RGB(0, 64, 192));   // calm blue, not neon
            SetBkMode(hdc, TRANSPARENT);
            return (INT_PTR)GetSysColorBrush(COLOR_BTNFACE);
        }
        // (v0.5.0: the status line is SS_OWNERDRAW — its red rejection flash
        // is painted in DrawStatusBar via WM_DRAWITEM, not here.)
        break;
    }
    case WM_TIMER: {
        if (wp == kCtrlPollTimerId) {
            if (g_workerActive.load()) return TRUE;   // Ctrl-to-save inert during a run
            bool nowDown = (GetKeyState(VK_CONTROL) & 0x8000) != 0;
            if (nowDown != g_runCtrlDown) {
                g_runCtrlDown = nowDown;
                HWND hRun = GetDlgItem(hDlg, IDOK);
                if (hRun) {
                    SetWindowTextW(hRun, nowDown ? L"Save" : L"Run");
                    InvalidateRect(hRun, nullptr, TRUE);
                }
                // Cancel -> "Save as..." while Ctrl held (this dialog has no
                // mid-dialog worker, so there's no Cancel-collision concern).
                SetDlgItemTextW(hDlg, IDCANCEL,
                                nowDown ? L"Save as..." : L"Cancel");
            }
            return TRUE;
        }
        if (wp == kHelperFlashTimerId) {
            if (!g_helperRejected) {
                KillTimer(hDlg, kHelperFlashTimerId);
                return TRUE;
            }
            if (g_helperFlashTicks > 0) {
                --g_helperFlashTicks;
                HWND hStat = GetDlgItem(hDlg, IDC_STATIC_BE_STATUS);
                if (hStat) InvalidateRect(hStat, nullptr, TRUE);
                if (g_helperFlashTicks == 0)
                    KillTimer(hDlg, kHelperFlashTimerId);
            }
            return TRUE;
        }
        if (wp == kElapsedTimerId) {
            if (!g_workerActive.load()) { KillTimer(hDlg, kElapsedTimerId); return TRUE; }
            ULONGLONG elapsedMs = GetTickCount64() - g_runStartTick;
            unsigned secs = (unsigned)(elapsedMs / 1000);
            wchar_t buf[96];
            swprintf_s(buf, L"Running bulk_extractor\u2026 %02u:%02u (see console window)",
                       secs / 60, secs % 60);
            SetBeStatus(hDlg, buf);   // also invalidates -> marquee advances
            return TRUE;
        }
        return FALSE;
    }
    case WM_DRAWITEM: {
        // Owner-draw for Run (IDOK) and Cancel (IDCANCEL). Run gets a blue fill
        // + white text while Ctrl is held ("Save"); both otherwise render as a
        // standard 3D button.
        DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lp;
        if (dis && dis->CtlType == ODT_STATIC && dis->CtlID == IDC_STATIC_BE_STATUS) {
            DrawStatusBar(dis);   // v0.5.0 bottom status/progress bar
            return TRUE;
        }
        if (!dis || dis->CtlType != ODT_BUTTON ||
            (dis->CtlID != IDOK && dis->CtlID != IDCANCEL))
            return FALSE;

        bool ctrl     = g_runCtrlDown && dis->CtlID == IDOK;
        bool pressed  = (dis->itemState & ODS_SELECTED) != 0;
        bool disabled = (dis->itemState & ODS_DISABLED) != 0;
        bool focused  = (dis->itemState & ODS_FOCUS) != 0;

        COLORREF bg;
        if (disabled)     bg = GetSysColor(COLOR_BTNFACE);
        else if (ctrl)    bg = pressed ? RGB(0, 90, 170) : RGB(0, 120, 215);
        else              bg = pressed ? GetSysColor(COLOR_BTNSHADOW)
                                       : GetSysColor(COLOR_BTNFACE);
        HBRUSH hbr = CreateSolidBrush(bg);
        FillRect(dis->hDC, &dis->rcItem, hbr);
        DeleteObject(hbr);

        DrawEdge(dis->hDC, &dis->rcItem,
                 pressed ? EDGE_SUNKEN : EDGE_RAISED, BF_RECT | BF_SOFT);

        wchar_t txt[64] = {0};
        GetWindowTextW(dis->hwndItem, txt, 64);
        SetBkMode(dis->hDC, TRANSPARENT);
        COLORREF fg = disabled ? GetSysColor(COLOR_GRAYTEXT)
                               : (ctrl ? RGB(255, 255, 255)
                                       : GetSysColor(COLOR_BTNTEXT));
        SetTextColor(dis->hDC, fg);
        RECT rcText = dis->rcItem;
        if (pressed) OffsetRect(&rcText, 1, 1);
        DrawTextW(dis->hDC, txt, -1, &rcText,
                  DT_CENTER | DT_VCENTER | DT_SINGLELINE);

        if (focused) {
            RECT rcFocus = dis->rcItem;
            InflateRect(&rcFocus, -3, -3);
            DrawFocusRect(dis->hDC, &rcFocus);
        }
        return TRUE;
    }
    case WM_COMMAND: {
        WORD id  = LOWORD(wp);
        WORD evt = HIWORD(wp);
        switch (id) {
        case IDC_RADIO_INPUT_EVOIMAGE:
        case IDC_RADIO_INPUT_PICK:
        case IDC_RADIO_INPUT_SELECTED:
            UpdateInputState(hDlg, s);
            return TRUE;

        case IDC_CHK_TAG_HITS:
            // Re-run UpdateInputState so the per-feature sub-checkbox
            // enables/disables in step with this parent checkbox.
            UpdateInputState(hDlg, s);
            return TRUE;

        case IDC_BTN_BROWSE_INPUT_FILE: {
            std::wstring p;
            DlgGetText(hDlg, IDC_EDIT_INPUT_PATH, p);
            if (BrowseForFile(hDlg, p)) SetDlgItemTextW(hDlg, IDC_EDIT_INPUT_PATH, p.c_str());
            return TRUE;
        }
        case IDC_BTN_BROWSE_INPUT_DIR: {
            std::wstring p;
            DlgGetText(hDlg, IDC_EDIT_INPUT_PATH, p);
            if (BrowseForFolder(hDlg, p)) SetDlgItemTextW(hDlg, IDC_EDIT_INPUT_PATH, p.c_str());
            return TRUE;
        }
        case IDC_BTN_BROWSE_OUTPUT: {
            std::wstring p;
            DlgGetText(hDlg, IDC_EDIT_OUTPUT_DIR, p);
            if (BrowseForFolder(hDlg, p)) SetDlgItemTextW(hDlg, IDC_EDIT_OUTPUT_DIR, p.c_str());
            return TRUE;
        }
        case IDC_BTN_BROWSE_BE: {
            std::wstring p;
            DlgGetText(hDlg, IDC_EDIT_BE_BIN, p);
            if (!BrowseForFile(hDlg, p)) return TRUE;
            // v0.3.0: in WSL mode, translate "\\wsl$\<distro>\..." UNC
            // returned by the picker into the Linux-side "/..." path,
            // so the field carries something WSL itself can resolve.
            // (Windows paths returned in WSL mode are converted to
            // /mnt/c/... at run time, so leaving them as-is is also OK.)
            bool wslMode = IsDlgButtonChecked(hDlg, IDC_CHK_USE_WSL) == BST_CHECKED;
            if (wslMode) {
                std::wstring linuxPath = WslUncToLinuxPath(p);
                if (!linuxPath.empty()) p = linuxPath;
                // WSL binary can't be verified from Windows — accept the path
                // and clear any stale native-mode rejection.
                SetDlgItemTextW(hDlg, IDC_EDIT_BE_BIN, p.c_str());
                ClearHelperRejection(hDlg);
                return TRUE;
            }
            // v0.4.0: native mode — identity-verify the picked exe before
            // accepting it. Show the rejected path + flash on failure; clear
            // the rejection (re-enabling Run) on success.
            SetDlgItemTextW(hDlg, IDC_EDIT_BE_BIN, p.c_str());
            SetBeStatus(hDlg, L"(verifying...)");
            HWND hStat = GetDlgItem(hDlg, IDC_STATIC_BE_STATUS);
            if (hStat) UpdateWindow(hStat);
            std::wstring idDetail;
            if (!VerifyHelperIdentity(p, kHelperIdentityNeedle, idDetail)) {
                ShowHelperRejection(hDlg, p, idDetail);
            } else {
                ClearHelperRejection(hDlg);
                Log(L"bulk_extractor binary accepted (" + p + L") — " + idDetail);
            }
            UpdateBinaryStatusReadout(hDlg, p);
            return TRUE;
        }
        case IDC_CHK_USE_WSL: {
            // Swap the BE-binary edit content to match the new mode.
            // We don't lose the "other" path: keep both in Settings
            // (s->beBinary, s->wslBeBinary). The currently-displayed
            // path is captured back into the appropriate slot before
            // swapping, so the analyst can toggle freely without losing
            // a custom path they typed in either mode.
            if (!s) return TRUE;
            std::wstring current;
            DlgGetText(hDlg, IDC_EDIT_BE_BIN, current);
            bool nowWsl = IsDlgButtonChecked(hDlg, IDC_CHK_USE_WSL) == BST_CHECKED;
            if (nowWsl) {
                // We were just in Windows mode; save typed content there.
                s->beBinary = current;
                SetDlgItemTextW(hDlg, IDC_EDIT_BE_BIN, s->wslBeBinary.c_str());
                // WSL binary can't be verified from Windows — clear any native
                // rejection so it doesn't linger while in WSL mode.
                ClearHelperRejection(hDlg);
            } else {
                s->wslBeBinary = current;
                SetDlgItemTextW(hDlg, IDC_EDIT_BE_BIN, s->beBinary.c_str());
                // Back in native mode — re-verify the restored Windows path.
                ClearHelperRejection(hDlg);
                std::wstring nativePath = TrimW(s->beBinary);
                if (!nativePath.empty() && FileExists(nativePath)) {
                    std::wstring idDetail;
                    if (!VerifyHelperIdentity(nativePath, kHelperIdentityNeedle, idDetail))
                        ShowHelperRejection(hDlg, nativePath, idDetail);
                }
            }
            // v0.5.0: readout swaps with the mode (WSL status vs native version).
            UpdateBinaryStatusReadout(hDlg, s->beBinary);
            return TRUE;
        }
        case IDC_BTN_ABOUT:
            ShowAboutDialog(hDlg);
            return TRUE;
        case IDC_BTN_OPEN_OUTPUT: {
            // Open the output dir if it exists; fall back to its parent (the
            // per-X-Tension case folder) so the button is useful before the
            // first run and after a re-stamp.
            std::wstring p;
            DlgGetText(hDlg, IDC_EDIT_OUTPUT_DIR, p);
            p = TrimW(p);
            if (!p.empty() && DirExists(p)) { OpenInExplorer(p); return TRUE; }
            size_t slash = p.find_last_of(L'\\');
            if (slash != std::wstring::npos && slash > 0) {
                std::wstring parent = p.substr(0, slash);
                if (DirExists(parent)) { OpenInExplorer(parent); return TRUE; }
            }
            MessageBoxW(hDlg, L"Output directory does not exist yet.",
                        L"bulk_extractor", MB_OK | MB_ICONINFORMATION);
            return TRUE;
        }
        case IDC_BTN_RESET_SCANNERS: {
            for (int i = 0; i < kNumScanners; ++i) {
                CheckDlgButton(hDlg, IDC_SCANNER_BASE + i,
                               kScanners[i].defaultEnabled ? BST_CHECKED : BST_UNCHECKED);
            }
            return TRUE;
        }
        case IDC_BTN_TOGGLE_ALL: {
            // Smart toggle: if any scanner is currently unchecked, check
            // them all; otherwise (all are checked), uncheck them all.
            bool anyUnchecked = false;
            for (int i = 0; i < kNumScanners; ++i) {
                if (IsDlgButtonChecked(hDlg, IDC_SCANNER_BASE + i) != BST_CHECKED) {
                    anyUnchecked = true;
                    break;
                }
            }
            UINT newState = anyUnchecked ? BST_CHECKED : BST_UNCHECKED;
            for (int i = 0; i < kNumScanners; ++i) {
                CheckDlgButton(hDlg, IDC_SCANNER_BASE + i, newState);
            }
            return TRUE;
        }
        case IDOK: {
            if (!s) { EndDialog(hDlg, IDCANCEL); return TRUE; }

            // v0.4.0: Ctrl+Run = save the cfg-backed settings to the standard
            // sidecar next to the DLL WITHOUT launching a run. Skips the
            // Run-only validation gates (output-dir etc.) so an analyst can
            // park a binary/WSL config and come back to it. The timer-driven
            // "Save" label + blue tint is the visual cue this branch will fire.
            if ((GetKeyState(VK_CONTROL) & 0x8000) != 0) {
                CfgValues cfg = CollectCfgFromDialog(hDlg, s);
                std::wstring cfgPath = GetSelfDirectory() + L"\\bulk_extractor.cfg";
                bool ok = SaveCfg(cfgPath, cfg);
                SetBeStatus(hDlg,
                    ok ? L"Settings saved to bulk_extractor.cfg"
                       : L"Failed to save bulk_extractor.cfg (see Messages)");
                Log(ok ? (L"settings saved via Ctrl+Run: " + cfgPath)
                       : (L"settings save FAILED via Ctrl+Run: " + cfgPath));
                return TRUE;
            }

            if      (IsDlgButtonChecked(hDlg, IDC_RADIO_INPUT_EVOIMAGE)) s->inputMode = InputMode::ActiveEoImage;
            else if (IsDlgButtonChecked(hDlg, IDC_RADIO_INPUT_SELECTED)) s->inputMode = InputMode::SelectedItems;
            else                                                          s->inputMode = InputMode::PickPath;

            DlgGetText(hDlg, IDC_EDIT_INPUT_PATH, s->inputPath);
            DlgGetText(hDlg, IDC_EDIT_OUTPUT_DIR, s->outputDir);
            // v0.5.0: if the field still holds an auto-suggested dir that a
            // previous Run already used, re-stamp it so every Run gets a
            // fresh dir (see RestampSuggestedOutputDir for why reuse is bad).
            if (RestampSuggestedOutputDir(s->outputDir)) {
                SetDlgItemTextW(hDlg, IDC_EDIT_OUTPUT_DIR, s->outputDir.c_str());
                Log(L"output dir already used by a previous run — re-stamped to: "
                    + s->outputDir);
            }
            // BE binary edit holds Linux path in WSL mode, Windows path
            // otherwise — capture into the matching Settings slot.
            s->useWsl = IsDlgButtonChecked(hDlg, IDC_CHK_USE_WSL) == BST_CHECKED;
            {
                std::wstring beField;
                DlgGetText(hDlg, IDC_EDIT_BE_BIN, beField);
                if (s->useWsl) s->wslBeBinary = beField;
                else           s->beBinary    = beField;
            }
            // Threads from combobox (1-based selection -> threads value).
            {
                HWND cb = GetDlgItem(hDlg, IDC_COMBO_THREADS);
                int sel = (int)SendMessageW(cb, CB_GETCURSEL, 0, 0);
                s->threads = (sel >= 0) ? (sel + 1) : 0;
            }
            s->maxRecurse     = DlgGetInt(hDlg, IDC_EDIT_MAXRECURSE, 12);
            // Scanners — read each checkbox into the parallel scannerOn vector.
            s->scannerOn.assign(kNumScanners, false);
            for (int i = 0; i < kNumScanners; ++i) {
                s->scannerOn[i] = IsDlgButtonChecked(hDlg, IDC_SCANNER_BASE + i) == BST_CHECKED;
            }
            s->addToCase  = IsDlgButtonChecked(hDlg, IDC_CHK_ADD_TO_CASE) == BST_CHECKED;
            s->openFolder = IsDlgButtonChecked(hDlg, IDC_CHK_OPEN_FOLDER) == BST_CHECKED;
            s->tagScanned = IsDlgButtonChecked(hDlg, IDC_CHK_TAG_SCANNED) == BST_CHECKED;
            s->tagHits    = IsDlgButtonChecked(hDlg, IDC_CHK_TAG_HITS)    == BST_CHECKED;
            s->tagHitsPerFeature = IsDlgButtonChecked(hDlg, IDC_CHK_TAG_HITS_PER_FEATURE) == BST_CHECKED;

            // Validate output dir is non-empty (other validation happens later
            // — we want the user to see "you forgot the output dir" not just
            // a silent dialog refusing to close).
            if (TrimW(s->outputDir).empty()) {
                MessageBoxW(hDlg, L"Output directory is required.", L"bulk_extractor",
                            MB_OK | MB_ICONWARNING);
                SetFocus(GetDlgItem(hDlg, IDC_EDIT_OUTPUT_DIR));
                return TRUE;
            }

            // v0.5.0: final native identity gate inline, BEFORE starting the
            // worker — so a bad binary surfaces via the in-dialog flash UI
            // (IDC_STATIC_BE_STATUS, the IDC_BTN_BROWSE_BE Browse path) instead
            // of only the worker's Log-only path. WSL mode is exempt (the Linux
            // binary can't be PE-inspected from Windows); just require non-empty.
            if (!s->useWsl) {
                if (TrimW(s->beBinary).empty() || !FileExists(s->beBinary)) {
                    ShowHelperRejection(hDlg, s->beBinary, L"file not found");
                    return TRUE;
                }
                std::wstring idDetail;
                if (!VerifyHelperIdentity(s->beBinary, kHelperIdentityNeedle, idDetail)) {
                    ShowHelperRejection(hDlg, s->beBinary, idDetail);
                    return TRUE;
                }
            } else if (TrimW(s->wslBeBinary).empty()) {
                MessageBoxW(hDlg, L"WSL bulk_extractor path is required.",
                            L"bulk_extractor", MB_OK | MB_ICONWARNING);
                return TRUE;
            }

            // Copy resolved settings + run context into worker-owned storage
            // (the modal Settings* points at ShowSettingsDialog's stack &s that
            // the worker must not depend on). g_run holds
            // hVolume/hEvidence/selected for the standalone path; mirror it.
            g_workerSettings = *s;
            g_workerCtx      = g_run;

            // Phase A on X-Ways' thread (threading gate): SelectedItems
            // extraction reads item bytes via XWF_OpenItem/Read and may tag
            // via XWF_Label -- none of that may run on the worker. On failure
            // the status line already carries the reason; stay idle.
            g_workerPrep = RunPrep{};
            if (!PrepareRunInput(g_workerCtx, g_workerSettings, g_workerPrep)) {
                return TRUE;
            }
            if (g_workerPrep.didMutate) g_run.didMutate = true;

            StartBeWorker(hDlg);
            return TRUE;
        }
        case IDCANCEL: {
            // Phase 3: while a run is active, Cancel = cooperative abort.
            // First click sets g_cancelRequested; the worker's 100 ms wait
            // loop terminates the BE child and unwinds via WM_APP_DONE
            // (code 1), which re-enables this button. Disabled meanwhile so
            // it can't double-fire; the dialog still cannot close mid-run
            // (WM_CLOSE guard).
            if (g_workerActive.load()) {
                if (!g_cancelRequested.load()) {
                    g_cancelRequested.store(true);
                    EnableWindow(GetDlgItem(hDlg, IDCANCEL), FALSE);
                    SetBeStatus(hDlg, L"Cancelling…");
                    Log(L"Cancel requested — stopping bulk_extractor…");
                }
                return TRUE;
            }

            // v0.4.0: Ctrl+Close = "Save as..." — pick a .cfg path and write
            // the current settings there, then close. The export is a copy;
            // the X-Tension only auto-loads the standard sidecar next to its
            // DLL on next launch.
            if (s && (GetKeyState(VK_CONTROL) & 0x8000) != 0) {
                CfgValues cfg = CollectCfgFromDialog(hDlg, s);
                wchar_t fileBuf[MAX_PATH] = L"bulk_extractor.cfg";
                OPENFILENAMEW ofn = {};
                ofn.lStructSize  = sizeof(ofn);
                ofn.hwndOwner    = hDlg;
                ofn.lpstrFilter  = L"X-Tension cfg (*.cfg)\0*.cfg\0All files (*.*)\0*.*\0";
                ofn.nFilterIndex = 1;
                ofn.lpstrFile    = fileBuf;
                ofn.nMaxFile     = MAX_PATH;
                ofn.lpstrTitle   = L"Save bulk_extractor settings to...";
                ofn.Flags        = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
                ofn.lpstrDefExt  = L"cfg";
                if (!GetSaveFileNameW(&ofn)) return TRUE;  // user cancelled picker
                bool ok = SaveCfg(fileBuf, cfg);
                Log(ok ? (L"settings saved via Ctrl+Close (Save as) to: " + std::wstring(fileBuf))
                       : (L"settings save FAILED via Ctrl+Close to: "      + std::wstring(fileBuf)));
                if (ok) EndDialog(hDlg, IDCANCEL);
                return TRUE;
            }
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
        }
        (void)evt;
        return FALSE;
    }
    case WM_APP_STATUS: {
        wchar_t* text = (wchar_t*)lp;
        if (text) {
            SetBeStatus(hDlg, text);
            delete[] text;
        }
        return TRUE;
    }
    case WM_APP_DONE: {
        // wp: 0 ok, 1 cancelled, 2 BE failed, 3 prereq failed (no run -- the
        // specific failure text is already on the status line).
        // P2: reap the worker first -- it posted this message as its last
        // real work, so the join returns almost immediately.
        if (g_workerThread.joinable()) g_workerThread.join();
        g_workerActive.store(false);
        KillTimer(hDlg, kElapsedTimerId);

        // Phase C on X-Ways' thread (threading gate): the XWF-mutating
        // post-processing (CreateEvObj + Label tagging) and temp cleanup run
        // HERE, not on the worker. Skipped when the run never started (wp 3).
        {
            bool didMutate = false;
            if (wp != 3) {
                PostProcessRun(g_workerSettings, g_workerPrep, wp == 0, &didMutate);
                if (wp == 1) Log(L"Run cancelled by user.");
            }
            if (didMutate) g_run.didMutate = true;
        }
        switch (wp) {
        case 0: SetBeStatus(hDlg,
                    L"Done. See Messages window for the run summary."); break;
        case 1: SetBeStatus(hDlg, L"Cancelled."); break;
        case 2: SetBeStatus(hDlg,
                    L"Failed: bulk_extractor returned a nonzero exit code (see Messages)."); break;
        default: break;  // 3: specific failure text already shown
        }

        // Re-enable Run + settings + the scanner checkboxes (inverse of
        // StartBeWorker). IDCANCEL is re-enabled explicitly (it is not in
        // kRunLockIds and Phase 3's IDCANCEL abort disables it mid-cancel).
        EnableWindow(GetDlgItem(hDlg, IDOK), TRUE);
        for (int id : kRunLockIds) {
            HWND h = GetDlgItem(hDlg, id);
            if (h) EnableWindow(h, TRUE);
        }
        for (int i = 0; i < kNumScanners; ++i) {
            HWND h = GetDlgItem(hDlg, IDC_SCANNER_BASE + i);
            if (h) EnableWindow(h, TRUE);
        }
        EnableWindow(GetDlgItem(hDlg, IDCANCEL), TRUE);

        // Re-apply input-mode enable/disable logic (some controls are mode-gated).
        if (s) UpdateInputState(hDlg, s);

        // The worker already posted the final WM_APP_STATUS summary text; leave
        // the status line as-is. Move focus to the (now close-acting) Cancel.
        SetFocus(GetDlgItem(hDlg, IDCANCEL));
        return TRUE;
    }
    case WM_CLOSE:
        if (g_workerActive.load()) return TRUE;   // must Cancel first
        EndDialog(hDlg, IDCANCEL);
        return TRUE;
    case WM_DESTROY:
        // v0.4.0: tear down the Ctrl-poll + flash timers and reset the gesture
        // state so a re-opened dialog starts clean. The bold font is process-
        // cached (reused across opens), so it's left alive intentionally.
        KillTimer(hDlg, kCtrlPollTimerId);
        KillTimer(hDlg, kHelperFlashTimerId);
        KillTimer(hDlg, kElapsedTimerId);
        g_dlgHwnd          = nullptr;
        g_runCtrlDown      = false;
        g_helperRejected   = false;
        g_helperFlashTicks = 0;
        return FALSE;  // let default processing continue
    }
    return FALSE;
}

// Show the modal settings dialog. Returns true if the user clicked Run.
static bool ShowSettingsDialog(HWND parent, Settings& s) {
    INT_PTR rv = DialogBoxParamW(g_hSelf, MAKEINTRESOURCEW(IDD_SETTINGS),
                                 parent, SettingsDlgProc,
                                 reinterpret_cast<LPARAM>(&s));
    return rv == IDOK;
}

// =============================================================================
//  WSL detection + path translation (v0.3.0)
// =============================================================================
//   Lets the analyst run BE via WSL ("Run via WSL" checkbox in the dialog)
//   instead of the bundled Windows binary. Historically necessary because BE
//   2.1.x didn't build on Windows; since 2.2.0 (2026-08-18) upstream ships an
//   official Windows binary with E01 support, so WSL is now optional — kept
//   for analysts with distro-packaged or self-built BE setups.

// Run a command line synchronously, capture stdout into `out`. Returns the
// exit code; sets *pTimedOut=true on timeout. Used for WSL detection probes.
static DWORD RunCaptureStdout(const std::wstring& cmd, std::wstring& out,
                              DWORD timeoutMs = 5000, BOOL* pTimedOut = nullptr) {
    if (pTimedOut) *pTimedOut = FALSE;

    // Anonymous pipe for stdout. Make read-end non-inheritable so the child
    // doesn't keep it open after exit (would block ReadFile until parent
    // closes its handle too).
    SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};
    HANDLE hRead = nullptr, hWrite = nullptr;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return (DWORD)-1;
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si = {}; si.cb = sizeof(si);
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError  = hWrite;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);  // inherit ours

    PROCESS_INFORMATION pi = {};
    std::vector<wchar_t> cmdline(cmd.begin(), cmd.end());
    cmdline.push_back(L'\0');

    BOOL ok = CreateProcessW(nullptr, cmdline.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(hWrite);  // we keep only the read end now
    if (!ok) {
        CloseHandle(hRead);
        return (DWORD)-1;
    }

    // Drain pipe until child exits or timeout.
    DWORD startTick = GetTickCount();
    char buf[1024];
    std::string accum;
    for (;;) {
        DWORD avail = 0;
        if (PeekNamedPipe(hRead, nullptr, 0, nullptr, &avail, nullptr) && avail > 0) {
            DWORD got = 0;
            DWORD want = (avail < sizeof(buf)) ? avail : sizeof(buf);
            if (ReadFile(hRead, buf, want, &got, nullptr) && got > 0) {
                accum.append(buf, got);
                continue;
            }
        }
        DWORD waitRv = WaitForSingleObject(pi.hProcess, 50);
        if (waitRv == WAIT_OBJECT_0) {
            // Drain any remaining pipe contents.
            for (;;) {
                DWORD got = 0;
                if (!ReadFile(hRead, buf, sizeof(buf), &got, nullptr) || got == 0) break;
                accum.append(buf, got);
            }
            break;
        }
        if (GetTickCount() - startTick > timeoutMs) {
            if (pTimedOut) *pTimedOut = TRUE;
            TerminateProcess(pi.hProcess, 1);
            WaitForSingleObject(pi.hProcess, 1000);
            break;
        }
    }

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hRead);

    out = Utf8ToWide(accum);
    return exitCode;
}

// One-time WSL detection. Cached for the lifetime of the process — running
// `wsl --status` adds ~300ms latency we don't want on every dialog open.
// (struct WslInfo declared near g_hSelf for forward-use by dialog proc.)
static const WslInfo& DetectWslOnce() {
    static WslInfo info;
    static bool detected = false;
    if (detected) return info;
    detected = true;

    // Step 1: is WSL installed at all? `wsl --status` exits 0 if a default
    // distribution is configured. Quiet failure = no WSL.
    {
        std::wstring out;
        DWORD rv = RunCaptureStdout(L"wsl.exe --status", out, 4000);
        if (rv == 0 || rv == 1) {
            // rv=1 can also indicate "no installed distributions" — treat as
            // present-but-unusable. Truly absent WSL gives a cmd-not-found
            // kind of failure (rv=-1 from our wrapper).
            info.wsl_present = (rv == 0);
        }
    }
    if (!info.wsl_present) return info;

    // Step 2: bulk_extractor in PATH inside WSL?
    std::wstring whichPath;
    {
        DWORD rv = RunCaptureStdout(L"wsl.exe -e which bulk_extractor", whichPath, 4000);
        if (rv == 0) {
            // Strip trailing whitespace/newlines.
            while (!whichPath.empty() &&
                   (whichPath.back() == L'\n' || whichPath.back() == L'\r' ||
                    whichPath.back() == L' '  || whichPath.back() == L'\t')) {
                whichPath.pop_back();
            }
            if (!whichPath.empty() && whichPath.front() == L'/') {
                info.be_path      = whichPath;
                info.be_available = true;
            }
        }
    }
    if (!info.be_available) return info;

    // Step 3: probe version. Output format depends on BE version:
    //   BE 2.0.x: "bulk_extractor version 2.0.4"
    //   BE 2.1.x+: "bulk_extractor 2.1.1"  (the word "version" was dropped;
    //              same shape verified for 2.2.0: "bulk_extractor 2.2.0")
    // Strategy: try " version " first (legacy format), otherwise scan for
    // the first whitespace-delimited token that starts with a digit and
    // contains a '.' (the version number itself).
    {
        std::wstring out;
        DWORD rv = RunCaptureStdout(L"wsl.exe -e bulk_extractor -V", out, 4000);
        if (rv == 0 && !out.empty()) {
            size_t s = std::wstring::npos;
            size_t p = out.find(L" version ");
            if (p != std::wstring::npos) {
                s = p + 9;  // length of " version "
            } else {
                // Find first whitespace-delimited dotted-digit token.
                for (size_t i = 0; i < out.size(); ++i) {
                    bool atStart = (i == 0) ||
                                   out[i - 1] == L' '  || out[i - 1] == L'\t' ||
                                   out[i - 1] == L'\n' || out[i - 1] == L'\r';
                    if (atStart && iswdigit(out[i])) {
                        size_t j = i;
                        while (j < out.size() &&
                               out[j] != L' ' && out[j] != L'\t' &&
                               out[j] != L'\n' && out[j] != L'\r') ++j;
                        if (out.substr(i, j - i).find(L'.') != std::wstring::npos) {
                            s = i;
                            break;
                        }
                    }
                }
            }
            if (s != std::wstring::npos) {
                size_t e = s;
                while (e < out.size() &&
                       out[e] != L'\n' && out[e] != L'\r' &&
                       out[e] != L' '  && out[e] != L'\t') ++e;
                info.be_version = out.substr(s, e - s);
            }
        }
    }
    return info;
}

// Translate a Windows path "C:\foo\bar" → "/mnt/c/foo/bar" for WSL invocation.
// Drive letter lowercased, backslashes → forward slashes, colon dropped.
// If the input is already a Linux-style path (starts with '/') it's returned
// unchanged. UNC paths (\\server\...) are NOT supported (out-of-scope per
// project decision).
static std::wstring WindowsPathToWsl(const std::wstring& win) {
    if (win.empty()) return win;
    if (win.size() >= 1 && win[0] == L'/') return win;  // already Linux

    if (win.size() >= 3 && iswalpha(win[1] == L':' ? win[0] : 0) &&
        win[1] == L':' && (win[2] == L'\\' || win[2] == L'/')) {
        std::wstring out = L"/mnt/";
        out += (wchar_t)towlower(win[0]);
        for (size_t i = 2; i < win.size(); ++i) {
            wchar_t c = win[i];
            out += (c == L'\\') ? L'/' : c;
        }
        return out;
    }
    // Fallback: replace backslashes only; let WSL deal with relative paths.
    std::wstring out;
    out.reserve(win.size());
    for (wchar_t c : win) out += (c == L'\\') ? L'/' : c;
    return out;
}

// Translate a Windows-side WSL path "\\wsl$\Ubuntu\usr\bin\bulk_extractor"
// (or "\\wsl.localhost\Ubuntu\..." on newer Windows) to a Linux-side
// "/usr/bin/bulk_extractor". Returns empty if `win` isn't a WSL UNC.
static std::wstring WslUncToLinuxPath(const std::wstring& win) {
    static const wchar_t* kPrefixes[] = {
        L"\\\\wsl$\\",
        L"\\\\wsl.localhost\\",
    };
    for (const wchar_t* prefix : kPrefixes) {
        size_t plen = wcslen(prefix);
        if (win.size() <= plen) continue;
        if (_wcsnicmp(win.c_str(), prefix, plen) != 0) continue;
        // Skip the distro segment: <prefix><distro>\<rest>
        size_t s = win.find(L'\\', plen);
        if (s == std::wstring::npos) return L"/";  // distro root with nothing else
        std::wstring rest = win.substr(s);  // includes leading backslash
        std::wstring out;
        out.reserve(rest.size());
        for (wchar_t c : rest) out += (c == L'\\') ? L'/' : c;
        return out;  // already starts with '/'
    }
    return std::wstring();
}

// =============================================================================
//  Subprocess launch
// =============================================================================
//   Builds the bulk_extractor command line and spawns it in a NEW console so
//   the analyst sees real-time progress. We block on the process exiting
//   (no in-DLL cancel — analyst can close the console window or kill via
//   Task Manager). v2 will replace with a worker-thread + progress dialog.

static std::wstring QuoteIfNeeded(const std::wstring& s) {
    if (s.empty()) return L"\"\"";
    if (s.find_first_of(L" \t\"") == std::wstring::npos) return s;
    return L"\"" + s + L"\"";
}

static bool RunBulkExtractor(const Settings& s, const std::wstring& inputPath,
                             DWORD& exitCode, std::wstring& errOut,
                             bool pumpMessages) {
    // v0.3.0: translate paths if running via WSL. Output dir + input path
    // are Windows paths (analyst's storage); we map them to /mnt/c/...
    // for the Linux BE. -R-detection (is input a directory?) is done on
    // the WINDOWS side because the answer is the same regardless of how
    // BE accesses it.
    const bool wsl = s.useWsl;
    auto pathArg = [&](const std::wstring& winPath) {
        return wsl ? WindowsPathToWsl(winPath) : winPath;
    };

    std::wstring cmd;
    if (wsl) {
        // wsl.exe -e <linuxBeBinary> ... <args>
        cmd = L"wsl.exe -e ";
        cmd += QuoteIfNeeded(s.wslBeBinary);
    } else {
        cmd = QuoteIfNeeded(s.beBinary);
    }

    cmd += L" -o ";
    cmd += QuoteIfNeeded(pathArg(s.outputDir));

    if (s.threads > 0) {
        wchar_t buf[32];
        swprintf_s(buf, L" -j %d", s.threads);
        cmd += buf;
    }
    {
        wchar_t buf[32];
        swprintf_s(buf, L" -M %d", s.maxRecurse);
        cmd += buf;
    }

    // Scanner flags: emit -e for any default-disabled scanner the user turned
    // on, -x for any default-enabled scanner they turned off. Skip any that
    // match BE's default — keeps the cmdline short and readable in the log.
    for (int i = 0; i < kNumScanners; ++i) {
        bool want = (i < (int)s.scannerOn.size())
            ? s.scannerOn[i] : kScanners[i].defaultEnabled;
        bool def  = kScanners[i].defaultEnabled;
        if (want && !def) { cmd += L" -e "; cmd += kScanners[i].name; }
        if (!want &&  def) { cmd += L" -x "; cmd += kScanners[i].name; }
    }

    // BE wants `-R` only for directory-as-input scans. Detect by checking
    // whether the input is a directory (Windows-side check; same answer
    // either way).
    bool isDir = DirExists(inputPath);
    if (isDir) cmd += L" -R";

    cmd += L" ";
    cmd += QuoteIfNeeded(pathArg(inputPath));

    Log(L"command: " + cmd);

    std::vector<wchar_t> cmdline(cmd.begin(), cmd.end());
    cmdline.push_back(L'\0');

    STARTUPINFOW si = {}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    BOOL ok = CreateProcessW(nullptr, cmdline.data(), nullptr, nullptr, FALSE,
                             CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi);
    if (!ok) {
        wchar_t buf[160];
        swprintf_s(buf, L"CreateProcessW failed: GetLastError=%lu",
                   (unsigned long)GetLastError());
        errOut = buf;
        return false;
    }

    // The BE wait is thread-context-aware (in-DLL Cancel design §3.3). On the
    // X-Ways UI thread (synchronous managed/headless path, pumpMessages=true)
    // we keep the MsgWaitForMultipleObjects + PeekMessage drain so X-Ways stays
    // responsive during the BE wait. On a worker thread (dialog mode,
    // pumpMessages=false) we must NOT pump the UI message queue — a plain timed
    // WaitForSingleObject poll is used instead.
    if (pumpMessages) {
        for (;;) {
            DWORD r = MsgWaitForMultipleObjects(1, &pi.hProcess, FALSE,
                                                INFINITE, QS_ALLINPUT);
            if (r == WAIT_OBJECT_0) break;          // BE finished
            if (r == WAIT_OBJECT_0 + 1) {           // UI messages waiting
                MSG msg;
                while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
                continue;
            }
            break;                                   // WAIT_FAILED or unexpected
        }
    } else {
        for (;;) {
            DWORD r = WaitForSingleObject(pi.hProcess, 100);
            if (r == WAIT_OBJECT_0) break;          // BE finished
            if (r != WAIT_TIMEOUT) break;           // WAIT_FAILED or unexpected
            // Phase 3: cooperative cancel. IDCANCEL set the flag on the UI
            // thread; terminate BE here on the worker, which owns the process
            // handle, then fall through to the normal exit-code path (the
            // caller maps cancelRequested to WM_APP_DONE code 1).
            if (g_cancelRequested.load()) {
                Log(L"cancel: terminating bulk_extractor child process...");
                TerminateProcess(pi.hProcess, 1);
                WaitForSingleObject(pi.hProcess, 5000);
                break;
            }
        }
    }
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return exitCode == 0;
}

// =============================================================================
//  Output integration
// =============================================================================

// Add the output directory as a Directory-typed evidence object via
// XWF_CreateEvObj(nType=3, ...). Returns true if the call succeeded.
static bool AddOutputAsEvidence(const std::wstring& outputDir) {
    if (!XWF_CreateEvObj) {
        Log(L"XWF_CreateEvObj is not available — cannot add evidence object");
        return false;
    }
    std::wstring dir = outputDir;  // CreateEvObj wants writable LPWSTR
    HANDLE h = XWF_CreateEvObj(EVOBJ_TYPE_DIRECTORY, 0, dir.data(), nullptr);
    if (!h || h == INVALID_HANDLE_VALUE) {
        Log(L"XWF_CreateEvObj returned NULL/INVALID for: " + outputDir);
        return false;
    }
    Log(L"added evidence object: " + outputDir);
    return true;
}

static void OpenInExplorer(const std::wstring& path) {
    ShellExecuteW(nullptr, L"open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

// --- Feature-file walking for selected-items tagging ----------------------
//   We only call this when input was a temp dir of files named
//   `xwitem_<itemID>_<safe_leaf>.bin`. Walk every *.txt feature file, look
//   for the `xwitem_NNN_` token in each line, collect the set of item IDs
//   that had ≥1 hit. Skip *_histogram.txt (those are aggregations of the
//   same content) and report.xml (not a .txt anyway).
//
//   v0.2.11 returns a per-feature breakdown alongside the union: each
//   feature file's basename (without .txt) becomes a key, mapped to the
//   itemIDs that had at least one hit in that file. The `union` field
//   collects every itemID across all feature files. Callers can use just
//   the union (single label) or the breakdown (per-feature labels).
struct FeatureHits {
    std::unordered_map<std::wstring, std::unordered_set<LONG>> byFeature;
    std::unordered_set<LONG> union_;  // itemIDs with hits in any feature file
};

// Map a bulk_extractor feature-file basename (without .txt) to the scanner
// that produced it. Multiple feature files can come from one scanner — e.g.
// `url`, `domain`, `ip`, `tcp`, `ether` all come from the `net` scanner;
// `ccn`, `ccn_track2`, `telephone` come from `accts`; `rfc822` comes from
// `email`. v0.2.13 uses this mapping so the per-feature Labels match the
// scanner names the analyst sees in the Scanners checklist, instead of
// invented names that don't appear anywhere in the dialog.
//
// Source for the mapping: bulk_extractor 2.0.x documentation + reading
// scanner_*.cpp files in upstream src/ tree; 2.2.0 additions verified via
// `bulk_extractor64.exe -H` (each new scanner's "Feature Names" equals its
// scanner name). Feature file names that aren't in this table fall through
// to the original feature name, so we degrade gracefully if BE adds new
// feature outputs.
static std::wstring FeatureToScanner(const std::wstring& featureName) {
    static const struct { const wchar_t* feature; const wchar_t* scanner; } kMap[] = {
        // accts scanner — credit cards, SSNs, telephone numbers
        {L"accts",                  L"accts"},
        {L"ccn",                    L"accts"},
        {L"ccn_track2",             L"accts"},
        {L"telephone",              L"accts"},
        {L"pii",                    L"accts"},
        {L"pii_teamviewer",         L"accts"},
        // aes scanner — symmetric encryption keys
        {L"aes_keys",               L"aes"},
        // base16 / base64 — encoded binary
        {L"base16",                 L"base16"},
        {L"base64",                 L"base64"},
        // elf — Linux/Unix executables
        {L"elf",                    L"elf"},
        // email scanner — addresses, RFC 822 headers
        {L"email",                  L"email"},
        {L"rfc822",                 L"email"},
        // evtx scanner — Windows event log records
        {L"evtx_carved",            L"evtx"},
        // exif scanner — image metadata
        {L"exif",                   L"exif"},
        // facebook scanner — Facebook IDs / URLs
        {L"facebook",               L"facebook"},
        // find scanner — user-supplied regex matches
        {L"find",                   L"find"},
        // gps scanner — GPS coordinates
        {L"gps",                    L"gps"},
        // gzip scanner — gzipped streams
        {L"gzip",                   L"gzip"},
        // hex feature recorder (NOT a standalone scanner — multiple scanners
        // write hex-encoded content to hex.txt as a shared output channel).
        // Mapped to itself so the resulting label clearly says "hex" — the
        // analyst can interpret it as "the hex-encoded byte channel" rather
        // than expecting a corresponding scanner toggle in the dialog.
        {L"hex",                    L"hex"},
        // hiberfile scanner — hiberfile.sys carving
        {L"hiberfile",              L"hiberfile"},
        // httplogs scanner — HTTP-style log fragments
        {L"httplogs",               L"httplogs"},
        // json scanner — embedded JSON
        {L"json",                   L"json"},
        // kml_carved scanner — Google Earth KML
        {L"kml",                    L"kml_carved"},
        {L"kml_carved",             L"kml_carved"},
        // msxml scanner — Office XML
        {L"msxml",                  L"msxml"},
        // net scanner — network artefacts (URLs, domains, IPs, MACs, TCP)
        {L"domain",                 L"net"},
        {L"ether",                  L"net"},
        {L"ip",                     L"net"},
        {L"tcp",                    L"net"},
        {L"url",                    L"net"},
        {L"url_facebook-address",   L"net"},
        {L"url_facebook-id",        L"net"},
        {L"url_microsoft-live",     L"net"},
        {L"url_searches",           L"net"},
        {L"url_services",           L"net"},
        // ntfs* scanners — NTFS structure carving
        {L"ntfs_indx_carved",       L"ntfsindx"},
        {L"ntfs_logfile",           L"ntfslogfile"},
        {L"ntfs_mft",               L"ntfsmft"},
        {L"ntfs_usn",               L"ntfsusn"},
        // outlook scanner — PST/OST internals
        {L"outlook_pst",            L"outlook"},
        // pdf scanner — PDF text extraction
        {L"pdf",                    L"pdf"},
        // rar scanner — RAR archive carving
        {L"rar",                    L"rar"},
        // rtti scanner (BE 2.2.0+) — RawTherapee 8-bit thumbnail carving
        {L"rtti",                   L"rtti"},
        // sqlite scanner — SQLite databases
        {L"sqlite_carved",          L"sqlite"},
        // utmp scanner — Unix login records
        {L"utmp_carved",            L"utmp"},
        // vcard_carved scanner
        {L"vcard",                  L"vcard_carved"},
        {L"vcard_carved",           L"vcard_carved"},
        // vin scanner (BE 2.2.0+) — Vehicle Identification Numbers
        {L"vin",                    L"vin"},
        // windirs scanner — Windows directory artefacts
        {L"windirs",                L"windirs"},
        {L"windows_directories",    L"windirs"},
        // winlnk scanner — Windows shortcut files
        {L"winlnk",                 L"winlnk"},
        {L"winlnk_dest",            L"winlnk"},
        // winpe scanner — Windows PE files
        {L"winpe",                  L"winpe"},
        {L"winpe_unconfirmed",      L"winpe"},
        // winprefetch scanner — Prefetch records
        {L"winprefetch",            L"winprefetch"},
        // wordlist scanner — token list (typically not flagged as hits)
        {L"wordlist",               L"wordlist"},
        // xor scanner — XOR-obfuscated content discovery
        {L"xor",                    L"xor"},
        // zip scanner — ZIP archive carving
        {L"zip",                    L"zip"},
    };
    for (const auto& m : kMap) {
        if (featureName == m.feature) return m.scanner;
    }
    return featureName;  // unknown — degrade gracefully
}

static FeatureHits CollectHitsByFeature(const std::wstring& outputDir) {
    FeatureHits result;
    std::wstring pattern = outputDir + L"\\*.txt";
    WIN32_FIND_DATAW fd = {};
    HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return result;

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::wstring fname = fd.cFileName;
        // Skip histograms (rolled-up duplicates of feature content).
        if (fname.size() >= 14) {
            std::wstring tail = fname.substr(fname.size() - 14);
            std::wstring lower(tail.size(), L'\0');
            for (size_t i = 0; i < tail.size(); ++i) lower[i] = (wchar_t)towlower(tail[i]);
            if (lower == L"_histogram.txt") continue;
        }
        // Feature name = filename without ".txt" suffix (case-insensitive).
        std::wstring featureName = fname;
        if (featureName.size() >= 4) {
            std::wstring tail4(4, L'\0');
            for (size_t i = 0; i < 4; ++i)
                tail4[i] = (wchar_t)towlower(featureName[featureName.size() - 4 + i]);
            if (tail4 == L".txt") featureName.resize(featureName.size() - 4);
        }
        if (featureName.empty()) continue;

        std::wstring full = outputDir + L"\\" + fname;
        std::ifstream f(full);
        if (!f) continue;
        std::string line;
        auto& featureSet = result.byFeature[featureName];
        while (std::getline(f, line)) {
            if (line.empty() || line[0] == '#') continue;
            // Find the `xwitem_NNN_` token. Multiple may appear; we only need one.
            size_t p = 0;
            while ((p = line.find("xwitem_", p)) != std::string::npos) {
                size_t numStart = p + 7;
                size_t numEnd   = numStart;
                while (numEnd < line.size() && line[numEnd] >= '0' && line[numEnd] <= '9') ++numEnd;
                if (numEnd > numStart && numEnd < line.size() && line[numEnd] == '_') {
                    long id = strtol(line.c_str() + numStart, nullptr, 10);
                    featureSet.insert((LONG)id);
                    result.union_.insert((LONG)id);
                    break;
                }
                p = numEnd;
            }
        }
        // Drop empty feature buckets so callers don't iterate dead entries.
        if (featureSet.empty()) result.byFeature.erase(featureName);
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
    return result;
}

// =============================================================================
//  Selected-items export pipeline
// =============================================================================
//   Export each selected item into a fresh temp dir under names that embed the
//   item ID, so feature-file walking can map hits back to source items.
//   Returns the path of the temp dir on success (caller is responsible for
//   cleanup if desired); empty string on failure.

struct ExportResult {
    std::wstring tempDir;
    int          exported       = 0;
    int          exportFailed   = 0;
    int          virtualSkipped = 0;  // v0.2.4: virtual/unreadable items (e.g. Free space)
    int          taggedScanned  = 0;
};

static ExportResult ExportSelectedItems(HANDLE hVolume, HANDLE hEvidence,
                                        const std::vector<LONG>& selected,
                                        bool tagScanned) {
    ExportResult r;
    r.tempDir = CreateUniqueTempDir(hEvidence, L"input");
    if (r.tempDir.empty()) return r;

    for (LONG itemID : selected) {
        if (!XWF_GetItemSize) continue;
        INT64 sz = XWF_GetItemSize(itemID);
        if (sz <= 0) continue;  // skip empty/dir/unknown

        const wchar_t* nm = XWF_GetItemName ? XWF_GetItemName(itemID) : L"";
        std::wstring leaf = SanitizeForFilename(nm ? nm : L"");
        // Cap leaf length to keep paths short.
        if (leaf.size() > 64) leaf = leaf.substr(0, 64);

        wchar_t prefix[32];
        swprintf_s(prefix, L"xwitem_%ld_", itemID);
        std::wstring fname = std::wstring(prefix) + leaf + L".bin";
        std::wstring dest  = r.tempDir + L"\\" + fname;

        ExportOutcome outcome = ExportItemToFile(hVolume, itemID, dest);
        switch (outcome) {
        case ExportOutcome::Ok:
            ++r.exported;
            LogVerbose(L"  exported: " + fname);
            // Tag the source item as "scanned" the moment we successfully
            // export it — this way even a partial run leaves an audit trail
            // showing which items were submitted to bulk_extractor.
            if (tagScanned && (XWF_Label || XWF_AddToReportTable)) {
                if (XWF_Label ? XWF_Label(itemID, REPORT_TABLE_SCANNED,
                                          REPORT_TABLE_FLAG_CREATED_BY_APP)
                              : XWF_AddToReportTable(itemID, REPORT_TABLE_SCANNED,
                                                     REPORT_TABLE_FLAG_CREATED_BY_APP)) {
                    ++r.taggedScanned;
                }
            }
            break;
        case ExportOutcome::VirtualOrEmpty:
            ++r.virtualSkipped;
            LogVerbose(L"  skipped (virtual / unreadable): " + fname);
            break;
        case ExportOutcome::Failed:
            ++r.exportFailed;
            Log(L"  export FAILED: " + fname);
            break;
        }
    }
    return r;
}

// =============================================================================
//  Main run flow (called from XT_Prepare for non-DBC modes, XT_Finalize for DBC)
// =============================================================================
// =============================================================================
//  The run body, split into three phases so the dialog's worker thread never
//  touches the XWF_* API (threading gate):
//    A  PrepareRunInput -- resolve the input; SelectedItems extracts item
//       bytes (XWF_OpenItem/Read) and may tag via XWF_Label. X-Ways thread.
//    B  ExecuteBeRun    -- validate + identity-gate the BE binary, create the
//       output dir, spawn bulk_extractor and wait. No XWF calls beyond Log()
//       (XWF_OutputMessage, thread-tolerant); safe on the worker thread.
//    C  PostProcessRun  -- open folder, add-as-evidence (XWF_CreateEvObj),
//       feature-file hit tagging (XWF_Label), temp-dir cleanup. X-Ways thread.
//  Dialog path: A runs in IDOK, B on the worker, C in WM_APP_DONE.
//  Error/reject paths Log() only (no MessageBox). Mutate-status is reported
//  via prep.didMutate / *outDidMutate (threaded to g_run.didMutate so
//  XT_Finalize can return 0x02).
// =============================================================================

static bool PrepareRunInput(const RunCtx& ctx, const Settings& s, RunPrep& prep) {
    switch (s.inputMode) {
    case InputMode::ActiveEoImage: {
        std::wstring p = TrimW(s.inputPath);
        if (p.empty()) {
            Log(L"This evidence object does not expose a source path "
                L"(common for physical-disk EOs). Use 'Pick file or directory' instead.");
            PostWorkerStatus(L"Failed: evidence object has no source path.");
            return false;
        }
        prep.inputForBE = p;
        break;
    }
    case InputMode::PickPath: {
        std::wstring p = TrimW(s.inputPath);
        if (p.empty() || (!FileExists(p) && !DirExists(p))) {
            Log(L"Input path does not exist.");
            PostWorkerStatus(L"Failed: input path does not exist.");
            return false;
        }
        prep.inputForBE = p;
        break;
    }
    case InputMode::SelectedItems: {
        if (ctx.selected.empty()) {
            Log(L"No items were selected.");
            PostWorkerStatus(L"Failed: no items selected.");
            return false;
        }
        Log(L"exporting selected items to temp dir...");
        PostWorkerStatus(L"Exporting selected items…");
        ExportResult er = ExportSelectedItems(ctx.hVolume, ctx.hEvidence, ctx.selected, s.tagScanned);
        if (er.tempDir.empty() || er.exported == 0) {
            Log(L"Failed to export selected items to temp dir.");
            PostWorkerStatus(L"Failed: could not export selected items.");
            return false;
        }
        wchar_t buf[160];
        swprintf_s(buf, L"exported %d item(s) to %s",
                   er.exported, er.tempDir.c_str());
        Log(buf);
        if (er.exportFailed > 0) {
            swprintf_s(buf, L"  (%d failed to export)", er.exportFailed);
            Log(buf);
        }
        if (er.virtualSkipped > 0) {
            swprintf_s(buf, L"  (%d virtual / unreadable item(s) skipped)",
                       er.virtualSkipped);
            Log(buf);
        }
        if (s.tagScanned && er.taggedScanned > 0) {
            swprintf_s(buf, L"  tagged %d item(s) as \"%s\"",
                       er.taggedScanned, REPORT_TABLE_SCANNED);
            Log(buf);
            prep.didMutate = true;
        }
        prep.tempInputDir = er.tempDir;
        prep.inputForBE   = er.tempDir;
        break;
    }
    }
    return true;
}

static RunOutcome ExecuteBeRun(const Settings& s, const RunPrep& prep,
                               bool pumpMessages, DWORD& exitCodeOut) {
    const std::wstring& inputForBE = prep.inputForBE;

    // --- Validate BE binary --------------------------------------------
    // WSL mode: the binary lives in the Linux filesystem, not on Windows
    // side, so FileExists() can't help. Just require the field is non-empty.
    bool beValid;
    if (s.useWsl) {
        beValid = !TrimW(s.wslBeBinary).empty();
    } else {
        beValid = !TrimW(s.beBinary).empty() && FileExists(s.beBinary);
    }
    if (!beValid) {
        Log(L"bulk_extractor binary path is empty or does not point to a real file "
            L"— set it in the dialog / cfg.");
        PostWorkerStatus(L"Failed: bulk_extractor binary not found.");
        return RunOutcome::PrereqFailed;
    }

    // v0.4.0: final identity gate before spawn (native mode only — the WSL
    // binary can't be inspected from Windows). Reject hard — log the reason
    // verbatim and bail rather than launch some other exe with the BE CLI shape.
    // (PE VERSIONINFO + banner probe of a file on disk — no XWF calls.)
    if (!s.useWsl) {
        std::wstring idDetail;
        if (!VerifyHelperIdentity(s.beBinary, kHelperIdentityNeedle, idDetail)) {
            Log(L"REJECTED native bulk_extractor binary before run (" +
                s.beBinary + L") — " + idDetail);
            PostWorkerStatus(L"Failed: not a valid bulk_extractor binary.");
            return RunOutcome::PrereqFailed;
        }
        Log(L"bulk_extractor binary verified before run (" + s.beBinary + L") — " + idDetail);
    }

    // --- Make sure output dir exists ------------------------------------
    if (!DirExists(s.outputDir)) {
        // CreateDirectory does not auto-create intermediate dirs. Build them.
        std::wstring p; p.reserve(s.outputDir.size());
        for (size_t i = 0; i < s.outputDir.size(); ++i) {
            p.push_back(s.outputDir[i]);
            if (s.outputDir[i] == L'\\' || i == s.outputDir.size() - 1) {
                if (!p.empty() && !DirExists(p)) CreateDirectoryW(p.c_str(), nullptr);
            }
        }
        if (!DirExists(s.outputDir)) {
            Log(L"Failed to create output directory: " + s.outputDir);
            if (!prep.tempInputDir.empty()) {
                Log(L"selected-items temp dir KEPT (output dir failed) at: " + prep.tempInputDir);
            }
            PostWorkerStatus(L"Failed: could not create output directory.");
            return RunOutcome::PrereqFailed;
        }
    }
    // A reused output dir is analyst error: pre-2.2.0 BE refuses to run if it
    // already contains BE artifacts; 2.2.0's restart logic instead exits 0
    // without processing anything (verified 2026-08-19). Either way the fix is
    // the same — pick an empty / new dir. Just log what BE reports.
    Log(L"output dir: "    + s.outputDir);
    Log(L"input for BE: "  + inputForBE);
    if (s.useWsl) {
        Log(L"running via WSL: " + s.wslBeBinary);
    }

    // --- Run BE ---------------------------------------------------------
    std::wstring runErr;
    PostWorkerStatus(L"Running bulk_extractor… (see console window)");
    bool ok = RunBulkExtractor(s, inputForBE, exitCodeOut, runErr, pumpMessages);
    {
        wchar_t buf[160];
        swprintf_s(buf, L"bulk_extractor exit code: %lu", (unsigned long)exitCodeOut);
        Log(buf);
    }
    if (!ok && !runErr.empty()) Log(L"error: " + runErr);
    return ok ? RunOutcome::RanOk : RunOutcome::RanFailed;
}

static void PostProcessRun(const Settings& s, const RunPrep& prep,
                           bool beRanOk, bool* outDidMutate) {
    if (s.openFolder) OpenInExplorer(s.outputDir);

    if (s.addToCase) {
        if (AddOutputAsEvidence(s.outputDir)) {
            if (outDidMutate) *outDidMutate = true;
        } else {
            Log(L"(could not add output as evidence object — see prior message)");
        }
    }

    if (s.tagHits && s.inputMode == InputMode::SelectedItems) {
        FeatureHits fh = CollectHitsByFeature(s.outputDir);
        // 1) Always (when tagHits) apply the umbrella "bulk_extractor hits"
        //    label to every item with at least one hit in any feature.
        UINT64 tagged = 0;
        if (XWF_Label || XWF_AddToReportTable) {
            for (LONG id : fh.union_) {
                if (XWF_Label ? XWF_Label(id, REPORT_TABLE_HITS,
                                          REPORT_TABLE_FLAG_CREATED_BY_APP)
                              : XWF_AddToReportTable(id, REPORT_TABLE_HITS,
                                                     REPORT_TABLE_FLAG_CREATED_BY_APP)) {
                    ++tagged;
                }
            }
        }
        if (tagged > 0 && outDidMutate) *outDidMutate = true;
        wchar_t buf[200];
        swprintf_s(buf,
            L"feature-file scan: %zu source item(s) had hits; tagged %llu with \"%s\"",
            fh.union_.size(), (unsigned long long)tagged, REPORT_TABLE_HITS);
        Log(buf);

        // 2) v0.2.11 sub-option (refined v0.2.13): apply per-scanner labels in
        //    addition to the umbrella label. Aggregate the per-feature map into
        //    a per-scanner map via FeatureToScanner — url.txt, domain.txt, ip.txt
        //    etc. all collapse to the `net` scanner so the analyst sees Labels
        //    like "bulk_extractor: net" that match the Scanners checklist.
        if (s.tagHitsPerFeature && (XWF_Label || XWF_AddToReportTable) && !fh.byFeature.empty()) {
            std::unordered_map<std::wstring, std::unordered_set<LONG>> byScanner;
            for (const auto& kv : fh.byFeature) {
                std::wstring scanner = FeatureToScanner(kv.first);
                if (scanner.empty()) continue;  // skip unmapped/system entries
                auto& dst = byScanner[scanner];
                dst.insert(kv.second.begin(), kv.second.end());
            }

            std::vector<std::wstring> scanners;
            scanners.reserve(byScanner.size());
            for (const auto& kv : byScanner) scanners.push_back(kv.first);
            std::sort(scanners.begin(), scanners.end());

            UINT64 perScannerLabels = 0;
            UINT64 perScannerApplications = 0;
            for (const std::wstring& scanner : scanners) {
                std::wstring label = L"bulk_extractor: " + scanner;
                UINT64 thisCount = 0;
                for (LONG id : byScanner[scanner]) {
                    if (XWF_Label ? XWF_Label(id, label.c_str(),
                                              REPORT_TABLE_FLAG_CREATED_BY_APP)
                                  : XWF_AddToReportTable(id, label.c_str(),
                                                         REPORT_TABLE_FLAG_CREATED_BY_APP)) {
                        ++thisCount;
                    }
                }
                if (thisCount > 0) {
                    ++perScannerLabels;
                    perScannerApplications += thisCount;
                    swprintf_s(buf,
                        L"  per-scanner: \"%s\" -> %llu item(s)",
                        label.c_str(), (unsigned long long)thisCount);
                    Log(buf);
                }
            }
            swprintf_s(buf,
                L"per-scanner tagging: %llu label(s) applied across %llu item(s)",
                (unsigned long long)perScannerLabels,
                (unsigned long long)perScannerApplications);
            Log(buf);
            if (perScannerApplications > 0 && outDidMutate) *outDidMutate = true;
        }
    }

    // v0.2.4: cleanup the selected-items export temp dir.
    if (!prep.tempInputDir.empty()) {
        if (beRanOk && !s.keepTempDir) {
            if (DeleteDirRecursive(prep.tempInputDir)) {
                Log(L"selected-items temp dir cleaned up: " + prep.tempInputDir);
            } else {
                Log(L"selected-items temp dir cleanup FAILED at: " + prep.tempInputDir);
            }
        } else if (!beRanOk) {
            Log(L"selected-items temp dir KEPT (BE failed) at: " + prep.tempInputDir);
        } else {
            Log(L"selected-items temp dir KEPT (keep_temp_dir=true) at: " + prep.tempInputDir);
        }
    }
}

// Spawn the subprocess phase on a JOINABLE worker thread (dialog mode). The
// dialog stays open in a running state; the worker posts WM_APP_DONE when
// finished and is joined there (P2). IDOK has already run Phase A and copied
// the resolved inputs into g_workerSettings / g_workerPrep.
static void StartBeWorker(HWND hDlg) {
    g_workerActive.store(true);
    g_cancelRequested.store(false);     // clear stale state from any prior run
    g_runStartTick = GetTickCount64();

    // Lock out settings + Run. Cancel (IDCANCEL) stays enabled; its label stays
    // "Cancel" but its semantics flip to abort (handled in IDCANCEL, Phase 3).
    EnableWindow(GetDlgItem(hDlg, IDOK), FALSE);
    for (int id : kRunLockIds) {
        HWND h = GetDlgItem(hDlg, id);
        if (h) EnableWindow(h, FALSE);
    }
    for (int i = 0; i < kNumScanners; ++i) {
        HWND h = GetDlgItem(hDlg, IDC_SCANNER_BASE + i);
        if (h) EnableWindow(h, FALSE);
    }
    SetBeStatus(hDlg,
                    L"Running bulk_extractor… 00:00 (see console window)");
    SetTimer(hDlg, kElapsedTimerId, 100, nullptr);   // v0.5.0: 100 ms drives the marquee

    // JOINABLE worker (P2) running ONLY the subprocess phase (P1 -- no XWF_*
    // calls off X-Ways' thread). g_workerSettings / g_workerPrep are stable
    // copies made by IDOK before this call, so the lambda can read them after
    // IDOK returns. Reaped in WM_APP_DONE (and XT_Done as a safety net).
    if (g_workerThread.joinable()) g_workerThread.join();  // reap any prior run
    g_workerThread = std::thread([]() {
        DWORD exitCode = 0;
        RunOutcome oc = ExecuteBeRun(g_workerSettings, g_workerPrep,
                                     /*pumpMessages=*/false, exitCode);
        int code;
        if (oc == RunOutcome::PrereqFailed) code = 3;
        else if (g_cancelRequested.load())  code = 1;
        else if (oc == RunOutcome::RanOk)   code = 0;
        else                                code = 2;
        PostWorkerDone(code);   // exactly one DONE per run; Phase C + the
                                // final status text happen in the handler
    });
}

static void RunFlow(HWND parent, RunCtx& ctx) {
    // v0.2.3 guard: per 21.4 SR-5, hVolume passed to XT_Prepare/XT_Finalize is
    // NULL when the X-Tension is invoked from the **Case Root** window. Our
    // selected-items mode reads items via XWF_OpenItem(hVolume, ...) and would
    // AV with a NULL handle. Bail with a friendly explanation.
    if (ctx.selectionMode && !ctx.hVolume) {
        Log(L"selected-items mode requires invocation from a partition or image "
            L"directory browser, not the Case Root window.");
        MessageBoxW(parent,
            L"bulk_extractor's 'selected items' mode needs to read item bytes "
            L"from the underlying volume, but X-Ways did not pass a volume "
            L"handle (this happens when the X-Tension is invoked from the "
            L"Case Root window).\n\n"
            L"Right-click the items inside the partition / image directory "
            L"browser instead, then run bulk_extractor.",
            L"bulk_extractor", MB_OK | MB_ICONWARNING);
        return;
    }

    // Build defaults.
    Settings s;
    std::wstring selfDir = GetSelfDirectory();
    CfgValues cfg = LoadCfg(selfDir);

    // BE binary: cfg override > bundled default.
    if (!cfg.be_binary.empty()) {
        s.beBinary = cfg.be_binary;
    } else {
        std::wstring bundled = selfDir + L"\\bulk_extractor64.exe";
        if (FileExists(bundled)) s.beBinary = bundled;
    }

    // v0.3.0: WSL BE binary. Sidecar override > detection > empty. The
    // dialog also disables the "Run via WSL" checkbox if detection failed.
    if (!cfg.wsl_be_binary.empty()) {
        s.wslBeBinary = cfg.wsl_be_binary;
    } else {
        const WslInfo& wsl = DetectWslOnce();
        if (wsl.be_available) s.wslBeBinary = wsl.be_path;
    }
    // Default-checked state from sidecar; only honor if WSL is actually
    // available so the dialog doesn't appear pre-checked when it can't
    // function.
    {
        const WslInfo& wsl = DetectWslOnce();
        s.useWsl = cfg.use_wsl_default && wsl.wsl_present && wsl.be_available;
    }

    // Output dir: cfg override > suggestion based on case dir.
    s.outputDir = !cfg.default_output_dir.empty() ? cfg.default_output_dir : SuggestOutputDir();

    // v0.2.4: pull keep_temp_dir from sidecar (default off → auto-clean).
    s.keepTempDir = cfg.keep_temp_dir;

    // Threads: system cores -> dropdown range, default = half (rounded up)
    // so the analyst keeps headroom for X-Ways + OS while BE is grinding.
    SYSTEM_INFO sysinfo = {}; GetSystemInfo(&sysinfo);
    s.threadsMax = (int)sysinfo.dwNumberOfProcessors;
    if (s.threadsMax < 1) s.threadsMax = 1;
    s.threads = (s.threadsMax + 1) / 2;

    // Scanner defaults match BE's defaults (parallel to kScanners).
    s.scannerOn.assign(kNumScanners, false);
    for (int i = 0; i < kNumScanners; ++i) s.scannerOn[i] = kScanners[i].defaultEnabled;

    // Context-driven UI defaults.
    s.selectionMode = ctx.selectionMode;
    s.selectedCount = (int)ctx.selected.size();

    // v0.3.1: probe the active EO's volume handle for the source path via
    // XWF_GetProp(hVol, 8, NULL) — the SDK's Python binding (Python.cpp:927)
    // wraps this as GetFilePath(hVolumeOrItem) returning the path as
    // wchar_t* through the INT64 return value (NULL buffer required).
    // Property 9 returns the pure name. The path is wrapped in [...] in
    // X-Ways' source-notation format; strip the brackets after deref.
    //
    // Two-stage chain:
    //   1. Active EO's hVolume.
    //   2. If no path AND parent EO exists: XWF_OpenEvObj(parent) → its
    //      volume → GetProp(vol, 8). Empirically: partitions inside a
    //      disk-image EO have no source path of their own; the parent
    //      disk EO's volume returns the .E01 file path.
    //
    // Every probe value is logged so the analyst can see what was tried.
    auto stripBrackets = [](std::wstring s) -> std::wstring {
        // X-Ways "source notation" embeds the path in [...]:
        //   "[C:\path\foo.E01]"                 → C:\path\foo.E01
        //   "[C:\path\foo.E01], Partition 2"    → C:\path\foo.E01    (partition-mode)
        //   "Image1 [C:\path\foo.E01]"          → C:\path\foo.E01    (titled)
        //   "foo.E01]"                          → foo.E01            (pure-name idiosyncrasy)
        s = TrimW(s);
        size_t lp = s.find(L'[');
        if (lp != std::wstring::npos) {
            size_t rp = s.find(L']', lp + 1);
            std::wstring inner = (rp == std::wstring::npos)
                ? s.substr(lp + 1)
                : s.substr(lp + 1, rp - lp - 1);
            return TrimW(inner);
        }
        if (!s.empty() && s.back() == L']') s.pop_back();
        return TrimW(s);
    };
    auto safeDerefWcs = [](INT64 rv) -> std::wstring {
        wchar_t snapshot[1024] = {0};
        int n = SafeWcsCopyFromPtr(rv, snapshot, 1024);
        if (n <= 0) return {};
        return std::wstring(snapshot);
    };
    auto probeVolForPath = [&](HANDLE vol, const wchar_t* label) -> std::wstring {
        if (!vol || !XWF_GetProp) return {};
        INT64 rv8 = XWF_GetProp(vol, 8, nullptr);
        std::wstring raw = safeDerefWcs(rv8);
        std::wstring stripped = StripExtendedPathPrefix(stripBrackets(raw));

        Log(std::wstring(L"  ") + label + L" GetProp(vol, 8 file-path) raw: " +
            (raw.empty() ? std::wstring(L"<empty>") : raw));

        if (!stripped.empty() && (FileExists(stripped) || DirExists(stripped))) {
            Log(std::wstring(L"  source resolved from ") + label +
                L" volume file-path: " + stripped);
            return stripped;
        }
        return {};
    };

    std::wstring activeSrc;
    {
        std::wstring reason;
        if (!XWF_GetProp) {
            reason = L"XWF_GetProp not available (need X-Ways 21.x+)";
        } else if (!ctx.hVolume && !ctx.hEvidence) {
            reason = L"no active evidence object handle in this context";
        } else {
            // Stage 1 — probe the active EO's volume directly.
            if (ctx.hVolume) activeSrc = probeVolForPath(ctx.hVolume, L"EO");

            // Stage 2 — walk to the parent EO and open its volume.
            // Partitions inside a disk-image EO show this pattern: the
            // partition's hVolume returns no path, but the parent disk EO's
            // volume returns the .E01 source.
            if (activeSrc.empty() && XWF_GetEvObj && XWF_GetEvObjProp &&
                XWF_OpenEvObj && ctx.hEvidence)
            {
                INT64 parentId = XWF_GetEvObjProp(ctx.hEvidence, 2, nullptr);
                {
                    wchar_t buf[64];
                    swprintf_s(buf, L"  EO property 2 (parent EO ID): %lld",
                               (long long)parentId);
                    Log(buf);
                }
                if (parentId > 0) {
                    HANDLE parentEO = XWF_GetEvObj((DWORD)parentId);
                    if (parentEO) {
                        HANDLE parentVol = XWF_OpenEvObj(parentEO, 0);
                        if (parentVol) {
                            activeSrc = probeVolForPath(parentVol, L"parent EO");
                            if (XWF_CloseEvObj) XWF_CloseEvObj(parentVol);
                        } else {
                            Log(L"  XWF_OpenEvObj returned NULL for parent EO");
                        }
                    } else {
                        Log(L"  XWF_GetEvObj returned NULL for parent ID");
                    }
                }
            }

            if (activeSrc.empty()) {
                reason = L"no parseable on-disk path found on this EO or its parent";
            }
        }
        if (!reason.empty()) Log(L"active EO source unavailable: " + reason);
        s.hasActiveEoImage    = !activeSrc.empty();
        s.eoUnavailableReason = reason;
    }
    if (ctx.selectionMode) {
        s.inputMode = InputMode::SelectedItems;
        // tagScanned + tagHits both default ON in Settings already; nothing to flip here.
    } else if (s.hasActiveEoImage) {
        s.inputMode = InputMode::ActiveEoImage;
        s.inputPath = activeSrc;
    }

    // Show dialog. The dialog now HOSTS the run on a worker thread
    // (IDOK -> StartBeWorker); ShowSettingsDialog returns only after the dialog
    // closes (idle Cancel, or Close after the worker posted WM_APP_DONE).
    // ctx.didMutate was threaded back into g_run by the WM_APP_DONE handler.
    if (!ShowSettingsDialog(parent, s)) {
        // Dialog closed. The run (if any) executed on the worker thread.
        return;
    }
    // (Run executed on the worker; ctx.didMutate already set via g_run in the
    //  WM_APP_DONE handler. Nothing further to do here.)
}

// =============================================================================
//  Entry points
// =============================================================================
extern "C" {

LONG __stdcall XT_Init(DWORD nVersion, DWORD nFlags, HWND hMainWnd, void*) {
    if (nFlags & 0x20) return 1;  // QUICKCHECK — accept without further work
    g_hMainWnd = hMainWnd;
    int missing = RetrieveFunctionPointers();
    wchar_t buf[200];
    swprintf_s(buf, L"%s %s — X-Ways build %.2f, %d missing exports",
               NAME, VERSION, nVersion / 100.0, missing);
    Log(buf);
    if (!XWF_OutputMessage) return -1;  // bare minimum to be useful
    return 1;
}

LONG __stdcall XT_About(HWND hParentWnd, void*) {
    std::wstring msg = NAME; msg += L" "; msg += VERSION; msg += L"\n"; msg += DESCRIPTION;
    if (XWF_OutputMessage) XWF_OutputMessage(msg.c_str(), 0);
    // v0.5.0: same About dialog the in-dialog button shows.
    ShowAboutDialog(hParentWnd ? hParentWnd : g_hMainWnd);
    return 0;
}

LONG __stdcall XT_Prepare(HANDLE hVolume, HANDLE hEvidence, DWORD nOpType, void*) {
    g_run = RunCtx{};
    g_run.hVolume   = hVolume;
    g_run.hEvidence = hEvidence;

    if (nOpType == XT_ACTION_DBC) {
        // Defer dialog + actual work to XT_Finalize after we've collected the
        // selected items via XT_ProcessItem.
        g_run.selectionMode = true;
        return 0x01;  // request XT_ProcessItem callbacks
    }

    // Non-DBC: dialog + run synchronously here.
    RunFlow(g_hMainWnd, g_run);
    return 0;
}

LONG __stdcall XT_ProcessItem(LONG nItemID, void*) {
    if (g_run.selectionMode) g_run.selected.push_back(nItemID);
    return 0;
}

LONG __stdcall XT_Finalize(HANDLE, HANDLE, DWORD nOpType, void*) {
    if (nOpType == XT_ACTION_DBC && g_run.selectionMode) {
        RunFlow(g_hMainWnd, g_run);
    }
    // 0x02 = ask X-Ways to save the volume snapshot (added v21.3 Preview 3).
    // Set when the run added Labels via XWF_AddToReportTable or attached an
    // output evidence object via XWF_CreateEvObj — saves the analyst a
    // manual save step. Older X-Ways builds ignore the flag harmlessly.
    bool didMutate = g_run.didMutate;
    g_run = RunCtx{};
    return didMutate ? 0x02 : 0;
}

LONG __stdcall XT_Done(void*) {
    // P2 safety net: never let X-Ways unload the DLL while the worker thread
    // is alive (FreeLibrary with a running thread in DLL code = crash).
    if (g_workerThread.joinable()) {
        Log(L"XT_Done: waiting for the bulk_extractor worker to finish...");
        g_cancelRequested.store(true);
        g_workerThread.join();
    }
    Log(L"XT_Done");
    return 0;
}

}  // extern "C"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) g_hSelf = hModule;
    return TRUE;
}

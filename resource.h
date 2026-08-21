#pragma once

// Dialog
#define IDD_SETTINGS                100

// Input source group
#define IDC_GROUP_INPUT             101
#define IDC_RADIO_INPUT_EVOIMAGE    102
#define IDC_RADIO_INPUT_PICK        103
#define IDC_RADIO_INPUT_SELECTED    104
#define IDC_EDIT_INPUT_PATH         105
#define IDC_BTN_BROWSE_INPUT_FILE   106
#define IDC_BTN_BROWSE_INPUT_DIR    107
#define IDC_STATIC_SELECTED_COUNT   108
#define IDC_STATIC_EO_HINT          109

// Output dir
#define IDC_LABEL_OUTPUT            110
#define IDC_EDIT_OUTPUT_DIR         111
#define IDC_BTN_BROWSE_OUTPUT       112

// BE binary
#define IDC_LABEL_BE_BIN            120
#define IDC_EDIT_BE_BIN             121
#define IDC_BTN_BROWSE_BE           122
#define IDC_CHK_USE_WSL             123  // v0.3.0: run BE via WSL
#define IDC_STATIC_WSL_VERSION      124  // shows detected BE-in-WSL version
// v0.4.0: helper-exe identity verification status line (below the BE-binary
// edit). Normally blank; turns bold-red "Not a valid bulk_extractor.exe file"
// and flashes when the resolved/picked native binary fails identity checks.
#define IDC_STATIC_BE_STATUS        125

// BE settings
#define IDC_LABEL_THREADS           130
#define IDC_COMBO_THREADS           131
#define IDC_LABEL_MAXRECURSE        132
#define IDC_EDIT_MAXRECURSE         133

// Scanners
#define IDC_GROUP_SCANNERS          140
#define IDC_BTN_RESET_SCANNERS      141
#define IDC_BTN_TOGGLE_ALL          142  // single button, smart Check / Uncheck all
// Scanner checkboxes are created programmatically in WM_INITDIALOG with
// IDs starting at IDC_SCANNER_BASE (one per entry in the kScanners array).
#define IDC_SCANNER_BASE            5000
#define IDC_SCANNER_LAST            5099

// v0.5.0: bottom bar — About + Open output live left of the status text on
// the Run/Cancel row.
#define IDC_BTN_ABOUT               160
#define IDC_BTN_OPEN_OUTPUT         161
// v0.5.0: binary group moved to the top; "Scan target:" summary line inside
// the Input source group.
#define IDC_GROUP_BINARY            162
#define IDC_LABEL_SCAN_TARGET       163
#define IDC_STATIC_SCAN_TARGET      164

// v0.5.0: About dialog (mirrors xways-ual-timeliner / xways-updater).
#define IDD_ABOUT                   200
#define IDC_ABOUT_TITLE             201
#define IDC_ABOUT_DESC              202
#define IDC_ABOUT_LABEL_AUTHOR_PREFIX 203
#define IDC_ABOUT_AUTHOR            204
#define IDC_ABOUT_LINK_GITHUB       205
#define IDC_ABOUT_LINK_TOOL         206  // upstream bulk_extractor repo
#define IDC_ABOUT_LINK_LINKEDIN     207
#define IDC_ABOUT_BTN_COFFEE        208

// Output handling
#define IDC_GROUP_OUTPUT            150
#define IDC_CHK_ADD_TO_CASE         151
#define IDC_CHK_OPEN_FOLDER         152
#define IDC_CHK_TAG_SCANNED         153
#define IDC_CHK_TAG_HITS            154
#define IDC_CHK_TAG_HITS_PER_FEATURE 155  // sub-option of IDC_CHK_TAG_HITS

// Worker thread posts these to the settings-dialog HWND (handled in
// SettingsDlgProc). See the in-DLL Cancel design spec.
//   WM_APP_STATUS: lParam = heap wchar_t* (dialog SetDlgItemText + delete[]).
//   WM_APP_DONE:   wParam  = 0 ok, 1 cancelled, 2 failed.
#define WM_APP_STATUS   (WM_APP + 1)
#define WM_APP_DONE     (WM_APP + 2)

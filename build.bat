@echo off
REM ============================================================================
REM  Build xways-bulk_extractor.dll (x64) with MSVC cl.exe + rc.exe.
REM  Auto-bootstraps VS x64 toolchain if cl.exe isn't on PATH.
REM ============================================================================

setlocal EnableDelayedExpansion

where cl >nul 2>nul && goto :have_toolchain
set "VCVARS="
for %%V in (
    "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
) do if not defined VCVARS if exist %%V set "VCVARS=%%~V"
if not defined VCVARS (
    echo ERROR: Could not find vcvars64.bat. Install MSVC C++ build tools.
    exit /b 1
)
echo Bootstrapping MSVC x64 environment from:
echo     !VCVARS!
call "!VCVARS!" >nul 2>nul
:have_toolchain

set NAME=xways-bulk_extractor
set OUT=%NAME%.dll
set CXXFLAGS=/nologo /std:c++17 /W3 /EHsc /O2 /utf-8 /DUNICODE /D_UNICODE
set LDFLAGS=/DLL /DEF:%NAME%.def /OUT:%OUT% /MACHINE:X64
REM Version.lib (v0.4.0): helper-exe identity verification reads the PE
REM VERSIONINFO resource via GetFileVersionInfo* / VerQueryValue.
set LIBS=Comdlg32.lib Shell32.lib User32.lib Ole32.lib Advapi32.lib Shlwapi.lib Gdi32.lib Version.lib

if exist *.obj del /q *.obj
if exist *.res del /q *.res

rc /nologo /fo %NAME%.res %NAME%.rc || goto :fail
cl %CXXFLAGS% /c %NAME%.cpp || goto :fail
link %LDFLAGS% %NAME%.obj %NAME%.res %LIBS% || goto :fail

echo.
echo Built: %OUT%

REM Project deployment convention: xtensions\<name>\<name>.dll — matches
REM X-Ways' xtensions\ auto-load folder. bulk_extractor64.exe goes into
REM the same per-X-Tension folder so xtension-relative path resolution
REM still finds it next to the DLL.
if not exist xtensions\%NAME% mkdir xtensions\%NAME%
copy /Y "%OUT%" "xtensions\%NAME%\%OUT%" >nul || goto :fail
echo Deployed: xtensions\%NAME%\%OUT%

REM v0.4.0: deploy the reference cfg alongside the DLL. The X-Tension reads a
REM live "bulk_extractor.cfg" next to the DLL (written by Ctrl+Run); this
REM .example documents every key without being auto-loaded.
if exist "%NAME%.cfg.example" copy /Y "%NAME%.cfg.example" "xtensions\%NAME%\%NAME%.cfg.example" >nul

REM Remove the project-root DLL so it can't be accidentally loaded from
REM there (cfg sidecars land next to the loaded DLL).
if exist "%OUT%" del /Q "%OUT%" 2>nul

if not exist "xtensions\%NAME%\bulk_extractor64.exe" (
    echo.
    echo NOTE: xtensions\%NAME%\bulk_extractor64.exe is missing.
    echo Drop the v2.0.0 binary in there to complete the bundle:
    echo   https://digitalcorpora.s3.amazonaws.com/downloads/bulk_extractor/bulk_extractor-2.0.0-windows.zip
)

exit /b 0

:fail
echo.
echo BUILD FAILED
exit /b 1

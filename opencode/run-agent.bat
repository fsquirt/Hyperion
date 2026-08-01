@echo off
rem ============================================================
rem  Hyperion analysis-machine launcher
rem  Uses HYPERION_WORKDIR so opencode keeps all data/config/cache/
rem  state under WorkDir (implemented in opencode global.ts).
rem  Does NOT redirect LOCALAPPDATA/APPDATA, so engine subprocesses
rem  (e.g. mcp-windbg Python) are not polluted.
rem ============================================================
setlocal EnableDelayedExpansion

rem ---- read WorkDir via ps1 (searches appsettings.json upward) ----
for /f "usebackq delims=" %%w in (`powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run-agent.ps1" -PrintWorkDir`) do set "WORKDIR=%%w"

if "%WORKDIR%"=="" (
    echo [ERROR] appsettings.json not found upward from %~dp0
    exit /b 1
)

rem ---- tell opencode to keep all data under WorkDir ----
set "HYPERION_WORKDIR=%WORKDIR%"
if not exist "%WORKDIR%\.opencode\config" mkdir "%WORKDIR%\.opencode\config"

rem ---- call ps1 to fetch cluster model and generate opencode.json ----
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run-agent.ps1" -AppSettingsPath "%~dp0appsettings.json"

echo.
echo Hyperion Agent start: WorkDir=%WORKDIR%
echo opencode data dir:    %WORKDIR%\.opencode
echo.

rem ---- launch opencode (TUI home is the Hyperion work mode) ----
opencode %*

endlocal

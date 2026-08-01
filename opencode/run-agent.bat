@echo off
rem ============================================================
rem  Hyperion analysis-machine launcher
rem  1) Redirect opencode data/config/state/cache into WorkDir so
rem     nothing is written to the machine user profile.
rem  2) Before starting, call server connect to fetch cluster LLM
rem     API (llm_apis) and generate opencode.json that registers the
rem     cluster provider and sets it as the default model, replacing
rem     opencode's built-in free default model (Big Pickle).
rem
rem  Usage: run this script (or double-click) to start the opencode TUI.
rem  Requires: this script and appsettings.json in the same directory.
rem ============================================================
setlocal EnableDelayedExpansion

rem ---- read WorkDir from appsettings.json ----
for /f "usebackq delims=" %%w in (`powershell -NoProfile -Command "$j=Get-Content '%~dp0appsettings.json' -Raw | ConvertFrom-Json; $j.WorkDir"`) do set "WORKDIR=%%w"

if "%WORKDIR%"=="" (
    echo [ERROR] WorkDir not found in appsettings.json.
    exit /b 1
)

rem ---- create WorkDir .opencode dirs ----
set "ODIR=%WORKDIR%\.opencode"
if not exist "%ODIR%" mkdir "%ODIR%"
if not exist "%ODIR%\config" mkdir "%ODIR%\config"

rem ---- redirect opencode global dirs into WorkDir (write only to WorkDir) ----
set "LOCALAPPDATA=%ODIR%"
set "APPDATA=%ODIR%"
set "XDG_DATA_HOME=%ODIR%\data"
set "XDG_CONFIG_HOME=%ODIR%\config"
set "XDG_CACHE_HOME=%ODIR%\cache"
set "XDG_STATE_HOME=%ODIR%\state"
set "OPENCODE_CONFIG_DIR=%ODIR%\config"
rem also redirect temp so agent intermediates do not hit system temp
set "TEMP=%WORKDIR%\.tmp"
set "TMP=%WORKDIR%\.tmp"
if not exist "%WORKDIR%\.tmp" mkdir "%WORKDIR%\.tmp"

rem ---- call ps1 to fetch cluster model and generate opencode.json ----
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run-agent.ps1" -AppSettingsPath "%~dp0appsettings.json"

echo.
echo Hyperion Agent start: WorkDir=%WORKDIR%
echo opencode data dir:    %ODIR%
echo temp dir:             %WORKDIR%\.tmp
echo.

rem ---- launch opencode (TUI home is the Hyperion work mode) ----
opencode %*

endlocal

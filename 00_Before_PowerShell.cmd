@echo off
setlocal ENABLEEXTENSIONS

REM Move to the directory where this script resides (equivalent to Set-Location to current/script dir)
set "SCRIPT_DIR=%~dp0"
pushd "%SCRIPT_DIR%" >nul 2>&1
echo [OpenDBTools] Working directory set to: "%CD%"

echo.
echo [OpenDBTools] This helper prepares PowerShell by setting the Execution Policy.
echo [OpenDBTools] Choose how you want to apply it:
echo   [1] Bypass -Scope CurrentUser   ^(recommended default^)
echo   [2] Bypass -Scope Process       ^(affects only this session^)
echo.
set "choice="
set /p choice="Enter choice (1/2) [default: 1]: "

if /I "%choice%"=="2" (
	set "EP_SCOPE=Process"
) else (
	set "EP_SCOPE=CurrentUser"
)

echo [OpenDBTools] Applying: Set-ExecutionPolicy Bypass -Scope %EP_SCOPE% -Force
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "Set-ExecutionPolicy Bypass -Scope %EP_SCOPE% -Force"
if errorlevel 1 (
	echo [OpenDBTools] WARNING: Failed to set Execution Policy. You may need admin rights or different policy settings. ^(ErrorLevel=%ERRORLEVEL%^)
) else (
	echo [OpenDBTools] Execution Policy applied successfully.
)

echo.
echo [OpenDBTools] Checking PowerShell module requirements...
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "& { if (-not (Get-Module -ListAvailable -Name SqlServer)) { Write-Host '[OpenDBTools] SqlServer module not found - will be installed on first run' -ForegroundColor Yellow } else { Write-Host '[OpenDBTools] SqlServer module already available' -ForegroundColor Green } }"

echo.
echo [OpenDBTools] Environment is ready. You can now run the OpenDBTools PowerShell script.
echo         Example: .\OpenDBTools.ps1
echo.
echo [OpenDBTools] Note: On first run, the script will automatically install required PowerShell modules if needed.
echo [OpenDBTools] Make sure you have an internet connection for module installation.
echo.
pause

popd >nul 2>&1
endlocal
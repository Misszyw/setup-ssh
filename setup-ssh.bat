@echo off
rem ============================================
rem  Windows one-click OpenSSH installer (v2)
rem  Double-click to run - auto-elevates to admin.
rem  For options, run setup-ssh.ps1 directly.
rem  e.g.  setup-ssh.bat -AddSshUser      (create ssh/ssh admin account)
rem  e.g.  setup-ssh.bat -PreferOffline  (use local offline payload first)
rem ============================================
setlocal
cd /d "%~dp0"

echo ============================================
echo   OpenSSH Server / Client Setup for Windows
echo   Install OpenSSH Server, open firewall,
echo   configure login account, generate client
echo   keys, and start the sshd service.
echo ============================================
echo.

rem ---- elevation check (fltmc is more reliable than net session) ----
fltmc >nul 2>&1
if not errorlevel 1 goto :run_setup

echo Requesting administrator privileges...
echo Please click "Yes" on the UAC prompt.
rem NOTE: must forward %* or -RebootNow / -ClientOnly etc. are silently lost
rem v3: try/catch + explicit exit codes so we can distinguish success from
rem     a cancelled/failed elevation (old version exited silently = looked like a crash)
if "%*"=="" (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Start-Process -FilePath '%~f0' -Verb RunAs -ErrorAction Stop } catch { Write-Host ('[X] Elevation failed: ' + $_.Exception.Message); exit 3 }; Write-Host '[+] Elevated setup started. Setup continues in the new window (check the taskbar if you do not see it).'; exit 0"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs -ErrorAction Stop } catch { Write-Host ('[X] Elevation failed: ' + $_.Exception.Message); exit 3 }; Write-Host '[+] Elevated setup started. Setup continues in the new window (check the taskbar if you do not see it).'; exit 0"
)
if errorlevel 1 (
    echo.
    echo [X] Elevation failed or was cancelled - see message above.
    echo     Fallback: right-click setup-ssh.bat and choose "Run as administrator".
    echo     If an admin window opened but vanished instantly, check antivirus logs,
    echo     then run setup-ssh.bat from an elevated command prompt to see the error.
    echo.
    pause
    exit /b 1
)
echo.
echo This window closes in 4 seconds; setup continues in the admin window.
timeout /t 4 /nobreak >nul 2>&1
exit /b

:run_setup

title OpenSSH Setup (Admin)

echo Launching setup wizard...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup-ssh.ps1" %*
set RC=%ERRORLEVEL%

echo.
if %RC% EQU 4 (
    echo ============================================
    echo   Component staged - REBOOT REQUIRED.
    echo   OpenSSH Server payload is ready but needs
    echo   one reboot to take effect. Re-run this
    echo   script after reboot, or use -RebootNow
    echo   to reboot and auto-resume.
    echo ============================================
) else (
    if %RC% NEQ 0 (
        echo ============================================
        echo   Setup finished with errors ^(exit code %RC%^).
        echo   Check the log path printed above.
        echo ============================================
    ) else (
        echo ============================================
        echo   Setup finished successfully.
        echo   Scroll up for connection details.
        echo ============================================
    )
)
echo.
pause
exit /b %RC%

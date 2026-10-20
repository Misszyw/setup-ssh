@echo off
rem ============================================
rem  Fix OpenSSH host key permissions (ACL + owner)
rem  so the sshd SERVICE (SYSTEM) can load them.
rem  Symptom it fixes: sshd -t passes as admin but
rem  the service fails to start (SCM 7034 /
rem  "UNPROTECTED PRIVATE KEY FILE" / no hostkeys).
rem  Double-click; it self-elevates.
rem ============================================
setlocal
fltmc >nul 2>&1
if not errorlevel 1 goto :run

echo Requesting administrator privileges...
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Start-Process -FilePath '%~f0' -Verb RunAs -ErrorAction Stop } catch { Write-Host ('[X] Elevation failed: ' + $_.Exception.Message); exit 3 }; Write-Host '[+] Elevated. Continuing in the new window...'; exit 0"
if errorlevel 1 (
    echo.
    echo [X] Elevation failed or was cancelled.
    echo.
    pause
    exit /b 1
)
timeout /t 2 /nobreak >nul 2>&1
exit /b

:run
title Fix sshd host keys (Admin)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0fix-sshd-keys.ps1"
echo.
pause
exit /b

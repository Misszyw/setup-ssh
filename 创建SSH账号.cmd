@echo off
rem ============================================
rem  One-click: create the dedicated SSH login account
rem  (same as running:  setup-ssh.bat -AddSshUser)
rem  Creates local account  ssh / ssh  in Administrators,
rem  enables key + password login, re-runs the wizard
rem  idempotently. Double-click this file.
rem ============================================
cd /d "%~dp0"
call "%~dp0setup-ssh.bat" -AddSshUser

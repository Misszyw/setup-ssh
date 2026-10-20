# Fix OpenSSH host key permissions so the sshd SERVICE (SYSTEM) can load them.
# Symptom this fixes: "sshd -t" passes as admin, but the service fails to start
# (SCM event 7034 / log shows "UNPROTECTED PRIVATE KEY FILE ... too open" /
#  "no hostkeys available -- exiting").
# Requirement (verified): ACL must contain only SYSTEM + Administrators, and the
# file OWNER must be SYSTEM or Administrators as well.
$ErrorActionPreference = 'Continue'
$keep = @('S-1-5-18', 'S-1-5-32-544')
$dir = Join-Path $env:ProgramData 'ssh'

Write-Host "OpenSSH host key permission fix"
Write-Host ("Dir: " + $dir)
Write-Host ""

$keys = @(Get-ChildItem -LiteralPath $dir -Filter 'ssh_host_*_key' -File -ErrorAction SilentlyContinue)
if (-not $keys.Count) { Write-Host "[X] No ssh_host_*_key files found in $dir"; exit 1 }

foreach ($k in $keys) {
    $f = $k.FullName
    $fix = $false
    try {
        $acl = Get-Acl -LiteralPath $f
        try {
            $o = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
            if ($keep -notcontains $o) { $fix = $true }
        } catch { }
        foreach ($a in $acl.Access) {
            try {
                $s = $a.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
                if ($keep -notcontains $s -or $a.AccessControlType -ne 'Allow') { $fix = $true }
            } catch { $fix = $true }
        }
        if ($fix) {
            & icacls.exe $f /inheritance:r 2>&1 | Out-Null
            foreach ($a in (Get-Acl -LiteralPath $f).Access) {
                try {
                    $s = $a.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
                    if ($keep -notcontains $s -or $a.AccessControlType -ne 'Allow') { & icacls.exe $f /remove:g ('*' + $s) 2>&1 | Out-Null }
                } catch { }
            }
            & icacls.exe $f /grant '*S-1-5-18:F' '*S-1-5-32-544:F' 2>&1 | Out-Null
            & icacls.exe $f /setowner '*S-1-5-32-544' 2>&1 | Out-Null
            Write-Host ("[fixed] " + $f)
        } else {
            Write-Host ("[ok]    " + $f)
        }
    } catch {
        Write-Host ("[ERR]   " + $f + " : " + $_.Exception.Message)
    }
}

Write-Host ""
Write-Host "Trying to start sshd service..."
try {
    Start-Service -Name sshd -ErrorAction Stop
    $svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
    Write-Host ("[+] sshd is now: " + $svc.Status + " (StartType=" + $svc.StartType + ")")
} catch {
    Write-Host ("[X] sshd still failed to start: " + $_.Exception.Message)
    Write-Host "    Run the full wizard or check event log: Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 20"
}
Write-Host ""
Write-Host "Done."

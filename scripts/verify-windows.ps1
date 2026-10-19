# Verifies the unsigned NSIS installer on a real Windows machine/runner: silent install, files, shortcuts,
# one-click launch (no terminal), console served, uninstall. Used by CI; also fine to run by hand.
param([Parameter(Mandatory = $true)][string]$Setup)
$ErrorActionPreference = "Stop"
$fail = 0
function Check($name, [bool]$cond) { if ($cond) { Write-Host "PASS  $name" } else { Write-Host "FAIL  $name"; $script:fail++ } }

$inst = Join-Path $env:LOCALAPPDATA "Programs\RedX"
Write-Host "installing $Setup silently"
$p = Start-Process -FilePath $Setup -ArgumentList "/S" -Wait -PassThru
Check "installer exit code 0 (got $($p.ExitCode))" ($p.ExitCode -eq 0)
foreach ($f in "redxd.exe", "redx.exe", "redx-launcher.exe", "redx.ico", "uninstall.exe") { Check "installed $f" (Test-Path (Join-Path $inst $f)) }
$sm = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\RedX\RedX.lnk"
Check "Start-menu shortcut exists" (Test-Path $sm)
Check "uninstall registry entry" (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\RedX")
Write-Host (& (Join-Path $inst "redxd.exe") --version)
Write-Host (& (Join-Path $inst "redx.exe") --version)

# one click: run the launcher exactly like the shortcut does (no arguments, no terminal)
$data = Join-Path $env:RUNNER_TEMP "redx-data"
if (-not $env:RUNNER_TEMP) { $data = Join-Path $env:TEMP "redx-data" }
$env:REDX_DATA_DIR = $data
$env:REDX_LISTEN = "127.0.0.1:7791"
Start-Process -FilePath (Join-Path $inst "redx-launcher.exe")
$up = $false
for ($i = 0; $i -lt 60 -and -not $up; $i++) {
  try { $r = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:7791/healthz" -TimeoutSec 2; $up = ($r.StatusCode -eq 200) } catch { Start-Sleep -Milliseconds 500 }
}
Check "launcher started the host (healthz)" $up
if ($up) {
  $c = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:7791/" -TimeoutSec 5
  Check "console served" ($c.StatusCode -eq 200 -and $c.Content -match "RedX")
  $s = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:7791/ui/icons/redx.svg" -TimeoutSec 5
  Check "console assets served" ($s.StatusCode -eq 200)
}
Get-Process redxd -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1

# uninstall (silent; _?= makes the uninstaller run in place so -Wait works)
$u = Start-Process -FilePath (Join-Path $inst "uninstall.exe") -ArgumentList "/S", "_?=$inst" -Wait -PassThru
Check "uninstaller exit code 0 (got $($u.ExitCode))" ($u.ExitCode -eq 0)
Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $inst "uninstall.exe")
Check "binaries removed" (-not (Test-Path (Join-Path $inst "redxd.exe")))
Check "shortcut removed" (-not (Test-Path $sm))
Check "registry entry removed" (-not (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\RedX"))
Check "data directory kept" (Test-Path $data)
if ($fail -gt 0) { Write-Host "$fail check(s) failed"; exit 1 }
Write-Host "windows installer verified"

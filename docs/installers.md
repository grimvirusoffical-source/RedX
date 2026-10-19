# Installers

Every installer is **unsigned**: it is not signed with a paid code-signing certificate and (macOS) not notarized. Your
operating system will warn the first time, and the steps below are how to proceed. Download only from a place you trust and
compare the file with `SHA256SUMS`.

| OS | File | What it does |
|---|---|---|
| Windows 10/11 (amd64, arm64) | `redx-<ver>-windows-<arch>-setup.exe` | Per-user install (no administrator rights) to `%LOCALAPPDATA%\Programs\RedX`; Start-menu folder with *RedX*, *Stop RedX* and *Uninstall RedX*; optional desktop shortcut; optional *start when I sign in*; uninstaller in *Apps & features*. |
| macOS (Apple silicon, Intel, universal) | `redx-<ver>-macos-<arm64\|amd64\|universal>.dmg` or `.pkg` | `.dmg`: drag **RedX.app** to Applications. `.pkg`: installs the app and puts `redx` and `redxd` in `/usr/local/bin`. |
| Debian, Ubuntu, Raspberry Pi OS | `redx_<ver>_<amd64\|arm64\|armhf>.deb` | `redx`, `redxd`, `redx-launcher`, an application-menu entry with the scythe icon, and a `systemd` unit (not enabled automatically). |
| Any Linux, any OS | `redx-<ver>-<os>-<arch>.tar.gz` / `.zip` | The programs, docs and example configuration, for manual installs (`install.sh` / `install.ps1` are included). |

## One click, no terminal

Start **RedX** from the Start menu, the Applications folder or the application menu. That runs `redx-launcher`, which starts the
host in the background (no console window), waits until it is healthy and opens the web console in your browser. The first time,
the console offers **Create admin key** (shown once, on this computer only) and a short setup wizard. Starting RedX again just opens
the console. Stopping it: *Stop RedX* in the Windows Start menu, *Activity Monitor → redxd → Quit* on macOS, or `pkill redxd`.

Where the data lives when started this way: Windows `%LOCALAPPDATA%\RedX\data`, macOS `~/Library/Application Support/RedX/data`,
Linux `~/.redx/data`. An older `%ProgramData%\RedX\data` or `/usr/local/var/redx` is kept if it already exists. Uninstalling never
deletes your data.

## First-run warnings

* **Windows SmartScreen** ("Windows protected your PC"): choose *More info* then *Run anyway*.
* **macOS Gatekeeper** ("unidentified developer"): right-click (or Control-click) RedX in Applications, choose *Open*, then *Open*.
  If macOS still blocks it: *System Settings → Privacy & Security → Open Anyway*. The app carries only an ad-hoc signature.
* **Linux**: no warning; `sudo apt install ./redx_<ver>_<arch>.deb`.

## Run it as a service instead

Servers and Raspberry Pis: `.deb` plus `sudo systemctl enable --now redxd` (see [Hosting](hosting.md#linux-systemd-including-raspberry-pi-os-arm64--armv7)), or `install.sh` / `install.ps1`
(Windows service) from the archives. A service has no browser: create the admin key in a terminal with
`redx key create --offline --scope admin --db '*'`, or start it with `--bootstrap web` and finish setup on the machine itself.

## Remote access and the PWA

The console can be installed as an app (PWA) only from `https://` with a certificate the device trusts, or from
`http://127.0.0.1` / `localhost`. A phone on `http://192.168.x.y:7777` can still use the console in the browser but cannot install it.
See [the console guide](console.md#6-install-it-as-an-app-pwa).

## What has been verified

Built and unit-tested on Linux only. The Windows `.exe` installers are built on Linux with NSIS; install, launch, shortcut and
uninstall have **not** been run on Windows. The macOS `.app`, `.dmg` and `.pkg` can only be built on macOS and have **not** been
built or run. The `.deb` was built and its contents checked on Linux; it has not been installed on a Raspberry Pi. Docker and
iOS are untested. `scripts/verify-windows.ps1` and `scripts/verify-macos.sh` (run by the `release-build` workflow) do the real
install-and-launch checks once the workflows can run.

## Building installers yourself

`scripts/build.sh --version X` (and the macOS installer script) refuse to build from a git working tree with uncommitted or
untracked files, so the commit stamped into every binary is exactly the source that was built. `REDX_ALLOW_DIRTY=1`
builds anyway and stamps the version as `X-dirty`. A build without `--version` (a development build) is stamped `-dirty`
instead of refused.

macOS builds are ad-hoc signed only (still **unsigned** in the sense above). Signing with your own Apple Developer ID is
opt-in: set `MACOS_SIGN_IDENTITY="Developer ID Application: …"` (and `MACOS_INSTALLER_IDENTITY="Developer ID Installer: …"`
for the `.pkg`; it is signed with `productbuild --sign`, which also works over a headless SSH session where `productsign`
cannot use the installer key). Every Mach-O is then signed on its own, inside out (`Contents/Resources/bin/redx`, `Contents/MacOS/redxd`,
then the app) with the hardened runtime, and the `/usr/local/bin` copies in the `.pkg` are the same signed binaries.
Notarization is not done by these scripts.

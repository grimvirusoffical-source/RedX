; RedX Windows installer (NSIS). Per-user install: no administrator rights needed.
; Build:  makensis -DVERSION=0.4.1 -DSRC=<dir with redxd.exe redx.exe redx-launcher.exe> -DICON=<redx.ico> -DOUT=<setup.exe> redx.nsi
; UNSIGNED: Windows SmartScreen will warn ("More info" -> "Run anyway").
Unicode true
!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifndef SRC
  !define SRC "."
!endif
!ifndef ICON
  !define ICON "redx.ico"
!endif
!ifndef OUT
  !define OUT "redx-setup.exe"
!endif
!ifndef ARCH
  !define ARCH "amd64"
!endif

!include "MUI2.nsh"
!include "FileFunc.nsh"

Name "RedX ${VERSION}"
OutFile "${OUT}"
InstallDir "$LOCALAPPDATA\Programs\RedX"
InstallDirRegKey HKCU "Software\RedX" "InstallDir"
RequestExecutionLevel user
SetCompressor /SOLID lzma
BrandingText "RedX ${VERSION} (unsigned build)"
; Windows wants a numeric X.X.X.X here; NUMVERSION is VERSION without a suffix such as "-rc" (package.sh passes it)
!ifndef NUMVERSION
  !define NUMVERSION "${VERSION}"
!endif
VIProductVersion "${NUMVERSION}.0"
VIAddVersionKey "ProductName" "RedX"
VIAddVersionKey "FileDescription" "RedX database host installer"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "RedX"

!define MUI_ICON "${ICON}"
!define MUI_UNICON "${ICON}"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\redx-launcher.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Start RedX and open the web console"
!define MUI_FINISHPAGE_SHOWREADME ""
!define MUI_FINISHPAGE_SHOWREADME_NOTCHECKED
!define MUI_FINISHPAGE_SHOWREADME_TEXT "Start RedX automatically when I sign in to Windows"
!define MUI_FINISHPAGE_SHOWREADME_FUNCTION AutoStartToggle

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Function AutoStartToggle
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "RedX" '"$INSTDIR\redx-launcher.exe"'
FunctionEnd

Section "RedX" SecMain
  SectionIn RO
  ; stop a running host from a previous install so files can be replaced
  nsExec::Exec 'taskkill /F /IM redxd.exe'
  Pop $0
  SetOutPath "$INSTDIR"
  File "${SRC}\redxd.exe"
  File "${SRC}\redx.exe"
  File "${SRC}\redx-launcher.exe"
  File "${ICON}"
  File /nonfatal "${SRC}\installers.md"
  File /nonfatal "${SRC}\console.md"
  File /nonfatal "${SRC}\hosting.md"
  File /nonfatal "${SRC}\boxql.md"
  File /nonfatal "${SRC}\redx.example.toml"

  CreateDirectory "$SMPROGRAMS\RedX"
  CreateShortcut "$SMPROGRAMS\RedX\RedX.lnk" "$INSTDIR\redx-launcher.exe" "" "$INSTDIR\redx.ico" 0 SW_SHOWNORMAL "" "Start the RedX host and open the web console"
  CreateShortcut "$SMPROGRAMS\RedX\Stop RedX.lnk" "$SYSDIR\taskkill.exe" "/F /IM redxd.exe" "$INSTDIR\redx.ico" 0 SW_SHOWMINIMIZED "" "Stop the RedX host"
  CreateShortcut "$SMPROGRAMS\RedX\Uninstall RedX.lnk" "$INSTDIR\uninstall.exe"
  CreateShortcut "$DESKTOP\RedX.lnk" "$INSTDIR\redx-launcher.exe" "" "$INSTDIR\redx.ico" 0

  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKCU "Software\RedX" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RedX" "DisplayName" "RedX"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RedX" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RedX" "Publisher" "RedX"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RedX" "DisplayIcon" "$INSTDIR\redx.ico"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RedX" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RedX" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RedX" "NoModify" 1
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RedX" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RedX" "EstimatedSize" "$0"
SectionEnd

Section "Uninstall"
  nsExec::Exec 'taskkill /F /IM redxd.exe'
  Pop $0
  Delete "$SMPROGRAMS\RedX\RedX.lnk"
  Delete "$SMPROGRAMS\RedX\Stop RedX.lnk"
  Delete "$SMPROGRAMS\RedX\Uninstall RedX.lnk"
  RMDir "$SMPROGRAMS\RedX"
  Delete "$DESKTOP\RedX.lnk"
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "RedX"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RedX"
  DeleteRegKey HKCU "Software\RedX"
  Delete "$INSTDIR\redxd.exe"
  Delete "$INSTDIR\redx.exe"
  Delete "$INSTDIR\redx-launcher.exe"
  Delete "$INSTDIR\redx.ico"
  Delete "$INSTDIR\installers.md"
  Delete "$INSTDIR\console.md"
  Delete "$INSTDIR\hosting.md"
  Delete "$INSTDIR\boxql.md"
  Delete "$INSTDIR\redx.example.toml"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  ; The data directory (your databases and keys) is deliberately NOT removed.
  MessageBox MB_OK "RedX was removed. Your data was kept in:$\r$\n%LOCALAPPDATA%\RedX\data (or the folder you configured).$\r$\nDelete it yourself if you no longer need it." /SD IDOK
SectionEnd

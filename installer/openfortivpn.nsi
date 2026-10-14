; openfortivpn Windows Installer
; Requires NSIS 3.x (https://nsis.sourceforge.io/)
;
; Build instructions:
;   1. Place these files in the installer/ directory:
;      - openfortivpn.exe (from CMake build)
;      - wintun.dll (from https://www.wintun.net/)
;      - libssl-*.dll, libcrypto-*.dll (from MinGW or vcpkg)
;      - libwinpthread-1.dll, libgcc_s_seh-1.dll (from MinGW)
;   2. Run: makensis openfortivpn.nsi

!define PRODUCT_NAME "openfortivpn"
!define PRODUCT_VERSION "1.24.1"
!define PRODUCT_PUBLISHER "openfortivpn contributors"

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "openfortivpn-${PRODUCT_VERSION}-setup.exe"
InstallDir "$PROGRAMFILES64\openfortivpn"
RequestExecutionLevel admin

;--- Pages ---
Page directory
Page instfiles
UninstPage uninstConfirm
UninstPage instfiles

;--- Install ---
Section "Install"
	SetOutPath $INSTDIR

	; Core files
	File "openfortivpn.exe"
	File "wintun.dll"
	File "README.md"

	; Runtime DLLs (MinGW build)
	File /nonfatal "libssl-3-x64.dll"
	File /nonfatal "libcrypto-3-x64.dll"
	File /nonfatal "libwinpthread-1.dll"
	File /nonfatal "libgcc_s_seh-1.dll"

	; Create config directory
	CreateDirectory "$APPDATA\openfortivpn"

	; Write example config
	FileOpen $0 "$APPDATA\openfortivpn\config.example" w
	FileWrite $0 "# openfortivpn configuration file$\r$\n"
	FileWrite $0 "# Copy this to 'config' and edit.$\r$\n"
	FileWrite $0 "#$\r$\n"
	FileWrite $0 "# host = vpn-gateway$\r$\n"
	FileWrite $0 "# port = 8443$\r$\n"
	FileWrite $0 "# username = foo$\r$\n"
	FileWrite $0 "# trusted-cert = <sha256-digest>$\r$\n"
	FileClose $0

	; Add to PATH
	EnVar::AddValue "PATH" "$INSTDIR"

	; Create uninstaller
	WriteUninstaller "$INSTDIR\uninstall.exe"

	; Start menu
	CreateDirectory "$SMPROGRAMS\openfortivpn"
	CreateShortcut "$SMPROGRAMS\openfortivpn\Uninstall.lnk" \
		"$INSTDIR\uninstall.exe"

	; Registry for Add/Remove Programs
	WriteRegStr HKLM \
		"Software\Microsoft\Windows\CurrentVersion\Uninstall\openfortivpn" \
		"DisplayName" "${PRODUCT_NAME}"
	WriteRegStr HKLM \
		"Software\Microsoft\Windows\CurrentVersion\Uninstall\openfortivpn" \
		"DisplayVersion" "${PRODUCT_VERSION}"
	WriteRegStr HKLM \
		"Software\Microsoft\Windows\CurrentVersion\Uninstall\openfortivpn" \
		"Publisher" "${PRODUCT_PUBLISHER}"
	WriteRegStr HKLM \
		"Software\Microsoft\Windows\CurrentVersion\Uninstall\openfortivpn" \
		"UninstallString" "$INSTDIR\uninstall.exe"
	WriteRegStr HKLM \
		"Software\Microsoft\Windows\CurrentVersion\Uninstall\openfortivpn" \
		"InstallLocation" "$INSTDIR"
SectionEnd

;--- Uninstall ---
Section "Uninstall"
	; Remove files
	Delete "$INSTDIR\openfortivpn.exe"
	Delete "$INSTDIR\wintun.dll"
	Delete "$INSTDIR\README.md"
	Delete "$INSTDIR\libssl-3-x64.dll"
	Delete "$INSTDIR\libcrypto-3-x64.dll"
	Delete "$INSTDIR\libwinpthread-1.dll"
	Delete "$INSTDIR\libgcc_s_seh-1.dll"
	Delete "$INSTDIR\uninstall.exe"
	RMDir "$INSTDIR"

	; Remove from PATH
	EnVar::DeleteValue "PATH" "$INSTDIR"

	; Remove start menu
	Delete "$SMPROGRAMS\openfortivpn\Uninstall.lnk"
	RMDir "$SMPROGRAMS\openfortivpn"

	; Remove registry
	DeleteRegKey HKLM \
		"Software\Microsoft\Windows\CurrentVersion\Uninstall\openfortivpn"
SectionEnd

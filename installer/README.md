# Windows Installer

This directory contains an [NSIS](https://nsis.sourceforge.io/) script for
building a Windows installer.

## Prerequisites

1. Build openfortivpn with CMake (MinGW-w64 or MSVC)
2. Download [wintun.dll](https://www.wintun.net/) (amd64 version)
3. Install [NSIS 3.x](https://nsis.sourceforge.io/) with the
   [EnVar plugin](https://nsis.sourceforge.io/EnVar_plug-in)

## Building the installer

Copy these files into this directory:

- `openfortivpn.exe` (from your build output)
- `wintun.dll` (from wintun zip, `wintun/bin/amd64/wintun.dll`)
- `README.md` (from project root)
- MinGW runtime DLLs (if building with MinGW):
  - `libssl-3-x64.dll`
  - `libcrypto-3-x64.dll`
  - `libwinpthread-1.dll`
  - `libgcc_s_seh-1.dll`

Then run:

```shell
makensis openfortivpn.nsi
```

This produces `openfortivpn-1.24.1-setup.exe`.

## What the installer does

- Installs to `C:\Program Files\openfortivpn\`
- Adds the install directory to the system PATH
- Creates an example config at `%APPDATA%\openfortivpn\config.example`
- Registers in Add/Remove Programs for clean uninstall

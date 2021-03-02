# Windows-Optimize-Debloat
For those who seek to minimize their Windows 10 installs.

This script should work for most, if not all, systems without issue. While [@SimeonOnSecurity](https://github.com/simeononsecurity) creates, reviews, and tests each repo intensivly, we can not test every possible configuration nor does [@SimeonOnSecurity](https://github.com/simeononsecurity) take any responsibility for breaking your system. If something goes wrong, be prepared to submit an [issue](./issues). Do not run this script if you don't understand what it does.

## Introduction:
Windows 10 is an invasive and insecure operating system out of the box. 
Organizations like [Microsoft](https://microsoft.com), [PrivacyTools.io](https://PrivacyTools.io), and others have recommended configuration changes to optimize and debloat the Windows 10 operating system. These changes are include blocking telemetry, deleting logs, and removing bloatware to name a few. This script aims to automate the configurations recommended by those organizations.

## Notes: 
- This script is designed for operation in primarily **Personal Use** environments. 
- This script is designed in such a way that the optimizations, unlike some other scripts, will not break core windows functionality.
 - Features like Windows Update, Windows Defender, the Windows Store, and Cortona have been restricted, but are not in a disfunctional state like most other Windows 10 Privacy scripts.
- If you seek a minimized script targeted only to commercial environments, please see this [GitHub Repository](https://github.com/simeononsecurity/Standalone-Windows-STIG-Script)

## Requirements:
- [X] Windows 10 Enterprise, Windows 10 Professional, or Windows 10 Home
  - Windows 10 Home does not allow for GPO configurations.
    - Script will still work but not all settings will apply.
  - Windows 10 "N" Editions are not tested.
  - Currently Windows 10 **v1909**, **v2004**, or **20H2**. 
  - Run the [Windows 10 Upgrade Assistant](https://support.microsoft.com/en-us/help/3159635/windows-10-update-assistant) to update and verify latest major release.

## A list of scripts and tools this collection utilizes:
- [Microsoft Security Compliance Toolkit 1.0](https://www.microsoft.com/en-us/download/details.aspx?id=55319)

## Additional configurations were considered from:
- [BuiltByBel - PrivateZilla](https://github.com/builtbybel/privatezilla)
- [MelodysTweaks - Basic Tweaks](https://sites.google.com/view/melodystweaks/basictweaks)
- [Microsoft - Managing Windows 10 Telemetry and Callbacks](https://docs.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services)
- [Microsoft - Windows 10 Privacy](https://docs.microsoft.com/en-us/windows/privacy/)
- [Microsoft - Windows 10 VDI Recomendations](https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds_vdi-recommendations-1909)
- [Mirinsoft - SharpApp](https://github.com/builtbybel/sharpapp)
- [Mirinsoft - debotnet](https://github.com/builtbybel/debotnet)
- [UnderGroundWires - Privacy.S**Y](https://github.com/undergroundwires/privacy.sexy)
- [Sycnex - Windows10Debloater](https://github.com/Sycnex/Windows10Debloater)
- [The-Virtual-Desktop-Team - Virtual-Desktop-Optimization-Tool](https://github.com/The-Virtual-Desktop-Team/Virtual-Desktop-Optimization-Tool)
- [TheVDIGuys - Windows 10 VDI Optimize](https://github.com/TheVDIGuys/Windows_10_VDI_Optimize)
- [W4H4WK - Debloat Windows 10](https://github.com/W4RH4WK/Debloat-Windows-10/tree/master/scripts)

## How to run the script
### Manual Install:
If manually downloaded, the script must be launched from an administrative powershell in the directory containing all the files from the [GitHub Repository](https://github.com/simeononsecurity/Windows-Optimize-Harden-Debloat)
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force
Get-ChildItem -Recurse *.ps1 | Unblock-File
.\sos-optimize-windows.ps1
```
### Automated Install:
The script may be launched from the extracted GitHub download like this:
```powershell
iex ((New-Object System.Net.WebClient).DownloadString('https://simeononsecurity.ch/scripts/windowsoptimizeanddebloat.ps1'))
```

# Windows-Optimize-Debloat

[![Test script against windows docker container](https://github.com/simeononsecurity/Windows-Optimize-Debloat/actions/workflows/test-with-docker.yml/badge.svg)](https://github.com/simeononsecurity/Windows-Optimize-Debloat/actions/workflows/test-with-docker.yml)[![VirusTotal Scan](https://github.com/simeononsecurity/Windows-Optimize-Debloat/actions/workflows/virustotal.yml/badge.svg)](https://github.com/simeononsecurity/Windows-Optimize-Debloat/actions/workflows/virustotal.yml)

*For those who seek to minimize their Windows 10 and 11 installs.*

**Note:** This script should work for most, if not all, systems without issue. While [@SimeonOnSecurity](https://github.com/simeononsecurity) creates, reviews, and tests each repo intensivly, we can not test every possible configuration nor does [@SimeonOnSecurity](https://github.com/simeononsecurity) take any responsibility for breaking your system. If something goes wrong, be prepared to submit an [issue](../../issues). Do not run this script if you don't understand what it does.

## Introduction:
Windows 10 and 11 is are invasive and insecure operating system out of the box. 
Organizations like [Microsoft](https://microsoft.com), [PrivacyTools.io](https://PrivacyTools.io), and others have recommended configuration changes to optimize and debloat the Windows 10 operating system. These changes are include blocking telemetry, deleting logs, and removing bloatware to name a few. This script aims to automate the configurations recommended by those organizations.

## Notes: 
- This script is designed for operation in primarily **Personal Use** environments. 
- This script is designed in such a way that the optimizations, unlike some other scripts, will not break core windows functionality.
 - Features like Windows Update, Windows Defender, the Windows Store, and Cortona have been restricted, but are not in a disfunctional state like most other Windows 10 Privacy scripts.
- If you seek a minimized script targeted only to commercial environments, please see this [GitHub Repository](https://github.com/simeononsecurity/Standalone-Windows-STIG-Script)

## Requirements:
- [X] Windows 10/11 Enterprise, Windows 10 Professional, or Windows 10 Home
  - Windows Home does not allow for GPO configurations.
    - Script will still work but not all settings will apply.
  - Windows "N" Editions are not tested.
  - Run the [Windows 10 Upgrade Assistant](https://support.microsoft.com/en-us/help/3159635/windows-10-update-assistant) to update and verify latest major release.
     
## Additions, notable changes, and bugfixes:

**This script adds, removes, and changes settings on your system. Please review the script before running it.**

### Browsers:
- Browsers will have additional extentions installed to aid in privacy and security.
  - See [here](https://github.com/simeononsecurity/Windows-Optimize-Harden-Debloat/issues/11) for additional information.
- Browsers extension management and other enterprise settings are set. For instructions on how to see these options, you'll need to look at the [GPO instructions](https://github.com/simeononsecurity/Windows-Optimize-Debloat#editing-policies-in-local-group-policy-after-the-fact) below.

### Fixing Microsoft Account or Xbox Services:
This is because we block signing into microsoft accounts. Microsoft's telemetry and identity association is frowned upon. 
However, if you still wish to use these services see the following issue tickets for the resolution:
- https://github.com/simeononsecurity/Windows-Optimize-Harden-Debloat/issues/1
- https://github.com/simeononsecurity/Windows-Optimize-Harden-Debloat/issues/16
- https://github.com/simeononsecurity/Windows-Optimize-Harden-Debloat/issues/22

### Editing policies in Local Group Policy after the fact:

If you need to modify or change a setting, they are most likely configurable via GPO:

- Import the ADMX Policy definitions from this [repo](https://github.com/simeononsecurity/STIG-Compliant-Domain-Prep/tree/master/Files/PolicyDefinitions) into _C:\windows\PolicyDefinitions_ on the system you're trying to modify.

- Open `gpedit.msc` on on the system you're trying to modify.

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

## How to run the script:
### Automated Install:
The script may be launched from the extracted GitHub download like this:
```powershell
iwr -useb 'https://simeononsecurity.ch/scripts/windowsoptimizeanddebloat.ps1'|iex
```
**Note**: *This installation version installs all of the configurations. If you seek to customize it, please use the [Manual Install](https://github.com/simeononsecurity/Windows-Optimize-Debloat/tree/main#manual-install)*

### Chocolatey Install:
Assuming you have [Chocolatey](https://chocolatey.org/install) installed. You may install this script via the following command.
```powershell
choco install windows-optimize-debloat
```
Or view the package on the [Chocolatey Repo](https://community.chocolatey.org/packages/Windows-Optimize-Debloat).

**Note**: *The Chocolatey version of this script may lag behind this repo by multiple major versions. We update it sparingly, but stably. Additionally, this version will install all of the configurations. If you seek to customize it, please use the [Manual Install](https://github.com/simeononsecurity/Windows-Optimize-Debloat/tree/main#manual-install)*

### Manual Install:
If manually downloaded, the script must be launched from an administrative powershell in the directory containing all the files from the [GitHub Repository](https://github.com/simeononsecurity/Windows-Optimize-Debloat)

The script "sos-optimize-windows.ps1" includes several parameters that allow for customization of the optimization process. Each parameter is a boolean value that defaults to true if not specified.

- **$cleargpos**: Clears Group Policy Objects settings.
- **$installupdates**: Installs updates to the system.
- **$removebloatware**: Removes unnecessary programs and features from the system.
- **$disabletelemetry**: Disables data collection and telemetry.
- **$privacy**: Makes changes to improve privacy.
- **$imagecleanup**: Cleans up unneeded files from the system.
- **$diskcompression**: Compresses the system disk.
- **$updatemanagement**: Changes the way updates are managed and improved on the system.
- **$sosbrowsers**: Optimizes the system's web browsers.

An example of how to launch the script with specific parameters would be:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force
Get-ChildItem -Recurse *.ps1 | Unblock-File
powershell.exe -ExecutionPolicy ByPass -File .\sos-optimize-windows.ps1 -cleargpos:$false -installupdates:$false
```

## Learn more about [Debloating Windows 10 and Windows 11](https://simeononsecurity.ch/github/windows-optimize-debloat/)

<a href="https://simeononsecurity.ch" target="_blank" rel="noopener noreferrer">
  <h2>Explore the World of Cybersecurity</h2>
</a>
<a href="https://simeononsecurity.ch" target="_blank" rel="noopener noreferrer">
  <img src="https://simeononsecurity.ch/img/banner.png" alt="SimeonOnSecurity Logo" width="300" height="300">
</a>

### Links:
- #### [github.com/simeononsecurity](https://github.com/simeononsecurity)
- #### [simeononsecurity.ch](https://simeononsecurity.ch)

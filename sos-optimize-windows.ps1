param(
    [Parameter(Mandatory = $false)]
    [bool]$cleargpos = $true,
    [Parameter(Mandatory = $false)]
    [bool]$installupdates = $true,
    [Parameter(Mandatory = $false)]
    [bool]$removebloatware = $true,
    [Parameter(Mandatory = $false)]
    [bool]$disabletelemetry = $true,
    [Parameter(Mandatory = $false)]
    [bool]$privacy = $true,
    [Parameter(Mandatory = $false)]
    [bool]$imagecleanup = $true,
    [Parameter(Mandatory = $false)]
    [bool]$diskcompression = $true,
    [Parameter(Mandatory = $false)]
    [bool]$updatemanagement = $true,
    [Parameter(Mandatory = $false)]
    [bool]$sosbrowsers = $true
)

######SCRIPT FOR FULL INSTALL AND CONFIGURE ON STANDALONE MACHINE#####
#Continue on error
$ErrorActionPreference = 'silentlycontinue'

#Require elivation for script run
#Requires -RunAsAdministrator

#Set Directory to PSScriptRoot
if ((Get-Location).Path -NE $PSScriptRoot) { Set-Location $PSScriptRoot }

$paramscheck = $cleargpos, $installupdates, $removebloatware, $disabletelemetry, $privacy, $imagecleanup, $diskcompression, $updatemanagement, $sosbrowsers

# run a warning if no options are set to true
if ($paramscheck | Where-Object { $_ -eq $false } | Select-Object -Count -EQ $params.Count) {
    Write-Error "No Options Were Selected. Exiting..."
    Exit
}

# if any parameters are set to true take a restore point
$date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$scriptName = $MyInvocation.MyCommand.Name
if ($paramscheck | Where-Object { $_ } | Select-Object) {
    $freespace = (Get-WmiObject -class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq 'C:' }).FreeSpace
    $minfreespace = 10000000000 #10GB
    if ($freespace -gt $minfreespace) {
        Try {
            Write-Host "Taking a Restore Point Before Continuing...."
            $job = Start-Job -Name Take Restore Point -ScriptBlock {
                New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore' -Name 'SystemRestorePointCreationFrequency' -PropertyType DWORD -Value 0 -Force
                Checkpoint-Computer -Description "RestorePoint $scriptName $date" -RestorePointType "MODIFY_SETTINGS"
            }
            Wait-Job -Job $job
        }
        Catch {
            Write-Error "Failed to take restore point...."
        }
    }
    else {
        Write-Output "Not enough disk space to create a restore point. Current free space: $(($freespace/1GB)) GB"
    }
}

# Install Local Group Policy if Not Already Installed
if ($paramscheck | Where-Object { $_ } | Select-Object) {
    Start-Job -Name InstallGPOPackages -ScriptBlock {
        foreach ($F in (Get-ChildItem "$env:SystemRoot\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientTools-Package~*.mum").FullName) {
            if ((dism /online /get-packages | where-object { $_.name -like "*Microsoft-Windows-GroupPolicy-ClientTools*" }).count -eq 0) {
                dism /Online /NoRestart /Add-Package:$F
            }
        }

        foreach ($F in (Get-ChildItem "$env:SystemRoot\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientExtensions-Package~*.mum").FullName) {
            if ((dism /online /get-packages | where-object { $_.name -like "*Microsoft-Windows-GroupPolicy-ClientExtensions*" }).count -eq 0) {
                dism /Online /NoRestart /Add-Package:$F
            }
        }
    }
}

#GPO Configurations
function Import-GPOs([string]$gposdir) {
    Write-Host "Importing Group Policies from $gposdir ..." -ForegroundColor Green
    Foreach ($gpoitem in Get-ChildItem $gposdir) {
        Write-Host "Importing $gpoitem GPOs..." -ForegroundColor White
        $gpopath = "$gposdir\$gpoitem"
        #Write-Host "Importing $gpo" -ForegroundColor White
        .\Files\LGPO\LGPO.exe /g $gpopath > $null 2>&1
        #Write-Host "Done" -ForegroundColor Green
    }
}

if ($cleargpos -eq $true) {
    Write-Host "Removing Existing Local GPOs" -ForegroundColor Green
    #Remove and Refresh Local Policies
    Remove-Item -Recurse -Force "$env:WinDir\System32\GroupPolicy" | Out-Null
    Remove-Item -Recurse -Force "$env:WinDir\System32\GroupPolicyUsers" | Out-Null
    secedit /configure /cfg "$env:WinDir\inf\defltbase.inf" /db defltbase.sdb /verbose | Out-Null
    gpupdate /force | Out-Null
}
else {
    Write-Output "The Clear Existing GPOs Section Was Skipped..."
}

if ($installupdates -eq $true) {
    Write-Host "Installing the Latest Windows Updates" -ForegroundColor Green
    #Install PowerShell Modules
    Copy-Item -Path .\Files\"PowerShell Modules"\* -Destination C:\Windows\System32\WindowsPowerShell\v1.0\Modules -Force -Recurse
    #Unblock New PowerShell Modules
    Get-ChildItem C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate\ -recurse | Unblock-File
    #Install PSWindowsUpdate
    Import-Module -Name PSWindowsUpdate -Force -Global 

    #Install Latest Windows Updates
    Start-Job -Name "Windows Updates" -ScriptBlock {
        Install-WindowsUpdate -MicrosoftUpdate -AcceptAll; Get-WuInstall -AcceptAll -IgnoreReboot; Get-WuInstall -AcceptAll -Install -IgnoreReboot
    }
}
else {
    Write-Output "The Install Update Section Was Skipped..."
}
if ($removebloatware -eq $true) {
    Write-Host "Removing Windows Bloatware" -ForegroundColor Green
    Start-Job -Name "Remove Windows Bloatware" -ScriptBlock {
        #Removing Windows Bloatware
        Write-Host "Removing Bloatware"
        Write-Host "Removing Bloat Windows Apps"
        $WindowsApps = "*ACGMediaPlayer*", "*ActiproSoftwareLLC*", "*AdobePhotoshopExpress*", "*AdobeSystemsIncorporated.AdobePhotoshopExpress*", "*BubbleWitch3Saga*", "*CandyCrush*", "*CommsPhone*", "*ConnectivityStore*", "*Dolby*", "*Duolingo-LearnLanguagesforFree*", "*EclipseManager*", "*Facebook*", "*FarmHeroesSaga*", "*Flipboard*", "*HiddenCity*", "*Hulu*", "*LinkedInforWindows*", "*Microsoft.3dbuilder*", "*Microsoft.549981C3F5F10*", "*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*", "*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*", "*Microsoft.Appconnector*", "*Microsoft.Asphalt8Airborne*", "*Microsoft.BingNews*", "*Microsoft.BingWeather*", "*Microsoft.DrawboardPDF*", "*Microsoft.GamingApp*", "*Microsoft.GetHelp*", "*Microsoft.Getstarted*", "*Microsoft.MSPaint*", "*Microsoft.Messaging*", "*Microsoft.Microsoft3DViewer*", "*Microsoft.MicrosoftOfficeHub*", "*Microsoft.MicrosoftOfficeOneNote*", "*Microsoft.MicrosoftSolitaireCollection*", "*Microsoft.MicrosoftStickyNotes*", "*Microsoft.MixedReality.Portal*", "*Microsoft.OneConnect*", "*Microsoft.People*", "*Microsoft.Print3D*", "*Microsoft.SkypeApp*", "*Microsoft.Wallet*", "*Microsoft.Whiteboard*", "*Microsoft.WindowsAlarms*", "*Microsoft.WindowsCommunicationsApps*", "*Microsoft.WindowsFeedbackHub*", "*Microsoft.WindowsMaps*", "*Microsoft.WindowsSoundRecorder*", "*Microsoft.YourPhone*", "*Microsoft.ZuneMusic*", "*Microsoft.ZuneVideo*", "*Microsoft3DViewer*", "*MinecraftUWP*", "*Netflix*", "*Office.Sway*", "*OneCalendar*", "*OneNote*", "*PandoraMediaInc*", "*RoyalRevolt*", "*SpeedTest*", "*Sway*", "*Todos*", "*Twitter*", "*Viber*", "*WindowsScan*", "*Wunderlist*", "*bingsports*", "*empires*", "*spotify*", "*windowsphone*", "*xing*", "2FE3CB00.PicsArt-PhotoStudio", "46928bounde.EclipseManager", "4DF9E0F8.Netflix", "613EBCEA.PolarrPhotoEditorAcademicEdition", "6Wunderkinder.Wunderlist", "7EE7776C.LinkedInforWindows", "89006A2E.AutodeskSketchBook", "9E2F88E3.Twitter", "A278AB0D.DisneyMagicKingdoms", "A278AB0D.MarchofEmpires", "ActiproSoftwareLLC.562882FEEB491", "CAF9E577.Plex", "ClearChannelRadioDigital.iHeartRadio", "D52A8D61.FarmVille2CountryEscape", "D5EA27B7.Duolingo-LearnLanguagesforFree", "DB6EA5DB.CyberLinkMediaSuiteEssentials", "DolbyLaboratories.DolbyAccess", "Drawboard.DrawboardPDF", "Facebook.Facebook", "Fitbit.FitbitCoach", "Flipboard.Flipboard", "GAMELOFTSA.Asphalt8Airborne", "KeeperSecurityInc.Keeper", "Microsoft.3DBuilder", "Microsoft.549981C3F5F10", "Microsoft.549981C3F5F10", "Microsoft.Advertising.Xaml", "Microsoft.AppConnector", "Microsoft.BingFinance", "Microsoft.BingFoodAndDrink", "Microsoft.BingHealthAndFitness", "Microsoft.BingNews", "Microsoft.BingSports", "Microsoft.BingTranslator", "Microsoft.BingTravel", "Microsoft.BingWeather", "Microsoft.CommsPhone", "Microsoft.ConnectivityStore", "Microsoft.GamingServices", "Microsoft.GetHelp", "Microsoft.Getstarted", "Microsoft.Messaging", "Microsoft.Microsoft3DViewer", "Microsoft.MicrosoftOfficeHub", "Microsoft.MicrosoftPowerBIForWindows", "Microsoft.MicrosoftSolitaireCollection", "Microsoft.MinecraftUWP", "Microsoft.MixedReality.Portal", "Microsoft.NetworkSpeedTest", "Microsoft.News", "Microsoft.Office.Lens", "Microsoft.Office.OneNote", "Microsoft.Office.Sway", "Microsoft.OneConnect", "Microsoft.People", "Microsoft.Print3D", "Microsoft.ScreenSketch", "Microsoft.SkypeApp", "Microsoft.Wallet", "Microsoft.Whiteboard", "Microsoft.WindowsAlarms", "Microsoft.WindowsCamera", "Microsoft.WindowsFeedbackHub", "Microsoft.WindowsMaps", "Microsoft.WindowsPhone", "Microsoft.WindowsReadingList", "Microsoft.WindowsSoundRecorder", "Microsoft.Xbox.TCUI", "Microsoft.XboxApp", "Microsoft.XboxGameOverlay", "Microsoft.XboxSpeechToTextOverlay", "Microsoft.YourPhone", "Microsoft.ZuneMusic", "Microsoft.ZuneVideo", "Microsoft3DViewer", "NORDCURRENT.COOKINGFEVER", "PandoraMediaInc.29680B314EFC2", "Playtika.CaesarsSlotsFreeCasino", "ShazamEntertainmentLtd.Shazam", "SlingTVLLC.SlingTV", "SpotifyAB.SpotifyMusic", "TheNewYorkTimes.NYTCrossword", "ThumbmunkeysLtd.PhototasticCollage", "TuneIn.TuneInRadio", "WinZipComputing.WinZipUniversal", "XINGAG.XING", "flaregamesGmbH.RoyalRevolt2", "king.com.*", "king.com.BubbleWitch3Saga", "king.com.CandyCrushSaga", "king.com.CandyCrushSodaSaga", "microsoft.windowscommunicationsapps"
        ForEach ($WindowsApp in $WindowsApps) {
            Get-AppxPackage -allusers $WindowsApp | Remove-AppxPackage -AllUsers
            Get-AppXProvisionedPackage -Online | Where-Object DisplayName -eq $WindowsApp | Remove-AppxProvisionedPackage -Online
        }
    
        #Prevents Apps from re-installing
        $cdm = @(
            "ContentDeliveryAllowed"
            "FeatureManagementEnabled"
            "OemPreInstalledAppsEnabled"
            "PreInstalledAppsEnabled"
            "PreInstalledAppsEverEnabled"
            "SilentInstalledAppsEnabled"
            "SubscribedContent-314559Enabled"
            "SubscribedContent-338387Enabled"
            "SubscribedContent-338388Enabled"
            "SubscribedContent-338389Enabled"
            "SubscribedContent-338393Enabled"
            "SubscribedContentEnabled"
            "SystemPaneSuggestionsEnabled"
        )
    
        New-Item -Force  "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
        foreach ($key in $cdm) {
            Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" $key 0
        }
    
        Mkdir -Force  "HKLM:\Software\Policies\Microsoft\WindowsStore"
        Set-ItemProperty "HKLM:\Software\Policies\Microsoft\WindowsStore" "AutoDownload" 2
    
        #Prevents "Suggested Applications" returning
        New-Item -Force  "HKLM:\Software\Policies\Microsoft\Windows\CloudContent"
        Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1
    
    
        #  Description:
        #This script will remove and disable OneDrive integration.
    
        Import-Module -DisableNameChecking $PSScriptRoot\..\lib\Mkdir -Force .psm1
        Import-Module -DisableNameChecking $PSScriptRoot\..\lib\take-own.psm1
    
        Write-Output "Kill OneDrive process"
        Stop-Process -Force -Name "OneDrive.exe"
        Stop-Process -Force -Name "explorer.exe"
    
        Write-Output "Remove OneDrive"
        if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
            & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
        }
        if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
            & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
        }
    
        Write-Output "Removing OneDrive leftovers"
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"
        #check if directory is empty before removing:
        If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
        }
    
        Write-Output "Disable OneDrive via Group Policies"
        Mkdir -Force  "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\OneDrive"
        Set-ItemProperty "HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1
    
        Write-Output "Remove Onedrive from explorer sidebar"
        New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
        mkdir -Force "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
        Set-ItemProperty "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
        mkdir -Force "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
        Set-ItemProperty "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
        Remove-PSDrive "HKCR"
    
        #Thank you Matthew Israelsson
        Write-Output "Removing run hook for new users"
        reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
        reg delete "HKEY_USERS\Default\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
        reg unload "hku\Default"
    
        Write-Output "Removing startmenu entry"
        Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"
    
        Write-Output "Removing scheduled task"
        Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
    
        Write-Output "Restarting explorer"
        Start-Process "explorer.exe"
    
        Write-Output "Waiting for explorer to complete loading"
        Start-Sleep 10
    
        Write-Output "Removing additional OneDrive leftovers"
        foreach ($item in (Get-ChildItem "$env:WinDir\WinSxS\*onedrive*")) {
            Takeown-Folder $item.FullName
            Remove-Item -Recurse -Force $item.FullName
        }

        #Remove Bloatware Windows Apps
        Write-Output "Remove Reinstalled Apps"
        #Weather App
        Write-Output "removing Weather App"
        Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.BingWeather" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
        #Money App
        Write-Output "removing Money App"
        Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.BingFinance" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
        #Sports App
        Write-Output "removing Sports App"
        Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.BingSports" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
        #Twitter App
        Write-Output "removing Twitter App"
        Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "*.Twitter" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
        #XBOX App
        #Write-Output "removing XBOX App"
        #Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like"Microsoft.XboxApp"} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName}
        #Sway App
        Write-Output "removing Sway App"
        Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.Office.Sway" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
        #Onenote App
        Write-Output "removing Onenote App"
        Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.Office.OneNote" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
        #Get Office App
        Write-Output "removing Get Office App"
        Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.MicrosoftOfficeHub" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }
        #Get Skype App 
        Write-Output "removing skype App"
        Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -Like "Microsoft.SkypeApp" } | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }

        #This includes fixes by xsisbest
        Start-Job -Name "FixWhitelistedApps" -ScriptBlock {
            
            If (!(Get-AppxPackage -AllUsers | Select-Object Microsoft.Paint3D, Microsoft.MSPaint, Microsoft.WindowsCalculator, Microsoft.WindowsStore, Microsoft.MicrosoftStickyNotes, Microsoft.WindowsSoundRecorder, Microsoft.Windows.Photos)) {
            
                #Credit to abulgatz for the 4 lines of code
                Get-AppxPackage -allusers Microsoft.Paint3D | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
                Get-AppxPackage -allusers Microsoft.MSPaint | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
                Get-AppxPackage -allusers Microsoft.WindowsCalculator | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
                Get-AppxPackage -allusers Microsoft.WindowsStore | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
                Get-AppxPackage -allusers Microsoft.MicrosoftStickyNotes | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
                Get-AppxPackage -allusers Microsoft.WindowsSoundRecorder | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
                Get-AppxPackage -allusers Microsoft.Windows.Photos | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" } 
            }
        }

        Start-Job -Name "CheckDMWService" -ScriptBlock {
        
            If (Get-Service -Name dmwappushservice | Where-Object { $_.StartType -eq "Disabled" }) {
                Set-Service -Name dmwappushservice -StartupType Automatic
            }

            If (Get-Service -Name dmwappushservice | Where-Object { $_.Status -eq "Stopped" }) {
                Start-Service -Name dmwappushservice
            } 
        }

        Start-Job -Name "CheckInstallService" -ScriptBlock {
            If (Get-Service -Name InstallService | Where-Object { $_.Status -eq "Stopped" }) {  
                Start-Service -Name InstallService
                Set-Service -Name InstallService -StartupType Automatic 
            }
        }
    }

    #Debloating Scripts
    #This Start-Job -Name "finds any AppX/AppXProvisioned package and uninstalls it, except for Freshpaint, Windows Calculator, Windows Store, and Windows Photos.
    #Also, to note - This does NOT remove essential system services/software/etc such as .NET framework installations, Cortana, Edge, etc.

    #Creates a PSDrive to be able to access the 'HKCR' tree
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
    Start-Job -Name "Start-Debloat" -ScriptBlock {
        
        #Removes AppxPackages
        #Credit to Reddit user /u/GavinEke for a modified version of my whitelist code
        [regex]$WhitelistedApps = 'Microsoft.ScreenSketch|Microsoft.Paint3D|Microsoft.WindowsCalculator|Microsoft.WindowsStore|Microsoft.Windows.Photos|CanonicalGroupLimited.UbuntuonWindows|`
        Microsoft.MicrosoftStickyNotes|Microsoft.MSPaint|Microsoft.WindowsCamera|.NET|Framework|Microsoft.HEIFImageExtension|Microsoft.ScreenSketch|Microsoft.StorePurchaseApp|`
        Microsoft.VP9VideoExtensions|Microsoft.WebMediaExtensions|Microsoft.WebpImageExtension|Microsoft.DesktopAppInstaller'
        Get-AppxPackage -AllUsers | Where-Object { $_.Name -NotMatch $WhitelistedApps } | Remove-AppxPackage -ErrorAction SilentlyContinue
        #Run this again to avoid error on 1803 or having to reboot.
        Get-AppxPackage -AllUsers | Where-Object { $_.Name -NotMatch $WhitelistedApps } | Remove-AppxPackage -ErrorAction SilentlyContinue
        $AppxRemoval = Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -NotMatch $WhitelistedApps } 
        ForEach ( $App in $AppxRemoval) {
        
            Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName 
            
        }
    }

    Start-Job -Name "Remove-Keys" -ScriptBlock {  
        #These are the registry keys that it will delete.  
        $Keys = @(
            
            #Remove Background Tasks
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
            "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
            #"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
            #"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
            #Windows File
            "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            
            #Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
            #"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
            #"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
            #Scheduled Tasks to delete
            "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
            
            #Windows Protocol Keys
            "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
            #"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
            #"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
            #Windows Share Target
            "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        )
        
        #This writes the output of each key it is removing and also removes the keys listed above.
        ForEach ($Key in $Keys) {
            Write-Output "Removing $Key from registry"
            Remove-Item $Key -Recurse -ErrorAction SilentlyContinue
        }
    }
}
else {
    Write-Output "The Remove Bloatware Section Was Skipped..."
}

if ($disabletelemetry -eq $true) {
    Write-Host "Disabling Telemetry Reporting and Related Services" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\SoS\Telemetry"
    Start-Job -Name "Disable Telemetry" -ScriptBlock {
        #Disabling Telemetry and Services
        Write-Host "Disabling Telemetry and Related Services"
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name BingSearchEnabled -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name CortanaConsent -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Search" -Name BingSearchEnabled -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Search" -Name CortanaConsent -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name AllowCortana -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\" -Name "Search" -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Search" -Name BingSearchEnabled -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -Name "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" -Type "String" -Value  "BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search and Cortana application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|" -Force
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\" -Name "AU" -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name AUOptions -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name ScheduledInstallDay -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name ScheduledInstallTime -Type "DWORD" -Value 3 -Force
        New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\" -Name "Update" -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Update" -Name ExcludeWUDriversInQualityUpdate -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\Update" -Name ExcludeWUDriversInQualityUpdate -Type "DWORD" -Value 1 -Force
        New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\Update\" -Name "ExcludeWUDriversInQualityUpdates" -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\Update\ExcludeWUDriversInQualityUpdates" -Name Value -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name ExcludeWUDriversInQualityUpdate -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name ExcludeWUDriversInQualityUpdate -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WMDRM" -Name DisableOnline -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name BlockThirdPartyCookies -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name AutofillCreditCardEnabled -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name SyncDisabled -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Main" -Name AllowPrelaunch -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\" -Name "TabPreloader" -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name AllowTabPreloading -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\" -Name "MicrosoftEdge.exe" -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MicrosoftEdge.exe" -Name Debugger -Type "String" -Value "%windir%\System32\taskkill.exe" -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name BackgroundModeEnabled -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft" -Name DoNotUpdateToEdgeWithChromium -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\GameDVR" -Name AllowgameDVR -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKLM:\System\" -Name "GameConfigStore" -Force
        Set-ItemProperty -Path "HKLM:\System\GameConfigStore" -Name GameDVR_Enabled -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKLM:\Software\CurrentControlSet\" -Name "Control" -Force
        Set-ItemProperty -Path "HKLM:\Software\CurrentControlSet\Control" -Name SvcHostSplitThresholdInKB -Type "DWORD" -Value 04000000 -Force
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\" -Name "GameDVR" -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name  HistoricalCaptureEnabled -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\" -Name "GameDVR" -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLm:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name  HistoricalCaptureEnabled -Type "DWORD" -Value 0 -Force
    
        #Disable Razer Game Scanner Service
        Stop-Service "Razer Game Scanner Service"
        Set-Service  "Razer Game Scanner Service" -StartupType Disabled
    
        #Disable Windows Password Reveal Option
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredUI" -Name DisablePasswordReveal -Type "DWORD" -Value 1 -Force
    
        #Disable PowerShell 7+ Telemetry
        $POWERSHELL_Telemetry_OPTOUT = $true
        [System.Environment]::SetEnvironmentVariable('POWERSHELL_Telemetry_OPTOUT', 1 , [System.EnvironmentVariableTarget]::Machine)
        Write-Host $POWERSHELL_Telemetry_OPTOUT
    
        #Disable NET Core CLI Telemetry
        $DOTNET_CLI_Telemetry_OPTOUT = $true
        [System.Environment]::SetEnvironmentVariable('DOTNET_CLI_Telemetry_OPTOUT', 1 , [System.EnvironmentVariableTarget]::Machine)
        Write-Host $DOTNET_CLI_Telemetry_OPTOUT
    
        #Disable Office Telemetry
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" -Force
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" -Name "DisableTelemetry" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" -Name "DisableTelemetry" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" -Name "VerboseLogging" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" -Name "VerboseLogging" -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Mail" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Mail" -Name "EnableLogging" -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Mail" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Mail" -Name "EnableLogging" -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Calendar" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Calendar" -Name "EnableCalendarLogging" -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Calendar" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Calendar" -Name "EnableCalendarLogging" -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Word\Options" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Word\Options" -Name "EnableLogging" -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Options" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Options" -Name "EnableLogging" -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" -Name "EnableLogging" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" -Name "EnableUpload" -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" -Name "EnableLogging" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" -Name "EnableUpload" -Type "DWORD" -Value 0 -Force
        #Disable Office Telemetry Agent
        schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /DISABLE
        schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack2016" /DISABLE
        schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /DISABLE
        schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn2016" /DISABLE
        #Disable Office Subscription Heartbeat
        schtasks /change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /DISABLE
        schtasks /change /TN "Microsoft\Office\Office 16 Subscription Heartbeat" /DISABLE
        #Disable Office feedback
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Feedback" -Force
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Feedback" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Feedback" -Name "Enabled" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Feedback" -Name "Enabled" -Type "DWORD" -Value 0 -Force
        #Disable Office Customer Experience Improvement Program
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common" -Force
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common" -Name "QMEnable" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common" -Name "QMEnable" -Type "DWORD" -Value 0 -Force
    
        #Breaks Windows Account Logon - While not recommended many people still use it
        #Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\wlidsvc" -Name Start -Type "DWORD" -Value 4 -Force
        #Set-Service wlidsvc -StartupType Disabled
    
        #Disable Visual Studio Code Telemetry
        New-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\14.0\SQM" -Force
        New-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\15.0\SQM" -Force
        New-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\16.0\SQM" -Force
        Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\14.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\15.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\16.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKLM:\Software\Microsoft\VSCommon\14.0\SQM" -Force
        New-Item -Path "HKLM:\Software\Microsoft\VSCommon\15.0\SQM" -Force
        New-Item -Path "HKLM:\Software\Microsoft\VSCommon\16.0\SQM" -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\VSCommon\14.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\VSCommon\15.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\VSCommon\16.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKCU:\Software\Microsoft\VisualStudio\Telemetry" -Force
        New-Item -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\Feedback" -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\VisualStudio\Telemetry" -Name TurnOffSwitch -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\Feedback" -Name DisableFeedbackDialog -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\Feedback" -Name DisableEmailInput -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\Feedback" -Name DisableScreenshotCapture -Type "DWORD" -Value 1 -Force
        Stop-Service "VSStandardCollectorService150"
        Set-Service  "VSStandardCollectorService150" -StartupType Disabled
    
        #Disable Unnecessary Windows Services
        Stop-Service "MessagingService"
        Set-Service "MessagingService" -StartupType Disabled
        Stop-Service "PimIndexMaintenanceSvc"
        Set-Service "PimIndexMaintenanceSvc" -StartupType Disabled
        Stop-Service "RetailDemo"
        Set-Service "RetailDemo" -StartupType Disabled
        Stop-Service "MapsBroker"
        Set-Service "MapsBroker" -StartupType Disabled
        Stop-Service "DoSvc"
        Set-Service "DoSvc" -StartupType Disabled
        Stop-Service "OneSyncSvc"
        Set-Service "OneSyncSvc" -StartupType Disabled
        Stop-Service "UnistoreSvc"
        Set-Service "UnistoreSvc" -StartupType Disabled
    
        ###Disable Windows Error Reporting ###
        ###The error reporting feature in Windows is what produces those alerts after certain program or operating system errors, prompting you to send the information about the problem to Microsoft.
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type "DWORD" -Value 1 -Force
        Get-ScheduledTask -TaskName "QueueReporting" | Disable-ScheduledTask
    
        #Opt-out nVidia Telemetry
        Set-ItemProperty -Path "HKLM:\Software\NVIDIA Corporation\Global\FTS" -Name EnableRID44231 -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\NVIDIA Corporation\Global\FTS" -Name EnableRID64640 -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\NVIDIA Corporation\Global\FTS" -Name EnableRID66610 -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKLM:\Software\NVIDIA Corporation\NvControlPanel2\Client" -Force
        Set-ItemProperty -Path "HKLM:\Software\NVIDIA Corporation\NvControlPanel2\Client" -Name OptInOrOutPreference -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\NvTelemetryContainer" -Name Start -Type "DWORD" -Value 4 -Force
        Set-ItemProperty -Path "HKLM:\Software\NVIDIA Corporation\Global\Startup\SendTelemetryData" -Name 0 -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" -Name "SendTelemetryData" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\NvTelemetryContainer" -Name "Start" -Type "DWORD" -Value 4 -Force
        Stop-Service NvTelemetryContainer
        Set-Service NvTelemetryContainer -StartupType Disabled
        #Delete NVIDIA residual telemetry files
        Remove-Item -Recurse $env:systemdrive\System32\DriverStore\FileRepository\NvTelemetry*.dll
        Remove-Item -Recurse "$env:ProgramFiles\NVIDIA Corporation\NvTelemetry" | Out-Null
    
        #Disable Razer Game Scanner service
        Stop-Service "Razer Game Scanner Service"
        Set-Service "Razer Game Scanner Service" -StartupType Disabled
    
        #Disable Game Bar features
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\GameDVR" -Name AllowgameDVR -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name AppCaptureEnabled -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name  HistoricalCaptureEnabled -Type "DWORD" -Value 0 -Force
    
        #Disable Logitech Gaming service
        Stop-Service "LogiRegistryService"
        Set-Service "LogiRegistryService" -StartupType Disabled
    
        #Disable Visual Studio Telemetry
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VSCommon\14.0\SQM" -Name "OptIn" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VSCommon\15.0\SQM" -Name "OptIn" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\VSCommon\16.0\SQM" -Name "OptIn" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\14.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\15.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\VSCommon\16.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\VSCommon\14.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\VSCommon\15.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\VSCommon\16.0\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\VisualStudio\SQM" -Name OptIn -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\VisualStudio\Telemetry" -Name TurnOffSwitch -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Name "DisableFeedbackDialog" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Name "DisableEmailInput" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" -Name "DisableScreenshotCapture" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\VisualStudio\Telemetry" -Name "TurnOffSwitch" -Type "DWORD" -Value 1 -Force
        Stop-Service "VSStandardCollectorService150"
        Set-Service "VSStandardCollectorService150" -StartupType Disabled
    
        #Block Google Chrome Software Reporter Tool
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ChromeCleanupEnabled" -Type "String" -Value 0 -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ChromeCleanupReportingEnabled" -Type "String" -Value 0 -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "MetricsReportingEnabled" -Type "String" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisallowRun" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" -Name "1" -Type "String" -Value "software_reporter_tool.exe" /f
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\software_reporter_tool.exe" -Name Debugger -Type "String" -Value "%windir%\System32\taskkill.exe" -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "ChromeCleanupEnabled" -Type "String" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "ChromeCleanupReportingEnabled" -Type "String" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "MetricsReportingEnabled" -Type "String" -Value 0 -Force
    
        #Disable storing sensitive data in Acrobat Reader DC
        Set-ItemProperty -Path "HKCU:\Software\Adobe\Adobe ARM\1.0\ARM" -Name "iCheck" -Type "String" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "cSharePoint" -Type "String" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bToggleAdobeDocumentServices" -Type "String" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bToggleAdobeSign" -Type "String" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bTogglePrefSync" -Type "String" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bToggleWebConnectors" -Type "String" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bAdobeSendPluginToggle" -Type "String" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices" -Name "bUpdater" -Type "String" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Adobe\Adobe ARM\1.0\ARM" -Name "iCheck" -Type "String" -Value 0 -Force
    
        #Disable Adobe Acrobat Update Service
        Set-Service "Adobe Acrobat Update Task" -StartupType Disabled
        Set-Service "Adobe Flash Player Updater" -StartupType Disabled
        Set-Service "adobeflashplayerupdatesvc" -StartupType Disabled
        Set-Service "adobeupdateservice" -StartupType Disabled
        Set-Service "AdobeARMservice" -StartupType Disabled
    
        #Disable CCleaner Health Check
        Stop-Process -Force -Name  ccleaner.exe
        Stop-Process -Force -Name  ccleaner64.exe
        Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "HomeScreen" -Type "String" -Value 2 -Force
    
        #Disable CCleaner Monitoring && more
        Stop-Process -Force -Name "IMAGENAME eq CCleaner*"
        schtasks /Change /TN "CCleaner Update" /Disable
        Get-ScheduledTask -TaskName "CCleaner Update" | Disable-ScheduledTask
        Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "Monitoring" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "HelpImproveCCleaner" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "SystemMonitoring" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "UpdateAuto" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "UpdateCheck" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Piriform\CCleaner" -Name "CheckTrialOffer" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)HealthCheck" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)QuickClean" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)QuickCleanIpm" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)GetIpmForTrial" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)SoftwareUpdater" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Piriform\CCleaner" -Name "(Cfg)SoftwareUpdaterIpm" -Type "DWORD" -Value 0 -Force
    
        #Disable Dropbox Update service
        Set-Service dbupdate -StartupType Disabled
        Set-Service dbupdatem -StartupType Disabled
        Get-ScheduledTask -TaskName "DropboxUpdateTaskMachineCore" | Disable-ScheduledTask
        Get-ScheduledTask -TaskName "DropboxUpdateTaskMachineUA" | Disable-ScheduledTask
        #schtasks /Change /TN "DropboxUpdateTaskMachineCore" /Disable
        #schtasks /Change /TN "DropboxUpdateTaskMachineUA" /Disable
    
        #Disable Google update service
        Get-ScheduledTask -TaskName "GoogleUpdateTaskMachineCore" | Disable-ScheduledTask
        Get-ScheduledTask -TaskName "GoogleUpdateTaskMachineUA" | Disable-ScheduledTask
        #schtasks /Change /TN "GoogleUpdateTaskMachineCore" /Disable
        #schtasks /Change /TN "GoogleUpdateTaskMachineUA" /Disable
    
        #Disable Media Player Telemetry
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\MediaPlayer\Preferences" -Name "UsageTracking" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventCDDVDMetadataRetrieval" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventMusicFileMetadataRetrieval" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventRadioPresetsRetrieval" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Type "DWORD" -Value 1 -Force
        Set-Service WMPNetworkSvc -StartupType Disabled
    
        #Disable Microsoft Office Telemetry
        Get-ScheduledTask -TaskName "OfficeTelemetryAgentFallBack2016" | Disable-ScheduledTask
        Get-ScheduledTask -TaskName "OfficeTelemetryAgentLogOn2016" | Disable-ScheduledTask
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\15.0\osm" -Name "Enablelogging" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\15.0\osm" -Name "EnableUpload" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\osm" -Name "Enablelogging" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\osm" -Name "EnableUpload" -Type "DWORD" -Value 0 -Force
    
        #Disable Mozilla Firefox Telemetry
        Set-ItemProperty -Path "HKLM:\Software\Policies\Mozilla\Firefox" -Name "DisableTelemetry" -Type "DWORD" -Value 1 -Force
        #Disable default browser agent reporting policy
        Set-ItemProperty -Path "HKLM:\Software\Policies\Mozilla\Firefox" -Name "DisableDefaultBrowserAgent" -Type "DWORD" -Value 1 -Force
        #Disable default browser agent reporting services
        schtasks.exe /change /disable /tn "\Mozilla\Firefox Default Browser Agent 308046B0AF4A39CB"
        schtasks.exe /change /disable /tn "\Mozilla\Firefox Default Browser Agent D2CEEC440E2074BD"
    }
}
else {
    Write-Output "The Disable Telemetry Section Was Skipped..."
}

if ($privacy -eq $true) {
    Write-Host "Enabling Privacy and Security Focused" -ForegroundColor Green
    Start-Job -Name "Enable Privacy and Security Settings" -ScriptBlock {
        #Do not let apps on other devices open and message apps on this device, and vice versa
        New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" -Name RomeSdkChannelUserAuthzPolicy -PropertyType DWord -Value 1 -Force
        #Turn off Windows Location Provider
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Type "DWORD" -Value "1" -Force
        #Turn off location scripting
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Type "DWORD" -Value "1" -Force
        #Turn off location
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value "1" -Type "DWORD" -Force
        #For older Windows (before 1903)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Value "0" -Type "DWORD" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "Value" -Type "String" -Value "Deny" -Force
        #Deny app access to location
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" -Force
        #For older Windows (before 1903)
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Value "0" -Type "DWORD" -Force
        #Deny app access to motion data
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" -Name "Value" -Value "Deny" -Force
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMotion" -Type "DWORD" -Value 2 -Force
        #Deny app access to phone
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessPhone" -Type "DWORD" -Value 2 -Force
        #Deny app access to trusted devices
        #For older Windows (before 1903)
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" -Type "String" -Name "Value" -Value "DENY" -Force
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTrustedDevices" -Type "DWORD" -Value 2 -Force
        #Deny app sync with devices (unpaired, beacons, TVs etc.)
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices" -Type "DWORD" -Value 2 -Force
        #Deny app access to diagnostics info about your other apps
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Value "Deny" -Type "String" -Force
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsGetDiagnosticInfo" -Type "DWORD" -Value 2 -Force
        #Deny app access to your contacts
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" -Name "Value" -Value "Deny" -Type "String" -Force
        #For older Windows (before 1903)
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" -Type "String" -Name "Value" -Value "DENY" -Force
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessContacts" -Type "DWORD" -Value 2 -Force
        #Deny app access to Notifications
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" -Name "Value" -Value "Deny" -Type "String" -Force
        #For older Windows (before 1903)
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" -Type "String" -Name "Value" -Value "DENY" -Force
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessNotifications" -Type "DWORD" -Value 2 -Force
        #Deny app access to Calendar
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" -Name "Value" -Value "Deny" -Type "String" -Force
        #For older Windows (before 1903)
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" -Type "String" -Name "Value" -Value "DENY" -Force
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCalendar" -Type "DWORD" -Value 2 -Force
        #Deny app access to call history
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" -Name "Value" -Value "Deny" -Type "String" -Force
        #For older Windows (before 1903)
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" -Type "String" -Name "Value" -Value "DENY" -Force
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCallHistory" -Type "DWORD" -Value 2 -Force
        #Deny app access to email
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" -Name "Value" -Value "Deny" -Type "String" -Force
        #For older Windows (before 1903)
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" -Type "String" -Name "Value" -Value "DENY" -Force
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessEmail" -Type "DWORD" -Value 2 -Force
        #Deny app access to tasks
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" -Name "Value" -Value "Deny" -Type "String" -Force
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTasks" -Type "DWORD" -Value 2 -Force
        #Deny app access to messaging (SMS / MMS)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" -Name "Value" -Value "Deny" -Type "String" -Force
        #For older Windows (before 1903)
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" -Type "String" -Name "Value" -Value "DENY" -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}" -Type "String" -Name "Value" -Value "DENY" -Force
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMessaging" -Type "DWORD" -Value 2 -Force
        #Deny app access to radios
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" -Name "Value" -Value "Deny" -Type "String" -Force
        #For older Windows (before 1903)
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" -Type "String" -Name "Value" -Value "DENY" -Force
        #Using GPO (re-activation through GUI is not possible)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessRadios" -Type "DWORD" -Value 2 -Force
        #Deny app access to bluetooth devices
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" -Name "Value" -Value "Deny" -Type "String" -Force
        #Disable device metadata retrieval (breaks auto updates)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type "DWORD" -Value 1 -Force
        #Do not include drivers with Windows Updates
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type "DWORD" -Value 1 -Force
        #Prevent Windows Update for device driver search
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Type "DWORD" -Value 0 -Force
        #Disable Customer Experience Improvement (CEIP/SQM)
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type "DWORD" -Value "0" -Force
        #Disable Application Impact Telemetry (AIT)
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type "DWORD" -Value "0" -Force
        #Disable diagnostics telemetry
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\DiagTrack" -Name "Start" -Type "DWORD" -Value 4 -Force 
        Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\dmwappushsvc" -Name "Start" -Type "DWORD" -Value 4 -Force 
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "Start" -Type "DWORD" -Value 4 -Force 
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" -Name "Start" -Type "DWORD" -Value 4 -Force
        Stop-Service "DiagTrack"
        Set-Service "DiagTrack" -StartupType Disabled
        Stop-Service "dmwappushservice"
        Set-Service "dmwappushservice" -StartupType Disabled
        Stop-Service "diagnosticshub.standardcollector.service"
        Set-Service "diagnosticshub.standardcollector.service" -StartupType Disabled
        Stop-Service "diagsvc"
        Set-Service "diagsvc" -StartupType Disabled
        #Disable Customer Experience Improvement Program
        schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /DISABLE
        schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /DISABLE
        schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /DISABLE
        #Disable Webcam Telemetry (devicecensus.exe)
        schtasks /change /TN "Microsoft\Windows\Device Information\Device" /DISABLE
        # Disable Application Experience (Compatibility Telemetry)
        schtasks /change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /DISABLE
        schtasks /change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /DISABLE
        schtasks /change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /DISABLE
        schtasks /change /TN "Microsoft\Windows\Application Experience\AitAgent" /DISABLE
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" -Name "Debugger" -Type "String" -Value "%windir%\System32\taskkill.exe" -Force
        #Disable telemetry in data collection policy
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type "DWORD" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitEnhancedDiagnosticDataWindowsAnalytics" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value 0 -Force 
        #Disable license telemetry
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -Type "DWORD" -Value "1" -Force
        #Disable error reporting
        #Disable Windows Error Reporting (WER)
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type "DWORD" -Value "1" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type "DWORD" -Value "1" -Force
        #DefaultConsent / 1 - Always ask (default) / 2 - Parameters only / 3 - Parameters and safe data / 4 - All data
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting\Consent" -Name "DefaultConsent" -Type "DWORD" -Value "0" -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting\Consent" -Name "DefaultOverrideBehavior" -Type "DWORD" -Value "1" -Force
        #Disable WER sending second-level data
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting" -Name "DontSendAdditionalData" -Type "DWORD" -Value "1" -Force
        #Disable WER crash dialogs, popups
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting" -Name "LoggingDisabled" -Type "DWORD" -Value "1" -Force
        schtasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable
        schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
        #Disable Windows Error Reporting Service
        Stop-Service "WerSvc" 
        Set-Service "WerSvc" -StartupType Disabled
        Stop-Service "wercplsupport" 
        Set-Service "wercplsupport" -StartupType Disabled
        #Disable all settings sync
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSync" -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSyncUserOverride" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSyncOnPaidNetwork" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" -Name "SyncPolicy" -Type "DWORD" -Value 5 -Force
        #Disable Application Setting Sync
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableApplicationSettingSync" -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableApplicationSettingSyncUserOverride" -Type "DWORD" -Value 1 -Force
        #Disable App Sync Setting Sync
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableAppSyncSettingSync" -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableAppSyncSettingSyncUserOverride" -Type "DWORD" -Value 1 -Force
        #Disable App Sync Setting Sync
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableAppSyncSettingSync" -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableAppSyncSettingSyncUserOverride" -Type "DWORD" -Value 1 -Force
        #Disable Desktop Theme Setting Sync
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableDesktopThemeSettingSync" -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableDesktopThemeSettingSyncUserOverride" -Type "DWORD" -Value 1 -Force
        #Disable Personalization Setting Sync
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisablePersonalizationSettingSync" -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisablePersonalizationSettingSyncUserOverride" -Type "DWORD" -Value 1 -Force
        #Disable Start Layout Setting Sync
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableStartLayoutSettingSync" -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableStartLayoutSettingSyncUserOverride" -Type "DWORD" -Value 1 -Force
        #Disable Web Browser Setting Sync
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWebBrowserSettingSync" -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWebBrowserSettingSyncUserOverride" -Type "DWORD" -Value 1 -Force
        #Disable Windows Setting Sync
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWindowsSettingSync" -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableWindowsSettingSyncUserOverride" -Type "DWORD" -Value 1 -Force
        #Disable Windows Insider Service
        Stop-Service "wisvc" 
        Set-Service "wisvc" -StartupType Disabled
        #Do not let Microsoft try features on this build
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableExperimentation" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableConfigFlighting" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" -Name "value" -Type "DWORD" -Value 0 -Force
        #Disable getting preview builds of Windows
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Type "DWORD" -Value 0 -Force
        #Remove "Windows Insider Program" from Settings
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" -Name "HideInsiderPage" -Type "DWORD" -Value "1" -Force
        #Disable ad customization with Advertising ID
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type "DWORD" -Value 0 -Force 
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type "DWORD" -Value 1 -Force
        #Disable targeted tips
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Type "DWORD" -Value "1" -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type "DWORD" -Value "1" -Force
        #Turn Off Suggested Content in Settings app
        New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -PropertyType "DWord" -Value "0" -Force
        New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -PropertyType "DWord" -Value "0" -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Value "0" -Type "DWORD" -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Value "0" -Type "DWORD" -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Value "0" -Type "DWORD" -Force
        #Disable cortana
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type "DWORD" -Value 0 -Force 
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" -Name "value" -Type "DWORD" -Value 0 -Force 
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaEnabled" -Type "DWORD" -Value 0 -Force 
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaEnabled" -Type "DWORD" -Value 0 -Force 
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CanCortanaBeEnabled" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name BingSearchEnabled -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanaAboveLock" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent"  -Value 0 -Type "DWORD" -Force 
        #Disable web search in search bar
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name DisableWebSearch -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -Type "DWORD" -Force                   
        #Disable search web when searching pc
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name ConnectedSearchUseWeb -Type "DWORD" -Value 0 -Force
        #Disable search indexing encrypted items / stores
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name AllowIndexingEncryptedStoresOrItems -Type "DWORD" -Value 0 -Force
        #Disable location based info in searches
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name AllowSearchToUseLocation -Type "DWORD" -Value 0 -Force
        #Disable language detection
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name AlwaysUseAutoLangDetection -Type "DWORD" -Value 0 -Force
        #Opt out from Windows privacy consent
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type "DWORD" -Value 0 -Force
        #Disable cloud speech recognation
        New-Item -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Type "DWORD" -Value 0 -Force
        #Disable text and handwriting collection
        New-Item -Path "HKCU:\Software\Policies\Microsoft\InputPersonalization" -Force
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type "DWORD" -Value 1 -Force
        New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Force
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Type "DWORD" -Value 1 -Force
        New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\TabletPC" -Force
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type "DWORD" -Value 1 -Force
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Force
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type "DWORD" -Value 0 -Force
        #Disable Windows feedback
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type "DWORD" -Value 0 -Force 
        reg delete "HKCU\SOFTWARE\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type "DWORD" -Value 1 -Force 
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type "DWORD" -Value 1 -Force
        #Disable Wi-Fi sense
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "value" -Type "DWORD" -Value 0 -Force 
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "value" -Type "DWORD" -Value 0 -Force 
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type "DWORD" -Value 0 -Force 
        #Disable App Launch Tracking
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Value 0 -Type "DWORD" -Force
        #Disable Activity Feed
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value "0" -Type "DWORD" -Force
        #Disable feedback on write (sending typing info)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Type "DWORD" -Value 0 -Force
        #Disable Windows DRM internet access
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Type "DWORD" -Value 1 -Force
        #Disable game screen recording
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type "DWORD" -Value 0 -Force 
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type "DWORD" -Value 0 -Force
        #Disable Auto Downloading Maps
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AllowUntriggeredNetworkTrafficOnSettingsPage" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AutoDownloadAndUpdateMapData" -Type "DWORD" -Value 0 -Force
        #Disable Website Access of Language List
        Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type "DWORD" -Value 1 -Force
        #Disable Inventory Collector
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Type "DWORD" -Value 1 -Force
        #Do not send Watson events
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableGenericReports" -Type "DWORD" -Value 1 -Force
        #Disable Malicious Software Reporting tool diagnostic data
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Type "DWORD" -Value 1 -Force
        #Disable local setting override for reporting to Microsoft MAPS
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "LocalSettingOverrideSpynetReporting" -Type "DWORD" -Value 0 -Force
        #Turn off Windows Defender SpyNet reporting
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type "DWORD" -Value 0 -Force
        #Do not send file samples for further analysis
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type "DWORD" -Value 2 -Force
        #Disable live tile data collection
        New-Item -Path "HKCU:\Software\Policies\Microsoft\MicrosoftEdge\Main" -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\MicrosoftEdge\Main" -Name "PreventLiveTileDataCollection" -Type "DWORD" -Value 1 -Force
        #Disable MFU tracking
        New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\EdgeUI" -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\EdgeUI" -Name "DisableMFUTracking" -Type "DWORD" -Value 1 -Force
        #Disable recent apps
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\EdgeUI" -Name "DisableRecentApps" -Type "DWORD" -Value 1 -Force
        #Turn off backtracking
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\EdgeUI" -Name "TurnOffBackstack" -Type "DWORD" -Value 1 -Force
        #Disable Search Suggestions in Edge
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes" -Name "ShowSearchSuggestionsGlobal" -Type "DWORD" -Value 0 -Force
        #Disable Geolocation in Internet Explorer
        New-Item -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\Geolocation" -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Internet Explorer\Geolocation" -Name "PolicyDisableGeolocation" -Type "DWORD" -Value 1 -Force
        #Disable Internet Explorer InPrivate logging
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Safety\PrivacIE" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Safety\PrivacIE" -Name "DisableLogging" -Type "DWORD" -Value 1 -Force
        #Disable Internet Explorer CEIP
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" -Name "DisableCustomerImprovementProgram" -Type "DWORD" -Value 0 -Force
        #Disable calling legacy WCM policies
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "CallLegacyWCMPolicies" -Type "DWORD" -Value 0 -Force
        #Do not send Windows Media Player statistics
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences" -Name "UsageTracking" -Type "DWORD" -Value 0 -Force
        #Disable metadata retrieval
        New-Item -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer"  -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventCDDVDMetadataRetrieval" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventMusicFileMetadataRetrieval" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventRadioPresetsRetrieval" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Type "DWORD" -Value 1 -Force
        #Disable dows Media Player Network Sharing Service
        Stop-Service "WMPNetworkSvc" 
        Set-Service "WMPNetworkSvc" -StartupType Disabled
        #Disable lock screen camera
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Type "DWORD" -Value 1 -Force
        #Disable remote Assistance
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowFullControl" -Type "DWORD" -Value 0 -Force
        #Disable AutoPlay and AutoRun
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type "DWORD" -Value 255 -Force 
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Type "DWORD" -Value 1 -Force
        #Disable Windows Installer Always install with elevated privileges
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Type "DWORD" -Value 0 -Force
        #Refuse less secure authentication
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Type "DWORD" -Value 5 -Force
        #Disable the Windows Connect Now wizard
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\UI" -Name "DisableWcnUi" -Type "DWORD" -Value 1 -Force
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableFlashConfigRegistrar" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableInBand802DOT11Registrar" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableUPnPRegistrar" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableWPDRegistrar" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "EnableRegistrars" -Type "DWORD" -Value 0 -Force
        #Disable online tips
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "AllowOnlineTips" -Type "DWORD" -Value 0 -Force
        #Turn off Internet File Association service
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInternetOpenWith" -Type "DWORD" -Value 1 -Force
        #Turn off the "Order Prints" picture task
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoOnlinePrintsWizard" -Type "DWORD" -Value 1 -Force
        #Disable the file and folder Publish to Web option
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoPublishingWizard" -Type "DWORD" -Value 1 -Force
        #Prevent downloading a list of providers for wizards
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWebServices" -Type "DWORD" -Value 1 -Force
        #Do not keep history of recently opened documents
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Type "DWORD" -Value 1 -Force
        #Clear history of recently opened documents on exit
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentDocsOnExit" -Type "DWORD" -Value 1 -Force
        #Disable lock screen app notifications
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -Type "DWORD" -Value 1 -Force
        #Disable Live Tiles push notifications
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoTileApplicationNotification" -Type "DWORD" -Value 1 -Force
        #Turn off "Look For An App In The Store" option
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type "DWORD" -Value 1 -Force
        #Do not show recently used files in Quick Access
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Value 0 -Type "DWORD" -Force
        reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3134ef9c-6b18-4996-ad04-ed5912e00eb5}" /f
        reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3134ef9c-6b18-4996-ad04-ed5912e00eb5}" /f
        #Disable Sync Provider Notifications
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 0 -Type "DWORD" -Force
        #Enable camera on/off OSD notifications
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\OEM\Device\Capture" -Name "NoPhysicalCameraLED" -Value 1 -Type "DWORD" -Force
    
        #Windows Defender Privacy Options
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableGenericRePorts" -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -Name "LocalSettingOverrideSpynetReporting" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Type "DWORD" -Value 1 -Force
        #Remove the automatic start item for OneDrive from the default user profile registry hive
        Write-Output "remove onedrive automatic start"
        Remove-Item -Path "C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\OneDrive.lnk" -Force 
        Start-Process C:\\Windows\\System32\\Reg.exe -ArgumentList "Load HKLM\\Temp C:\\Users\\Default\\NTUSER.DAT" -Wait
        Start-Process C:\\Windows\\System32\\Reg.exe -ArgumentList "Delete HKLM\\Temp\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -Name OneDriveSetup -Force" -Wait
        Start-Process C:\\Windows\\System32\\Reg.exe -ArgumentList "Unload HKLM\\Temp"
        #Disable Cortana
        Write-Output "disabling cortona"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name AllowCortana -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name AllowSearchToUseLocation -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name DisableWebSearch -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name ConnectedSearchUseWeb -Type "DWORD" -Value 0 -Force
        #Disable Device Metadata Retrieval
        Write-Output "Disable Device Metadata Retrieval"
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\" -Name "Device Metadata" -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Device Metadata" -Name PreventDeviceMetadataFromNetwork -Type "DWORD" -Value 1 -Force
        #Disable Find My Device
        Write-Output "Disable Find My Device"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\FindMyDevice" -Name AllowFindMyDevice -Type "DWORD" -Value 0 -Force
        #Disable Font Streaming
        Write-Output "Disable Font Streaming"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name EnableFontProviders -Type "DWORD" -Value 0 -Force
        #Disable Insider Preview Builds
        Write-Output "Disable Insider Preview Builds"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds" -Name AllowBuildPreview -Type "DWORD" -Value 0 -Force
        Write-Output "IE Optimizations"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" -Name EnabledV9 -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\" -Name "Geolocation" -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Geolocation" -Name PolicyDisableGeolocation -Type "DWORD" -Value 1 -Force
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Explorer\" -Name "AutoComplete" -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" -Name AutoSuggest -Type "String" -Value no -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer" -Name AllowServicePoweredQSA -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\" -Name "Suggested Sites" -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Suggested Sites" -Name Enabled -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\" -Name "FlipAhead" -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\FlipAhead" -Name Enabled -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds" -Name BackgroundSyncStatus -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name AllowOnlineTips -Type "DWORD" -Value 0 -Force
        #Restrict License Manager
        #Write-Output "Restrict License Manager"
        #Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LicenseManager" -Name Start -Type "DWORD" -Value 4 -Force
        #Disable Live Tiles
        Write-Output "Disable Live Tiles"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name NoCloudApplicationNotification -Type "DWORD" -Value 1 -Force
        #Disable Windows Mail App
        Write-Output "Disable Windows Mail App"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Mail" -Name ManualLaunchAllowed -Type "DWORD" -Value 0 -Force
        #Disable Network Connection Status Indicator
        #Write-Output "Disable Network Connection Status Indicator"
        #Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name NoActiveProbe -Type "DWORD" -Value 1 -Force
        #Disable Offline Maps
        Write-Output "Disable Offline Maps"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Maps" -Name AutoDownloadAndUpdateMapData -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Maps" -Name AllowUntriggeredNetworkTrafficOnSettingsPage -Type "DWORD" -Value 0 -Force
    
        ##General VM Optimizations
        #Change TTL for ISP throttling workaround
        int ipv4 set glob defaultcurhoplimit=65
        int ipv6 set glob defaultcurhoplimit=65
        #Auto Cert Update
        Write-Output "Auto Cert Update"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\SystemCertificates\AuthRoot" -Name DisableRootAutoUpdate -Type "DWORD" -Value 0 -Force
        #Turn off Let websites provide locally relevant content by accessing my language list
        Write-Output "Turn off Let websites provide locally relevant content by accessing my language list"
        Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name HttpAcceptLanguageOptOut -Type "DWORD" -Value 1 -Force
        #Turn off Let Windows track app launches to improve Start and search results
        Write-Output "Turn off Let Windows track app launches to improve Start and search results"
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name Start_TrackProgs -Type "DWORD" -Value 0 -Force
        #Turn off Let apps use my advertising ID for experiences across apps (turning this off will reset your ID
        Write-Output "Turn off Let apps use my advertising ID for experiences across apps (turning this off will reset your ID"
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name Enabled -Type "DWORD" -Value 0 -Force
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\" -Name "AdvertisingInfo"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AdvertisingInfo" -Name DisabledByGroupPolicy -Type "DWORD" -Value 1 -Force
        #Turn off Let websites provide locally relevant content by accessing my language list
        Write-Output "Turn off Let websites provide locally relevant content by accessing my language list"
        Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name HttpAcceptLanguageOptOut -Type "DWORD" -Value 1 -Force
        #Turn off Let apps on my other devices open apps and continue experiences on this device
        Write-Output "Turn off Let apps on my other devices open apps and continue experiences on this device"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name EnableCdp -Type "DWORD" -Value 1 -Force
        #Turn off Location for this device
        Write-Output "Turn off Location for this device"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -Name LetAppsAccessLocation -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors" -Name DisableLocation -Type "DWORD" -Value 1 -Force
        #Turn off Windows should ask for my feedback
        Write-Output "Turn off Windows should ask for my feedback"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name DoNotShowFeedbackNotifications -Type "DWORD" -Value 1 -Force
        #Turn Off Send your device data to Microsoft
        Write-Output "Turn Off Send your device data to Microsoft"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name AllowTelemetry -Type "DWORD" -Value 0 -Force
        #Turn off tailored experiences with relevant tips and recommendations by using your diagnostics data
        Write-Output "Turn off tailored experiences with relevant tips and recommendations by using your diagnostics data"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name DisableWindowsConsumerFeatures -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name DisableTailoredExperiencesWithDiagnosticData -Type "DWORD" -Value 1 -Force
        New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\" -Name "CloudContent" -Force
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name DisableTailoredExperiencesWithDiagnosticData -Type "DWORD" -Value 1 -Force
        #Turn off Let apps run in the background
        Write-Output "Turn off Let apps run in the background"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -Name LetAppsRunInBackground -Type "DWORD" -Value 2 -Force
        #Software Protection Platform
        #Opt out of sending KMS client activation data to Microsoft
        Write-Output "Opt out of sending KMS client activation data to Microsoft"
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\" -Name "Software Protection Platform" -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name NoGenTicket -Type "DWORD" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name NoAcquireGT -Type "DWORD" -Value 1 -Force
        #Turn off Messaging cloud sync
        Write-Output "Turn off Messaging cloud sync"
        New-Item -Path "HKCU:\Software\Microsoft\" -Name "Messaging" -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Messaging" -Name CloudServiceSyncEnabled -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Messaging" -Name CloudServiceSyncEnabled -Type "DWORD" -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\SettingSync" -Name DisableSettingSync -Type "DWORD" -Value 2 -Force
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\SettingSync" -Name DisableSettingSyncUserOverride -Type "DWORD" -Value 1 -Force
        #Disable Teredo
        #Broke too many things. Should be disabled in an enterprise, but not for personal systems
        #Write-Output "Disable Teredo"
        #Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\TCPIP\v6Transition" -Name Teredo_State -Type "String" -Value Disabled -Force
        #Delivery Optimization
        Write-Output "Delivery Optimization"
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization" -Name DODownloadMode -Type "DWORD" -Value 99 -Force
        ###Disable app access to account info
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to calendar
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to call history
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to contacts
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to diagnostic information
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to documents
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to email
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to file system
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to location
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to messaging
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to motion
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to notifications
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" -Type "String" -Name Value -Value "DENY" -Force
        ###Disable app access to other devices
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth" -Name Value -Type "String" -Value "DENY" -Force
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to call
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to pictures
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to radios
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to tasks
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable app access to videos
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" -Name Value -Type "String" -Value "DENY" -Force
        ###Disable tracking of app starts ###
        ###Windows can personalize your Start menu based on the apps that you launch. ###
        ###This allows you to quickly have access to your list of Most used apps both in the Start menu and when you search your device.
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name Start_TrackProgs -Type "DWORD" -Value 0 -Force
        ###Disable Bing in Windows Search ###
        ###Like Google, Bing is a search engine that needs your data to improve its search results. Windows 10, by default, sends everything you search for in the Start Menu to their servers to give you results from Bing search. ###
        ###These searches are then uploaded to Microsoft's Privacy Dashboard.
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name "BingSearchEnabled" -Type "DWORD" -Value 0 -Force
        ###Disable Cortana ###
        ###With the Anniversary Update, Microsoft hid the option to disable Cortana. This policy makes it possible again. It will block the outbound network connections completely in the Firewall.
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type "DWORD" -Value 0 -Force
        If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules")) {
            New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -Force | Out-Null
        }
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -Name "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" -Type "String" -Value "BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search and Cortana application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|" -Force
    
        #Display full path in explorer
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\" -Name "CabinetState" -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Name FullPath -Type "DWORD" -Value 1 -Force
    
        #Make icons easier to touch in explorer
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name FileExplorerInTouchImprovement -Type "DWORD" -Value 1 -Force
    
        Write-Output "Disabling Telemetry via Group Policies"
        New-Item -Force  "HKLM:\Software\Policies\Microsoft\Windows\DataCollection"
        Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0 
     
        ###Prevent Edge from running in background ###
        ###On the new Chromium version of Microsoft Edge, extensions and other services can keep the browser running in the background even after it's closed. ###
        ###Although this may not be an issue for most desktop PCs, it could be a problem for laptops and low-end devices as these background processes can increase battery consumption and memory usage. The background process displays an icon in the system tray and can always be closed from there. ###
        ###If you run enable this policy the background mode will be disabled.
        If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Edge")) {
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Edge" -Force | Out-Null
        }
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "BackgroundModeEnabled" -Type "DWORD" -Value 0 -Force
    
        ###Disable synchronization of data ###
        ###This policy will disable synchronization of data using Microsoft sync services.
        If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Edge")) {
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Edge" -Force | Out-Null
        }
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SyncDisabled" -Type "DWORD" -Value 1 -Force
    
        ###Disable AutoFill for credit cards ###
        ###Microsoft Edge's AutoFill feature lets users auto complete credit card information in web forms using previously stored information. ###
        ###If you enable this policy, Autofill never suggests or fills credit card information, nor will it save additional credit card information that users might submit while browsing the web.
        If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Edge")) {
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Edge" -Force | Out-Null
        }
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "AutofillCreditCardEnabled" -Type "DWORD" -Value 0 -Force
    
        ###Disable Game Bar features ###
        ###The Game DVR is a feature of the Xbox app that lets you use the Game bar (Win+G) to record and share game clips and screenshots in Windows 10. However, you can also use the Game bar to record videos and take screenshots of any app in Windows 10. ###
        ###This Policy will disable the Windows Game Recording and Broadcasting.
        If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\GameDVR")) {
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null
        }
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type "DWORD" -Value 0 -Force
        ###Block suggestions and automatic Installation of apps ###
        ###Microsoft flushes various apps into the system without being asked, especially games such as Candy Crush Saga. Users have to uninstall these manually if they don't want them on their computer. ###
        ###To prevent these downloads from starting in the first place, a small intervention in the registry helps. Suggested apps pinned to Start are basically just advertising. This script will also disable suggested apps (ex: Candy Crush Soda Saga) for all accounts.
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type "DWORD" -Value 0 -Force
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type "DWORD" -Value 0 -Force
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type "DWORD" -Value 0 -Force
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type "DWORD" -Value 0 -Force
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type "DWORD" -Value 0 -Force
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type "DWORD" -Value 0 -Force
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type "DWORD" -Value 0 -Force
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type "DWORD" -Value 0 -Force
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type "DWORD" -Value 0 -Force
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type "DWORD" -Value 0 -Force
        If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent")) {
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
        }
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type "DWORD" -Value 1 -Force
    
        ###Disable Clipboard history ###
        ###With Windows 10 build 17666 or later, Microsoft has allowed cloud synchronization of clipboard. It is a special feature to sync clipboard content across all your devices connected with your Microsoft Account.
        New-Item -Path "HKCU:\Software\Microsoft\" -Name "Clipboard" -Force
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -Type "DWORD" -Value 0 -Force
        ###Disable Compatibility Telemetry ###
        ###The Windows Compatibility Telemetry process is periodically collecting a variety of technical data about your computer and its performance and sending it to Microsoft for its Windows Customer Experience Improvement Program. It is enabled by default, and the data points are useful for Microsoft to improve Windows 10. ###
        ###The CompatTelRunner.exe file is also used to upgrade your system to the latest OS version and install the latest updates. ###
        ###The process is not generally required for the Windows operating system to run properly and can be stopped or deleted. This script will disable the CompatTelRunner.exe (Compatibility Telemetry process) in a more cleaner way using Image File Execution Options Debugger Value. Setting this value to an executable designed to kill processes disables it. Windows won't re-enable it with almost each update. 
        If (!(Test-Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe")) {
            New-Item -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" -Force | Out-Null
        }
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" -Name "Debugger" -Type "String" -Value "%windir%\System32\taskkill.exe" -Force
    
     
        ###Disable Customer Experience Improvement Program ###
        Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" | Disable-ScheduledTask
        ###Disable Location tracking ###
        ###When Location Tracking is turned on, Windows and its apps are allowed to detect the current location of your computer or device. ###
        ###This can be used to pinpoint your exact location, e.g. Map traces the location of PC and helps you in exploring nearby restaurants.
        If (!(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
            New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
        }
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type "String" -Value "Deny" -Force
        ###Disable Telemetry in Windows 10 ###
        ###As you use Windows 10, Microsoft will collect usage information. All its options are available in Settings -> Privacy - Feedback and Diagnostics. There you can set the options "Diagnostic and usage data" to Basic, Enhanced and Full. This will set diagnostic data to Basic, which is the lowest level available for all consumer versions of Windows 10 ###
        ###NOTE: Diagnostic Data must be set to Full to get preview builds from Windows-Insider-Program! Just set the value of the AllowTelemetry key to "3" to revert the policy changes. All other changes remain unaffected.
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\" -Name "DataCollection" -Type "DWORD" -Value 0 -Force
        #Stop and Disable Diagnostic Tracking Service
        New-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\DiagTrack" -Name "Start" -Type "DWORD" -Value 4 -Force
        Stop-Service -Name DiagTrack
        Set-Service -Name DiagTrack -StartupType Disabled
        #Stop and Disable dmwappushservice Service
        New-Item -Path "HKLM:\SYSTEM\ControlSet001\Services\" -Name "dmwappushsvc" -Force
        New-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\dmwappushsvc" -Name "Start" -Type "DWORD" -Value 4 -Force
        Stop-Service -Name dmwappushservice
        Set-Service -Name dmwappushservice -StartupType Disabled
        ###Disable Timeline history ###
        ###Microsoft made Timeline available to the public with Windows 10 build 17063. It collects a history of activities you've performed, including files you've opened and web pages you've viewed in Edge.
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type "DWORD" -Value 0 -Force
        ###Disable Windows Tips ###
        ###Microsoft uses diagnostic information to determine which tips are appropriate. If you enable this policy, you will no longer see Windows Tips, e.g. Spotlight and Consumer Features, Feedback Notifications etc.
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Type "DWORD" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Type "DWORD" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeature" -Type "DWORD" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type "DWORD" -Value 1 -Force
    
        ###Do not show feedback notifications ###
        ###Windows 10 doesn’t just automatically collect information about your computer usage. It does do that, but it may also pop up from time to time and ask for feedback. This information is used to improve Windows 10 - in theory. As of Windows 10’s “November Update,” the Windows Feedback application is installed by default on all Windows 10 PCs. ###
        ###If you are running Windows 10 in a corporate setting, you should likely disable the Windows Feedback prompts that appear every few weeks.
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Type "DWORD" -Value 0 -Force
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type "DWORD" -Value 0 -Force
        ###Prevent using diagnostic data ###
        ###Starting with Windows 10 build 15019, a new privacy setting to "let Microsoft provide more tailored experiences with relevant tips and recommendations by using your diagnostic data" has been added. By enabling this policy you can prevent Microsoft from using your diagnostic data. 
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Type "DWORD" -Value 0 -Force
        ###Turn off Advertising ID for Relevant Ads ###
        ###Windows 10 comes integrated with advertising. Microsoft assigns a unique identificator to track your activity in the Microsoft Store and on UWP apps to target you with relevant ads. ###
        ###If someone is giving you personalized ads, it means they are tracking your data. Turn off the advertising feature from Windows 10 with this policy to stay secure.
        New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type "DWORD" -Value 0 -Force
        ###Turn off help Microsoft improve typing and writing ###
        ###When the Getting to know you privacy setting is turned on for inking & typing personalization in Windows 10, you can use your typing history and handwriting patterns to create a local user dictionary for you that is used to make better typing suggestions and improve handwriting recognition for each of the languages you use.
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Type "DWORD" -Value 0 -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type "DWORD" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type "DWORD" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Type "DWORD" -Value 1 -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type "DWORD" -Value 1 -Force
        ###Disable password reveal button ###
        ###On the new login screen, Microsoft added a password review button that displays what's in the password box in plain text when pressed. Note that, disabling Password Reveal button disables this feature not only in login screen but also in Microsoft Edge, Internet Explorer as well. ###
        ###Visible passwords may be seen by nearby persons, compromising them. The password reveal button can be used to display an entered password and should be disabled with this policy.
        If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\CredUI")) {
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CredUI" -Force | Out-Null
        }
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -Type "DWORD" -Value 1 -Force
    
        ###Disable Windows Media DRM Internet Access ###
        ###DRM stands for digital rights management. DRM is a technology used by content providers, such as online stores, to control how the digital music and video files you obtain from them are used and distributed. Online stores sell and rent songs and movies that have DRM applied to them. ###
        ###If the Windows Media Digital Rights Management should not get access to the Internet, you can enable this policy to prevent it.
        If (!(Test-Path "HKLM:\Software\Policies\Microsoft\WMDRM")) {
            New-Item -Path "HKLM:\Software\Policies\Microsoft\WMDRM" -Force | Out-Null
        }
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Type "DWORD" -Value 1 -Force
    
        ###Disable forced updates ###
        ###This will notify when updates are available, and you decide when to install them.
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type "DWORD" -Value 0 -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type "DWORD" -Value 2 -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Type "DWORD" -Value 0 -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -Type "DWORD" -Value 3 -Force
    
        ###Turn off distributing updates to other computers ###
        ###Windows 10 lets you download updates from several sources to speed up the process of updating the operating system. ###
        ###If you don't want your files to be shared by others and exposing your IP address to random computers, you can apply this policy and turn this feature off. ###
        ###Acceptable selections include:
        ###Bypass (100) 
        ###Group (2)
        ###HTTP only (0) Enabled by SharpApp!
        ###LAN (1)
        ###Simple (99)
        If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization")) {
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization" -Force | Out-Null
        }
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Type "DWORD" -Value 0 -Force
    
    
        Write-Output "Defuse Windows search settings"
        Set-WindowsSearchSetting -EnableWebResultsSetting $false
    
        Write-Output "Set general privacy options"
        #"Let websites provide locally relevant content by accessing my language list"
        Set-ItemProperty "HKCU:\Control Panel\International\User Profile" "HttpAcceptLanguageOptOut" 1
        #Locaton aware printing (changes default based on connected network)
        Mkdir "HKCU:\Printers\Defaults" -Force
        New-Item -Path "HKCU:\Printers\" -Name "Defaults" -Force
        Set-ItemProperty "HKCU:\Printers\Defaults" "NetID" "{00000000-0000-0000-0000-000000000000}"
        #"Send Microsoft info about how I write to help us improve typing and writing in the future"
        Mkdir "HKCU:\Software\Microsoft\Input\TIPC" -Force
        Set-ItemProperty "HKCU:\Software\Microsoft\Input\TIPC" "Enabled" 0
        #"Let apps use my advertising ID for experiencess across apps"
        Mkdir -Force  "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
        Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0
        #"Turn on SmartScreen Filter to check web content"
        Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" "EnableWebContentEvaluation" 0
    
        Write-Output "Disable synchronisation of settings"
        #These only apply if you log on using Microsoft account
        Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync" "BackupPolicy" 0x3c
        Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync" "DeviceMetadataUploaded" 0
        Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync" "PriorLogons" 1
        $groups = @(
            "Accessibility"
            "AppSync"
            "BrowserSettings"
            "Credentials"
            "DesktopTheme"
            "Language"
            "PackageState"
            "Personalization"
            "StartLayout"
            "Windows"
        )
        foreach ($group in $groups) {
            Mkdir -Force  "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$group"
            Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$group" "Enabled" 0
        }
    
        Write-Output "Set privacy policy accepted state to 0"
        #Prevents sending speech, inking and typing samples to MS (so Cortana
        #can learn to recognise you)
        Mkdir -Force  "HKCU:\Software\Microsoft\Personalization\Settings"
        Set-ItemProperty "HKCU:\Software\Microsoft\Personalization\Settings" "AcceptedPrivacyPolicy" 0
    
        Write-Output "Do not scan contact informations"
        #Prevents sending contacts to MS (so Cortana can compare speech etc samples)
        Mkdir -Force  "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore"
        Set-ItemProperty "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts" 0
    
        Write-Output "Inking and typing settings"
        #Handwriting recognition personalization
        Mkdir -Force  "HKCU:\Software\Microsoft\InputPersonalization"
        Set-ItemProperty "HKCU:\Software\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1
        Set-ItemProperty "HKCU:\Software\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1
    
        Write-Output "Microsoft Edge settings"
        Mkdir -Force  "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main"
        Set-ItemProperty "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" "DoNotTrack" 1
        Mkdir -Force  "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes"
        Set-ItemProperty "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes" "ShowSearchSuggestionsGlobal" 0
        Mkdir -Force  "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead"
        Set-ItemProperty "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead" "FPEnabled" 0
        Mkdir -Force  "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter"
        Set-ItemProperty "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" "EnabledV9" 0
    
        Write-Output "Disable background access of default apps"
        foreach ($key in (Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications")) {
            Set-ItemProperty ("HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\" + $key.PSChildName) "Disabled" 1
        }
    
        Write-Output "Denying device access"
        #Disable sharing information with unpaired devices
        Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "Type" "LooselyCoupled"
        Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "Value" "Deny"
        Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "InitialAppValue" "Unspecified"
    
        Write-Output "Disable location sensor"
        Mkdir -Force  "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
        Set-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "SensorPermissionState" 0
    
        Write-Output "Disable submission of Windows Defender findings (w/ elevated privileges)"
        Takeown-Registry("HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Defender\Spynet")
        Set-ItemProperty "HKLM:\Software\Microsoft\Windows Defender\Spynet" "SpyNetReporting" 0       #write-protected even after takeown ?!
        Set-ItemProperty "HKLM:\Software\Microsoft\Windows Defender\Spynet" "SubmitSamplesConsent" 0
    
        Write-Output "Do not share wifi networks"
        $user = New-Object System.Security.Principal.NTAccount($env:UserName)
        $sid = $user.Translate([System.Security.Principal.SecurityIdentifier]).value
        Mkdir -Force  ("HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\features\" + $sid)
        Set-ItemProperty ("HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\features\" + $sid) "FeatureStates" 0x33c
        Set-ItemProperty "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\features" "WiFiSenseCredShared" 0
        Set-ItemProperty "HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\features" "WiFiSenseOpen" 0
        
        #Creates a PSDrive to be able to access the 'HKCR' tree
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
            
        #Disables Windows Feedback Experience
        Write-Output "Disabling Windows Feedback Experience program"
        $Advertising = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
        If (Test-Path $Advertising) {
            Set-ItemProperty $Advertising -Name Enabled -Value 0 -Verbose
        }
            
        #Stops Cortana from being used as part of your Windows Search Function
        Write-Output "Stopping Cortana from being used as part of your Windows Search Function"
        $Search = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search'
        If (Test-Path $Search) {
            Set-ItemProperty $Search -Name AllowCortana -Value 0 -Verbose
        }
            
        #Stops the Windows Feedback Experience from sending anonymous data
        Write-Output "Stopping the Windows Feedback Experience program"
        $Period1 = 'HKCU:\Software\Microsoft\Siuf'
        $Period2 = 'HKCU:\Software\Microsoft\Siuf\Rules'
        $Period3 = 'HKCU:\Software\Microsoft\Siuf\Rules\PeriodInNanoSeconds'
        If (!(Test-Path $Period3)) { 
            mkdir $Period1 -ErrorAction SilentlyContinue
            mkdir $Period2 -ErrorAction SilentlyContinue
            mkdir $Period3 -ErrorAction SilentlyContinue
            New-ItemProperty $Period3 -Name PeriodInNanoSeconds -Value 0 -Verbose -ErrorAction SilentlyContinue
        }
                   
        Write-Output "Adding Registry key to prevent bloatware apps from returning"
        #Prevents bloatware applications from returning
        $registryPath = "HKLM:\Software\Policies\Microsoft\Windows\CloudContent"
        If (!(Test-Path $registryPath)) {
            Mkdir $registryPath -ErrorAction SilentlyContinue
            New-ItemProperty $registryPath -Name DisableWindowsConsumerFeatures -Value 1 -Verbose -ErrorAction SilentlyContinue
        }          
        
        Write-Output "Setting Mixed Reality Portal value to 0 so that you can uninstall it in Settings"
        $Holo = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic'    
        If (Test-Path $Holo) {
            Set-ItemProperty $Holo -Name FirstRunSucceeded -Value 0 -Verbose
        }
        
        #Disables live tiles
        Write-Output "Disabling live tiles"
        $Live = 'HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'    
        If (!(Test-Path $Live)) {
            mkdir $Live -ErrorAction SilentlyContinue     
            New-ItemProperty $Live -Name NoTileApplicationNotification -Value 1 -Verbose
        }
        
        #Turns off Data Collection via the AllowTelemtry key by changing it to 0
        Write-Output "Turning off Data Collection"
        $DataCollection = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection'    
        If (Test-Path $DataCollection) {
            Set-ItemProperty $DataCollection -Name AllowTelemetry -Value 0 -Verbose
        }
        
        #Disables People icon on Taskbar
        Write-Output "Disabling People icon on Taskbar"
        $People = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
        If (Test-Path $People) {
            Set-ItemProperty $People -Name PeopleBand -Value 0 -Verbose
        }
    
        #Disables suggestions on start menu
        Write-Output "Disabling suggestions on the Start Menu"
        $Suggestions = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'    
        If (Test-Path $Suggestions) {
            Set-ItemProperty $Suggestions -Name SystemPaneSuggestionsEnabled -Value 0 -Verbose
        }
        
        
        Write-Output "Removing CloudStore from registry if it exists"
        $CloudStore = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore'
        If (Test-Path $CloudStore) {
            Stop-Process -Force Explorer.exe -Force
            Remove-Item $CloudStore -Recurse -Force
            Start-Process Explorer.exe -Wait
        }
    
        #Loads the registry keys/values below into the NTUSER.DAT file which prevents the apps from redownloading. Credit to a60wattfish
        reg load HKU\Default_User C:\Users\Default\NTUSER.DAT
        Set-ItemProperty -Path Registry::HKU\Default_User\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SystemPaneSuggestionsEnabled -Value 0
        Set-ItemProperty -Path Registry::HKU\Default_User\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name PreInstalledAppsEnabled -Value 0
        Set-ItemProperty -Path Registry::HKU\Default_User\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name OemPreInstalledAppsEnabled -Value 0
        reg unload HKU\Default_User
        
        #Disables scheduled tasks that are considered unnecessary 
        Write-Output "Disabling scheduled tasks"
        #Get-ScheduledTask -TaskName XblGameSaveTaskLogon | Disable-ScheduledTask -ErrorAction SilentlyContinue
        #Get-ScheduledTask -TaskName XblGameSaveTask | Disable-ScheduledTask -ErrorAction SilentlyContinue
        Get-ScheduledTask -TaskName Consolidator | Disable-ScheduledTask -ErrorAction SilentlyContinue
        Get-ScheduledTask -TaskName UsbCeip | Disable-ScheduledTask -ErrorAction SilentlyContinue
        Get-ScheduledTask -TaskName DmClient | Disable-ScheduledTask -ErrorAction SilentlyContinue
        Get-ScheduledTask -TaskName DmClientOnScenarioDownload | Disable-ScheduledTask -ErrorAction SilentlyContinue
        
    }    
}
else {
    Write-Output "The Privacy Section Was Skipped..."
}

if ($imagecleanup -eq $true) {
    Write-Host "Cleaning Up Install Files and Cleanining Up the Image" -ForegroundColor Green
    Start-Job -Name "Image Cleanup" -ScriptBlock {
        #Delete "windows.old" folder
        #Cmd.exe /c Cleanmgr /sageset:65535 
        #Cmd.exe /c Cleanmgr /sagerun:65535
        Write-Verbose "Removing .tmp, .etl, .evtx, thumbcache*.db, *.log files not in use"
        Get-ChildItem -Path c:\ -Include *.tmp, *.dmp, *.etl, *.evtx, thumbcache*.db, *.log -File -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -ErrorAction SilentlyContinue
        #Delete "RetailDemo" content (if it exits)
        Write-Verbose "Removing Retail Demo content (if it exists)"
        Get-ChildItem -Path $env:ProgramData\Microsoft\Windows\RetailDemo\* -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -ErrorAction SilentlyContinue
        #Delete not in-use anything in the C:\Windows\Temp folder
        Write-Verbose "Removing all files not in use in $env:windir\TEMP"
        Remove-Item -Path $env:windir\Temp\* -Recurse -Force -ErrorAction SilentlyContinue
        #Clear out Windows Error Reporting (WER) report archive folders
        Write-Verbose "Cleaning up WER report archive"
        Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\Temp\* -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\ReportArchive\* -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\ReportQueue\* -Recurse -Force -ErrorAction SilentlyContinue
        #Delete not in-use anything in your $env:TEMP folder
        Write-Verbose "Removing files not in use in $env:TEMP directory"
        Remove-Item -Path $env:TEMP\* -Recurse -Force -ErrorAction SilentlyContinue
        #Clear out ALL visible Recycle Bins
        Write-Verbose "Clearing out ALL Recycle Bins"
        Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        #Clear out BranchCache cache
        Write-Verbose "Clearing BranchCache cache"
        Clear-BCCache -Force -ErrorAction SilentlyContinue
        #Clear volume backups (shadow copies)
        #vssadmin delete shadows /all /quiet
        #Empty trash bin
        Powershell -Command "$bin = (New-Object -ComObject Shell.Application).NameSpace(10);$bin.items() | ForEach { Write-Host "Deleting $($_.Name) from Recycle Bin"; Remove-Item $_.Path -Recurse -Force}"
        #Delete controversial default0 user
        net user defaultuser0 /delete 2>nul
        #Clear thumbnail cache
        Remove-Item -Force -Confirm:$false -Recurse $env:LocalAppData\Microsoft\Windows\Explorer\*.db
        #Clear Windows temp files
        Remove-Item -Force -Confirm:$false $env:localappdata\Temp\*
        Remove-Item -Force -Confirm:$false "$env:WINDIR\Temp"
        Remove-Item -Force -Confirm:$false "$env:TEMP"
        #Clear main telemetry file
        takeown /f "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" /r -Value y
        icacls "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" /grant administrators:F /t
        Write-Output"" > "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl"
        Write-Output Clear successful: "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl"
        #Clear Distributed Transaction Coordinator logs
        Remove-Item -Force -Confirm:$false  $env:SystemRoot\DtcInstall.log
        #Clear Optional Component Manager and COM+ components logs
        Remove-Item -Force -Confirm:$false $env:SystemRoot\comsetup.log
        #Clear Pending File Rename Operations logs
        Remove-Item -Force -Confirm:$false $env:SystemRoot\PFRO.log
        #Clear Windows Deployment Upgrade Process Logs
        Remove-Item -Force -Confirm:$false  $env:SystemRoot\setupact.log
        Remove-Item -Force -Confirm:$false $env:SystemRoot\setuperr.log
        #Clear Windows Setup Logs
        Remove-Item -Force -Confirm:$false $env:SystemRoot\setupapi.log
        Remove-Item -Force -Confirm:$false $env:SystemRoot\Panther\*
        Remove-Item -Force -Confirm:$false $env:SystemRoot\inf\setupapi.app.log
        Remove-Item -Force -Confirm:$false $env:SystemRoot\inf\setupapi.dev.log
        Remove-Item -Force -Confirm:$false $env:SystemRoot\inf\setupapi.offline.log
        #Clear Windows System Assessment Tool logs
        Remove-Item -Force -Confirm:$false $env:SystemRoot\Performance\WinSAT\winsat.log
        #Clear Password change events
        Remove-Item -Force -Confirm:$false $env:SystemRoot\debug\PASSWD.LOG
        #Clear user web cache database
        Remove-Item -Force -Confirm:$false $env:LocalAppData\Microsoft\Windows\WebCache\*.*
        #Clear system temp folder when noone is logged in
        Remove-Item -Force -Confirm:$false $env:SystemRoot\ServiceProfiles\LocalService\AppData\Local\Temp\*.*
        #Clear DISM (Deployment Image Servicing and Management) Logs
        Remove-Item -Force -Confirm:$false  $env:SystemRoot\Logs\CBS\CBS.log
        Remove-Item -Force -Confirm:$false  $env:SystemRoot\Logs\DISM\DISM.log
        #Clear Server-initiated Healing Events Logs
        Remove-Item -Force -Confirm:$false "$env:SystemRoot\Logs\SIH\*"
        #Common Language Runtime Logs
        Remove-Item -Force -Confirm:$false "$env:LocalAppData\Microsoft\CLR_v4.0\UsageTraces\*"
        Remove-Item -Force -Confirm:$false "$env:LocalAppData\Microsoft\CLR_v4.0_32\UsageTraces\*"
        #Network Setup Service Events Logs
        Remove-Item -Force -Confirm:$false "$env:SystemRoot\Logs\NetSetup\*"
        #Disk Cleanup tool (Cleanmgr.exe) Logs
        Remove-Item -Force -Confirm:$false "$env:SystemRoot\System32\LogFiles\setupcln\*"
        #Clear Windows update and SFC scan logs
        Remove-Item -Force -Confirm:$false $env:SystemRoot\Temp\CBS\*
        #Clear Windows Update Medic Service logs
        takeown /f $env:SystemRoot\Logs\waasmedic /r -Value y
        icacls $env:SystemRoot\Logs\waasmedic /grant administrators:F /t
        Remove-Item -Force -Confirm:$false $env:SystemRoot\Logs\waasmedic
        #Clear Cryptographic Services Traces
        Remove-Item -Force -Confirm:$false $env:SystemRoot\System32\catroot2\dberr.txt
        Remove-Item -Force -Confirm:$false $env:SystemRoot\System32\catroot2.log
        Remove-Item -Force -Confirm:$false $env:SystemRoot\System32\catroot2.jrs
        Remove-Item -Force -Confirm:$false $env:SystemRoot\System32\catroot2.edb
        Remove-Item -Force -Confirm:$false $env:SystemRoot\System32\catroot2.chk
        #Windows Update Events Logs
        Remove-Item -Force -Confirm:$false "$env:SystemRoot\Logs\SIH\*"
        #Windows Update Logs
        Remove-Item -Force -Confirm:$false "$env:SystemRoot\Traces\WindowsUpdate\*"
        #Clear Internet Explorer traces
        Remove-Item -Force -Confirm:$false "$env:LocalAppData\Microsoft\Windows\INetCache\IE\*"
        reg delete "HKCU\SOFTWARE\Microsoft\Internet Explorer\TypedURLs" /va /f
        reg delete "HKCU\SOFTWARE\Microsoft\Internet Explorer\TypedURLsTime" /va /f
        Remove-Item -Force -Confirm:$false "$env:LocalAppData\Microsoft\Internet Explorer"
        Remove-Item -Force -Confirm:$false "$env:APPDATA\Microsoft\Windows\Cookies"
        Remove-Item -Force -Confirm:$false "$env:USERPROFILE\Cookies"
        Remove-Item -Force -Confirm:$false "$env:USERPROFILE\Local Settings\Traces"
        Remove-Item -Force -Confirm:$false "$env:LocalAppData\Temporary Internet Files"
        Remove-Item -Force -Confirm:$false "$env:LocalAppData\Microsoft\Windows\Temporary Internet Files"
        Remove-Item -Force -Confirm:$false "$env:LocalAppData\Microsoft\Windows\INetCookies\PrivacIE"
        Remove-Item -Force -Confirm:$false "$env:LocalAppData\Microsoft\Feeds Cache"
        Remove-Item -Force -Confirm:$false "$env:LocalAppData\Microsoft\InternetExplorer\DOMStore"
        #Clear Google Chrome traces
        Remove-Item -Force -Confirm:$false "$env:LocalAppData\Google\Software Reporter Tool\*.log"
        Remove-Item -Force -Confirm:$false "$env:USERPROFILE\Local Settings\Application Data\Google\Chrome\User Data"
        Remove-Item -Force -Confirm:$false "$env:LocalAppData\Google\Chrome\User Data"
        Remove-Item -Force -Confirm:$false "$env:LocalAppData\Google\CrashReports\"
        Remove-Item -Force -Confirm:$false "$env:LocalAppData\Google\Chrome\User Data\Crashpad\reports\"
        #Clear Opera traces
        Remove-Item -Force -Confirm:$false "$env:USERPROFILE\AppData\Local\Opera\Opera"
        Remove-Item -Force -Confirm:$false "$env:APPDATA\Opera\Opera"
        Remove-Item -Force -Confirm:$false "$env:USERPROFILE\Local Settings\Application Data\Opera\Opera"
        #Clear Safari traces
        Remove-Item -Force -Confirm:$false "$env:USERPROFILE\AppData\Local\Apple Computer\Safari\Traces"
        Remove-Item -Force -Confirm:$false "$env:APPDATA\Apple Computer\Safari"
        Remove-Item -Force -Confirm:$false -Recurse "$env:USERPROFILE\AppData\Local\Apple Computer\Safari\Cache.db"
        Remove-Item -Force -Confirm:$false -Recurse "$env:USERPROFILE\AppData\Local\Apple Computer\Safari\WebpageIcons.db"
        Remove-Item -Force -Confirm:$false "$env:USERPROFILE\Local Settings\Application Data\Apple Computer\Safari\Traces"
        Remove-Item -Force -Confirm:$false -Recurse "$env:USERPROFILE\Local Settings\Application Data\Apple Computer\Safari\Cache.db"
        Remove-Item -Force -Confirm:$false -Recurse "$env:USERPROFILE\Local Settings\Application Data\Safari\WebpageIcons.db"
        #Clear Listary indexes
        Remove-Item -Force -Confirm:$false -Recurse $env:APPDATA\Listary\UserData > nul
        #Clear Java cache
        Remove-Item -Force -Confirm:$false "$env:APPDATA\Sun\Java\Deployment\cache"
        #Clear Flash traces
        Remove-Item -Force -Confirm:$false "$env:APPDATA\Macromedia\Flash Player"
        #Clear Steam dumps, logs and traces
        Remove-Item -Force -Confirm:$false %ProgramFiles(x86)%\Steam\Dumps
        Remove-Item -Force -Confirm:$false %ProgramFiles(x86)%\Steam\Traces
        Remove-Item -Force -Confirm:$false %ProgramFiles(x86)%\Steam\appcache\*.log
        #Clear Visual Studio telemetry and feedback data
        Remove-Item -Force -Confirm:$false "$env:APPDATA\vstelemetry" 2>nul
        Remove-Item -Force -Confirm:$false "$env:LocalAppData\Microsoft\VSApplicationInsights" 2>nul
        Remove-Item -Force -Confirm:$false "$env:ProgramData\Microsoft\VSApplicationInsights" 2>nul
        Remove-Item -Force -Confirm:$false "$env:TEMP\Microsoft\VSApplicationInsights" 2>nul
        Remove-Item -Force -Confirm:$false "$env:TEMP\VSFaultInfo" 2>nul
        Remove-Item -Force -Confirm:$false "$env:TEMP\VSFeedbackPerfWatsonData" 2>nul
        Remove-Item -Force -Confirm:$false "$env:TEMP\VSFeedbackVSRTCLogs" 2>nul
        Remove-Item -Force -Confirm:$false "$env:TEMP\VSRemoteControl" 2>nul
        Remove-Item -Force -Confirm:$false "$env:TEMP\VSTelem" 2>nul
        Remove-Item -Force -Confirm:$false "$env:TEMP\VSTelem.Out" 2>nul
        #Clear Dotnet CLI telemetry
        Remove-Item -Force -Confirm:$false "$env:USERPROFILE\.dotnet\TelemetryStorageService" 2>nul
        #Clear regedit last key
        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit" /va /f
        reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Regedit" /va /f
        #Clear regedit favorites
        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites" /va /f
        reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites" /va /f
        #Clear list of recent programs opened
        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU" /va /f
        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRULegacy" /va /f
        #Clear Adobe Media Browser MRU
        reg delete "HKCU\Software\Adobe\MediaBrowser\MRU" /va /f
        #Clear MSPaint MRU
        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Paint\Recent File List" /va /f
        reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Paint\Recent File List" /va /f
        #Clear Wordpad MRU
        reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Wordpad\Recent File List" /va /f
        #Clear Map Network Drive MRU MRU
        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU" /va /f
        reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU" /va /f
        #Clear Windows Search Assistant history
        reg delete "HKCU\Software\Microsoft\Search Assistant\ACMru" /va /f
        #Clear list of Recent Files Opened, by Filetype
        reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /va /f
        reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /va /f
        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU" /va /f
        #Clear windows media player recent files and urls
        reg delete "HKCU\Software\Microsoft\MediaPlayer\Player\RecentFileList" /va /f
        reg delete "HKCU\Software\Microsoft\MediaPlayer\Player\RecentURLList" /va /f
        reg delete "HKLM\SOFTWARE\Microsoft\MediaPlayer\Player\RecentFileList" /va /f
        reg delete "HKLM\SOFTWARE\Microsoft\MediaPlayer\Player\RecentURLList" /va /f
        #Clear Most Recent Application's Use of DirectX
        reg delete "HKCU\Software\Microsoft\Direct3D\MostRecentApplication" /va /f
        reg delete "HKLM\SOFTWARE\Microsoft\Direct3D\MostRecentApplication" /va /f
        #Clear Windows Run MRU & typedpaths
        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /va /f
        reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" /va /f
        #Clear recently accessed files
        Remove-Item -Force -Confirm:$false "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*"
        #Clear user pins
        Remove-Item -Force -Confirm:$false "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations\*"
        #Clear regedit last key
        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit" /va /f
        reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Regedit" /va /f
    }
}
else {
    Write-Output "The Image Cleanup Section Was Skipped..."
}

if ($diskcompression -eq $true) {
    Write-Host "Compressing Disk to Save Space" -ForegroundColor Green
    #Enable Disk Compression and Disable File Indexing
    Start-Job -Name "Enable Disk Compression and Disable File Indexing" -ScriptBlock {
        $DriveLetters = (Get-WmiObject -Class Win32_Volume).DriveLetter
        ForEach ($Drive in $DriveLetters) {
            If (-not ([string]::IsNullOrEmpty($Drive))) {
                $indexing = $Drive.IndexingEnabled
                #Write-Host "Enabling Disk Compression on the $Drive Drive"
                #Enable-NtfsCompression -Path "$Drive"\ -Recurse
                if ("$indexing" -eq $True) {
                    Write-Host "Disabling File Index on the $Drive Drive"
                    Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='$Drive'" | Set-WmiInstance -Arguments @{IndexingEnabled = $False } | Out-Null
                }
            }
        }
    }
}
else {
    Write-Output "The Disk Compression Section Was Skipped..."
}

if ($updatemanagement -eq $true) {
    Write-Host "Implementing the SoS Update Management Configurations" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\SoS\Update Management"
}
else {
    Write-Output "The Update Management Section Was Skipped..."
}

if ($sosbrowsers -eq $true) {
    Write-Host "Implementing the SoS Browser Configurations" -ForegroundColor Green
    Import-GPOs -gposdir ".\Files\GPOs\SoS\Browsers"
}
else {
    Write-Output "The Browsers Config Section Was Skipped..."
}

Write-Host "Checking Backgrounded Processes"; Get-Job

Write-Host "Performing Group Policy Update"
$timeoutSeconds = 180
$gpupdateJob = Start-Job -ScriptBlock { Gpupdate /force }
$gpupdateResult = Receive-Job -Job $gpupdateJob -Wait -Timeout $timeoutSeconds
if ($gpupdateResult -eq $null) {
    Write-Host "Group Policy Update timed out after $timeoutSeconds seconds."
} else {
    Write-Host "Group Policy Update completed."
}

Write-Warning "A reboot is required for all changes to take effect"

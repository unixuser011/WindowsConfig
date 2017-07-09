# Windows 10 Inital Setup configuration script
##

# DISCLAMER: This script is provided "as-is" and must be modified to fit your envrionment
# The original developer cannot be held accountable for your failure to read the fine print
##

# Ask for elevated permission
##
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Start-Process powershell.exe "-noProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

Write-Host
Write-Host "WARNING!!! Serious system instability can ocour if this script is interrupted" -ForegroundColor Black -BackgroundColor White
Write-Host "Please take this time to create a restore image of your system, so that if this script fails, you can restore to a fresh install" -ForegroundColor Black -BackgroundColor White
Write-Host
Write-Host "DISCLAMER: This script is provided 'as-is' and must be modified to fit your envrionment" -ForegroundColor Black -BackgroundColor White
Write-Host "The original developer cannot be held accountable for your failure to read the fine print" -ForegroundColor Black -BackgroundColor White
Write-Host "By pressing 'Enter' you accept these terms, If you do not agree, end this program" -ForegroundColor Black -BackgroundColor White
Write-Host "Press [Enter] to begin..." -ForegroundColor Black -BackgroundColor White
$key = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

Write-Host
Write-Host "Would you like to create a system restore point before continuing..."
$ReadHost = Read-Host " ( Y / N ) "
Switch ($ReadHost) {
    Y {Read-Host "Creating system restore point..."; Enable-ComputerRestore -Drive "C:\" -Confirm; wmic.exe /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "Restore point created before WindowsConfig", 100, 12}
    N {Read-Host "Continuing Script..."}
    Default {Read-Host "Continuing Scipt..."}
}

##
# Privicy Settings
##

Write-Host
Write-Host "##"
Write-Host "# Modifing Privicy Settings #"
Write-Host "##"
Write-Host

# Disable Telemetry
##
Write-Host "Disabling Telemetry"

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
If ((Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection")) {
     New-item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0

# Disable Wi-Fi Sense
##
Write-Host "Disabling WiFi Sense"

If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0

# Enable Windows SmartScreen Filter
##
Write-Host "Enabling Windows SmartScreen Filter"

Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "RequireAdmin"

# Raise UAC Level
##
Write-host "Rasing UAC Level"

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConcentPromptBehaviorAdmin" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConcentPromptBehaviorUser" -Type DWord -Value 3
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1

# Disable Bing Search in Start Menu
##
Write-Host "Disabling Bing Search in Start Menu"

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type Dword -Value 0

# Disable Start Menu Suggestions
##
Write-Host "Disabling Start Menu Suggestions"

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0

# Disable Location Tracking
##
Write-Host "Disabling Location Tracking"

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0

# Disable Feedback
##
Write-Host "Disabling Feedback"

If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0

# Disable Advertising ID
##
Write-Host "Disabling Advertising ID"

If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" | Out-Null
}
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0

# Disable Cortana
##
Write-Host "Disabling Cortana"

If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivicyPolicy" -Type DWord -Value 0
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -PropertyType DWord -Value 0 -Force

# Restrict Windows Update to Internet Download only
##
Write-Host "Restricting Windows Update to Internet Download only"

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 0
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Type DWord -Value 0

# Set Windows Update to Auto Download and Install (strictly for later on in script for downloading all updates, will be changed after
##
Write-Host "Setting Windows Update to auto"

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null
}
if (!(Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -PropertyType DWord -Value 4

# Remove AutoLogger and restrict directory
##
Write-Host "Removing AutoLogger and restrict directoy"

$autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
    Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
}
icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null

# Stop and disable Diagnostics Tracking
##
Write-Host "Disabling Diagnostics Tracking"

Stop-Service "DiagTrack"
Set-Service "DiagTrack" -StartupType Disabled

# Stop and disable WAP Push Service
##
Write-Host "Disabling WAP Push Service"

Stop-Service "dmwappushservice"
Set-Service "dmwappushservice" -StartupType Disabled

# Disable Microsoft Suggested Apps
##
Write-Host "Disabling Microsoft Suggested Apps"

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0

# Disable Windows Consumer Features
##
Write-Host "Disabling Windows Consumer Features"

If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -PropertyType DWord -Force

# Disable Windows Tips and Feedback
##
Write-Host "Disabling Windows Tips and feedback"

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Type DWord -Value 0

# Disable Windows Lockscreen Spotlight
##
#Write-host "Disabling Windows Lockscreen Spotlight"

#Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Type DWord -Value 0

# Enable Windows Powershell remoting without domain
##
Write-Host "Enabling Windows Powershell remoting without domain"

winrm quickconfig
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force

# Disable Windows GameDVR
##
Write-host "Disabling Windows GameDVR"

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0 -PropertyType DWord -Force
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -PropertyType DWord -Force

# Disable AutoPlay
##
Write-Host "Disabling AutoPlay"

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoPlayHandlers" -Name "DisableAutoPlay" -Type DWord -Value 1

# Disable AutoRun for all drives
##
Write-Host "Disabling AutoRun for all drives"

if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255

##
# Service Tasks
##

Write-Host
Write-Host "##"
Write-Host "# Modifing Service Tasks #"
Write-Host "##"
Write-Host

# Enable Firewall
##
Write-Host "Enabling Windows Firewall"

Set-NetFirewallProfile -Profile * -Enabled True

# Configure Windows Defender
##

Write-Host "Configuring Windows Defender"

Set-MpPreference -CheckForSignaturesBeforeRunningScan $True
Set-MpPreference -DisableArchiveScanning $False
Set-MpPreference -DisableBehaviorMonitoring $False
Set-MpPreference -DisableBlockAtFirstSeen $False
Set-MpPreference -DisableEmailScanning $False
Set-MpPreference -DisableIOAVProtection $False
Set-MpPreference -DisableIntrusionPreventionSystem $False
Set-MpPreference -DisableRealtimeMonitoring $False
Set-MpPreference -DisableRemovableDriveScanning $False
Set-MpPreference -DisableScriptScanning $False
Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $True
Set-MpPreference -DisableScanningNetworkFiles $True
Set-MpPreference -HighThreatDefaultAction Quarantine
Set-MpPreference -LowThreatDefaultAction Quarantine
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -ModerateThreatDefaultAction Quarantine
Set-MpPreference -PUAProtection Enabled
Set-MpPreference -RealTimeScanDirection Both
Set-MpPreference -ScanParameters QuickScan
Set-MpPreference -ScanScheduleDay Everyday
Set-MpPreference -SevereThreatDefaultAction Quarantine
Set-MpPreference -SignatureUpdateInterval 60
Set-MpPreference -SignatureFallbackOrder {MMPC | MicrosoftUpdateServer}
Set-MpPreference -SubmitSamplesConsent Always
Set-MpPreference -UnknownThreatDefaultAction Quarantine

Get-MpPreference >> C:\WindowsDefenderSettings.txt

# Disable Windows Update Automatic restart
##
Write-Host "Disabling Window Update Automatic restart"

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value 1

# Stop and disable Home Group services
##
Write-Host "Disabling Home Group services"

Stop-Service "HomeGroupListener"
Set-Service "HomeGroupListener" -StartupType Disabled
Stop-Service "HomeGroupProvider"
Set-Service "HomeGroupProvider" -StartupType Disabled

# Disable Lock Screen (Anniversary Update workaround)
##
Write-Host "Disabling Lock Screen (Anniversary Update workaround)"

If ([System.Environment]::OSVersion.Build -gt 14392) {
       $service = New-Object -com Schedule.Service
       $service.Connect()
       $task = $service.NewTask(0)
       $task.Settings.DisallowStartIfOnBatteries = $False
       $trigger = $task.Triggers.Create(9)
       $trigger = $task.Triggers.Create(11)
       $trigger.StateChange = 8
       $action = $task.Actions.Create(0)
       $action.Path = "reg.exe"
       $action.Arguments = "add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData /t REG_DWORD /v AllowLockScreen /d 0 /f"
       $service.GetFolder("\").RegisterTaskDevinition("Disable LockScreen", $task, 6, "NT AUTHORITY\SYSTEM", $null, 4) | Out-Null
}

##
# Remove Unwanted Applications
##

Write-Host
Write-Host "##"
Write-Host "# Removing Unwanted Applications #"
Write-Host "##"
Write-Host

# Remove OneDrive
##
Write-Host "Removing OneDrive"

Stop-Process -Name OneDrive -ErrorAction SilentlyContinue
Start-Sleep -s 3
$oneDrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
If (!(Test-Path $oneDrive)) {
    $oneDrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
}
Start-Process $oneDrive "/uninstall" -NoNewWindow -Wait
Start-Sleep -s 3
Stop-Process -Name Explorer -ErrorAction SilentlyContinue
Start-Sleep -s 3
Remove-Item "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item "$env:LOCAPAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item "$env:PROGRAMDATA\Microsoft\Microsoft Onedrive" -Force -Recurse -ErrorAction SilentlyContinue
If (Test-Path "$env:SYSTEMDRIVE\OneDriveTemp") {
    Remove-item "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
}
If (!(Test-Path "HKCR:")) {
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
}
Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue

# Remove OneDrive ads being displayed in Explorer (Creators Update)
##
Write-Host "Removing OneDrive ads being displayed in Explorer (Creators Update)"

Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ -name ShowSyncProviderNotifications -Value 0

# Remove Default bloatware
##
Write-Host "Removing default bloatware"

Write-Host "Removing BingWeather"
Get-AppxPackage -AllUsers -Name Microsoft.BingWeather | Remove-AppxPackage

Write-Host "Removing WindowsMaps"
Get-AppxPackage -AllUsers -Name Microsoft.WindowsMaps | Remove-AppxPackage

Write-Host "Removing OneConnect"
Get-AppxPackage -AllUsers -Name Microsoft.OneConnect | Remove-AppxPackage

Write-Host "Removing Messaging"
Get-AppxPackage -AllUsers -Name Microsoft.Messaging | Remove-AppxPackage

Write-Host "Removing 3DBuilder"
Get-AppxPackage -AllUsers -Name Microsoft.3DBuilder | Remove-AppxPackage

Write-Host "Removing WindowsFeedbackHub"
Get-AppxPackage -AllUsers -Name Microsoft.WindowsFeedbackHub | Remove-AppxPackage

Write-Host "Removing WindowsCamera"
Get-AppxPackage -AllUsers -Name Microsoft.WindowsCamera | Remove-AppxPackage

Write-Host "Removing GetStarted"
Get-AppxPackage -AllUsers -Name Microsoft.GetStarted | Remove-AppxPackage

Write-Host "Removing ZuneVideo"
Get-AppxPackage -AllUsers -Name Microsoft.ZuneVideo | Remove-AppxPackage

Write-Host "Removing Twitter"
Get-AppxPackage -AllUsers -Name *Twitter* | Remove-AppxPackage

Write-Host "Removing Netflix"
Get-AppxPackage -AllUsers -Name *Netflix* | Remove-AppxPackage

Write-Host "Removing People"
Get-AppxPackage -AllUsers -Name Microsoft.People | Remove-AppxPackage

Write-Host "Removing ZuneMusic"
Get-AppxPackage -AllUsers -Name Microsoft.ZuneMusic | Remove-AppxPackage

Write-Host "Removing SkypeApp"
Get-AppxPackage -AllUsers -Name *SkypeApp* | Remove-AppxPackage

Write-Host "Removing WindowsSoundRecorder"
Get-AppxPackage -AllUsers -Name Microsoft.WindowsSoundRecorder | Remove-AppxPackage

Write-Host "Removing MicrosoftStickyNotes"
Get-AppxPackage -AllUsers -Name Microsoft.MicrosoftStickyNotes | Remove-AppxPackage

Write-Host "Removing WindowsAlarms"
Get-AppxPackage -AllUsers -Name Microsft.WindowsAlarms | Remove-AppxPackage

Write-Host "Removing MicrosoftSolitaireCollection"
Get-AppxPackage -AllUsers -Name Microsoft.MicrosoftSolitaireCollection | Remove-AppxPackage

Write-host "Removing Facebook"
Get-AppxPackage -AllUsers -Name *Facebook* | Remove-AppxPackage

Write-host "Removing Minecraft"
Get-AppxPackage -AllUsers -Name *Minecraft* | Remove-AppxPackage

Write-Host "Removing CandyCrush"
Get-AppxPackage -AllUsers -Name King.com.CandyCrushSodaSaga | Remove-AppxPackage

Write-Host "Removing TuneInRadio"
Get-AppxPackage -AllUsers -Name TuneIn.TuneInRadio | Remove-AppxPackage

Write-Host "Removing PicsArt PhotoStudio"
Get-AppxPackage -AllUsers -Name 2FE3CB00.PicsArt-PhotoStudio | Remove-AppxPackage

Write-Host "Removing Xbox Apps"
Get-AppxPackage -AllUsers -Name Microsoft.XboxGameCallableUI | Remove-AppxPackage
Get-AppxPackage -AllUsers -Name Microsoft.XboxIdentityProvider | Remove-AppxPackage
Get-AppxPackage -AllUsers -Name Microsoft.XboxSpeechToTextOverlay | Remove-AppxPackage
Get-AppxPackage -AllUsers -Name Microsoft.XboxApp | Remove-AppxPackage

Write-Host "Removing OfficeHub"
Get-AppxPackage -AllUsers -Name Microsoft.MicrosoftOfficeHub | Remove-AppxPackage

Write-Host "Removing OneNote"
Get-AppxPackage -AllUsers -Name Microsoft.Office.OneNote | Remove-AppxPackage

Write-Host "Removing 3DViewer"
Get-AppxPackage -AllUsers -Name Microsoft.3DViewer | Remove-AppxPackage

# Remove New Microsoft Edge Button in IE
##
Write-Host "Removing 'Open in Edge' button in IE"

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "HideNewEdgeButton" -Value 1 -Type DWord -Force

# Disable SMBv1
##
Write-Host "Disabling SMBv1"

Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

##
# Windows Update and image service tasks
##

# Download latest Windows 10 Updates
##
Write-Host "Downloading latest Windows 10 Updates"

wuauclt.exe /ResetAuthorization /detectnow /updatenow
Start-Sleep -Seconds 600

# Set Windows Update to Notify for Download and Install
##
Write-Host "Setting Windows Update to Notify for Download and Install"

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value 2

# Dism online image base reset
##
Write-Host "Performing dism base reset"

dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase

# Dism online image repair
##
write-host "Performing dism image check and repair"

dism.exe /Online /Cleanup-Image /RestoreHealth

##
# Windows End-of-script tasks
##

Write-Host
Write-Host "##"
Write-Host "# End-of-script tasks #"
Write-Host "##"
Write-Host

# Enable boot menu
##
Write-Host "Enabling boot menu"

bcdedit --% /set {bootmgr} displaybootmenu true
bcdedit --% /set {bootmgr} timeout 7

# Restart
##

Write-Host "Script execution complete, Would you like to reboot now?"
$ReadHost = Read-Host " ( Y / N ) "
Switch ($ReadHost) {
    Y {Write-Host "Rebooting..."; Restart-Computer}
    N {Write-Host "Script End..." Exit}
    Default {Write-Host "Script End..." Exit}
}
########################################################################################################################################################
#                                                                                                                                                       #
#                      WindowsConfig.sp1                                                                                                                #
#                      (c) 2017, Darius Anderson, All rights reserved                                                                                   #
#          This program is provided "as-is" and must be modified for your envrionment                                                                   #
#          The orriginal designer cannon be held accontable for any issues that may arrise because of your failure to read the small print              #
#          NOTE: This program containes highly optional choices, some choices may not be aplicable for your envrionment                                 #
#          As such, it much be modified.                                                                                                                #
#                                                                                                                                                       #
#########################################################################################################################################################

# Contains code from /u/Synex's Windows10Debloater script, specifically, the removal of the mixed reality portal, removal of the people icon, and the unnecessary scheduled tasks

# Ask for elevated permission
##
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Start-Process powershell.exe "-noProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
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

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 -ErrorAction SilentlyContinue
If ((Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection")) {
     New-item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force -ErrorAction SilentlyContinue | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 -ErrorAction SilentlyContinue

# Disable Wi-Fi Sense
##
Write-Host "Disabling WiFi Sense"

If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force -ErrorAction SilentlyContinue | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0 -ErrorAction SilentlyContinue

# Enable Windows SmartScreen Filter
##
Write-Host "Enabling Windows SmartScreen Filter"

Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "RequireAdmin" -ErrorAction SilentlyContinue

# Raise UAC Level and admin approval mode
##
Write-host "Rasing UAC Level and enabling admin approval mode"

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConcentPromptBehaviorAdmin" -Type DWord -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConcentPromptBehaviorUser" -Type DWord -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableInstallerDetection" -Type DWord -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Type DWord -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtulization" -Type DWord -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ValidateAdminCodeSignatures" -Type DWord -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableSecureUAIPaths" -Type DWord -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -Type DWord -Value 1 -ErrorAction SilentlyContinue

# Disable Bing Search in Start Menu
##
Write-Host "Disabling Bing Search in Start Menu"

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type Dword -Value 0 -ErrorAction SilentlyContinue 

# Disable Start Menu Suggestions
##
Write-Host "Disabling Start Menu Suggestions"

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue

# Disable Pre-Installed Apps
##
Write-Host "Disabling and removing Pre-Installed/OEM apps"

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SlientInstalledAppsEnabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContentEnabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue
Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Force -ErrorAction SilentlyContinue

# Allowing uninstall of mixed reality portal
##
Write-Host "Allow uninstall of mixed reality portal"

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Holographic" -Name "FirstRunSucceeded" -Type DWord -Value 0 -ErrorAction SilentlyContinue

# Remove people icon on taskbar
##
Write-Host "Removing people icon on taskbar"

If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Force -ErrorAction SilentlyContinue | Out-Null
}
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0 -ErrorAction SilentlyContinue

# Disable Location Tracking
##
Write-Host "Disabling Location Tracking"

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0 -ErrorAction SilentlyContinue

# Disable Feedback
##
Write-Host "Disabling Feedback"

If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force -ErrorAction SilentlyContinue | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0 -ErrorAction SilentlyContinue

# Disable Advertising ID
##
Write-Host "Disabling Advertising ID"

If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -ErrorAction SilentlyContinue | Out-Null
}
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue

# Disable Cortana
##
Write-Host "Disabling Cortana"

If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force -ErrorAction SilentlyContinue | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivicyPolicy" -Type DWord -Value 0 -ErrorAction SilentlyContinue
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force -ErrorAction SilentlyContinue | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1 -ErrorAction SilentlyContinue
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force -ErrorAction SilentlyContinue | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0 -ErrorAction SilentlyContinue
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force -ErrorAction SilentlyContinue | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowContanaAboveLock" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -PropertyType DWord -Value 0 -Force -ErrorAction SilentlyContinue

# Restrict Windows Update to Internet Download only
##
Write-Host "Restricting Windows Update to Internet Download only"

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 0 -ErrorAction SilentlyContinue
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -ErrorAction SilentlyContinue | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Type DWord -Value 0 -ErrorAction SilentlyContinue

# Set Windows Update to Ask for permission to download and install updates
##
Write-Host "Setting Windows Update to Notify"

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue | Out-Null
}
if (!(Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -PropertyType DWord -Value 2 -ErrorAction SilentlyContinue

# Remove AutoLogger and restrict directory
##
Write-Host "Removing AutoLogger and restrict directoy"

$autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
    Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl" -ErrorAction SilentlyContinue
}
icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F -ErrorAction SilentlyContinue | Out-Null

# Stop and disable Diagnostics Tracking
##
Write-Host "Disabling Diagnostics Tracking"

Stop-Service "DiagTrack" -ErrorAction SilentlyContinue
Set-Service "DiagTrack" -StartupType Disabled -ErrorAction SilentlyContinue

# Stop and disable WAP Push Service
##
Write-Host "Disabling WAP Push Service"

Stop-Service "dmwappushservice" -ErrorAction SilentlyContinue
Set-Service "dmwappushservice" -StartupType Disabled -ErrorAction SilentlyContinue

# Disable Microsoft Suggested Apps
##
Write-Host "Disabling Microsoft Suggested Apps"

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue

# Disable Windows Consumer Features
##
Write-Host "Disabling Windows Consumer Features"

If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ErrorAction SilentlyContinue | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue

# Disable Windows Tips and Feedback
##
Write-Host "Disabling Windows Tips and feedback"

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue

# Disable Windows Lockscreen Spotlight
##
Write-host "Disabling Windows Lockscreen Spotlight"

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue

# Disable Windows GameDVR
##
Write-host "Disabling Windows GameDVR"

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -ErrorAction SilentlyContinue | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue

# Disable AutoPlay
##
Write-Host "Disabling AutoPlay"

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoPlayHandlers" -Name "DisableAutoPlay" -Type DWord -Value 1 -ErrorAction SilentlyContinue

# Disable AutoRun for all drives
##
Write-Host "Disabling AutoRun for all drives"

if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255 -ErrorAction SilentlyContinue

# Disable Windows Feedback Experience
##

Write-Host "Disabling Windows Feedback Experience"

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue

##
# Configure Windows Defender
##

# Note: this section isn't nessary for execution and thus, is purely optional, however if you are using Defender in your envrionmennt
# this section will configure it - the same as can be done in group policy

# Enable Block at first sight
Write-Host "Enabling Block at first sight"

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" | Out-Null
}
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableIOAVProtection" -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "DisableBlockAtFirstSeen" -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Value 2 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 3 -PropertyType DWord -Force

# Enable Behavior Monitoring
Write-Host "Enabling Behavior Monitoring"

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" | Out-Null
}
New-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 0 -PropertyType DWord -Force

# Enable On-Access Protection
Write-Host "Enabling On-Access Protection"

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 0 -PropertyType DWord -Force

# Enable Process Scanning
Write-Host "Enabling Process Scanning"

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 0 -PropertyType DWord -Force

# Enable bi-direction file scaninng
Write-Host "Enable bi-directional file scanning"

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "RealTimeScanDirection" -Value 0 -PropertyType DWord -Force

# Enable Network Protection
Write-Host "Enable Network Protection"

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -name "DisableIntrusionPreventionSystem" -Value 0 -PropertyType DWord -Force

# Disable Watson Events
Write-Host "Disable Watson Events"

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableGenericReports" -Value 1 -PropertyType DWord -Force

# Enable Check for updates before scan
Write-Host "Enable check for updates before scan"

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "CheckForSignaturesBeforeRunningScan" -Value 1 -PropertyType DWord -Force

# Enable Scan Archive files
Write-Host "Enable Scan Archive files"

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableArchiveScanning" -Value 0 -PropertyType DWord -Force

# Enable email scan
Write-Host "Enable Email Scan"

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableEmailScanning" -Value 0 -PropertyType DWord -Force

# Enable Heuristics
Write-Host "Enable Heuristics"

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DissbleHeuristics" -Value 0 -PropertyType DWord -Force

# Enable Packed executable scanning
Write-Host "Enable packed executable scanning"

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisablePackedExeScanning" -Value 0 -PropertyType DWord -Force

# Enable Removable Drive Scanning
Write-Host "Enable Removable Drive Scanning"

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableRemovableDriveScanning" -Value 0 -PropertyType DWord -Force

# Enable Reparse Point Scanning
Write-Host "Enable Reparse Point Scanning"

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableReparsePointScanning" -Value 0 -PropertyType DWord -Force

# Setting default scan to quick
Write-Host "Set default scan to quick"

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "ScanParameters" -Value 0 -PropertyType DWord -Force

# Setting update fallback order
Write-Host "Setting update fallback order"

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" -Name "FallbackOrder" -Value "MMPC|MicrosoftUpdateServer" -PropertyType String -Force

# Enable Real-item Definiton Updates
Write-Host "Enabling real-time definiton updates"

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" -Name "RealTimeSigatureDelivery" -Value 1 -PropertyType DWord -Force

# Setting update interval to every hour
Write-Host "setting update interval to every hour"

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" -Name "SignatureUpdateInterval" -Value 1 -PropertyType DWord -Force

# Setting antimalware service to normal priority startup
Write-Host "Setting antimalware service to normal priority startup"

New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "AllowFastServiceStartup" -Value 1 -PropertyType DWord -Force

# Allow service to remain running always
Write-Host "Allow service to remain running"

New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "ServiceKeepAlive" -Value 1 -PropertyType DWord -Force

# Enable Antivirus and antispyware
Write-Host "Enable AntiVirus and AntiSpyware"

New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus" -Value 0 -PropertyType DWord -Force

# Enable PUA detection
Write-Host "Enable PUA Detection"

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name "MpEnablePUS" -Value 1 -PropertyType DWord -Force

# Enable Exploit Guard Network Protection
Write-Host "Enable exploit guard network protection"

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard" | Out-Null
}
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -Value 1 -PropertyType DWord -Force

# Enable Controlled Folder Access
Write-Host "Enable Controlled Folder Access"

Set-MpPreference -EnableControlledFolderAccess Enabled

# Enable Early Launch AntiMalware
Write-Host "Enable early launch antimalware"

if (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" | Out-Null
}
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Name "DriverLoadPolicy" -Value 1 -PropertyType DWord -Force

# Set Threat action to quarantine
Write-Host "Set Threat action to quarantine"

Set-MpPreference -HighThreatDefaultAction Quarantine
Set-MpPreference -LowThreatDefaultAction Quarantine
Set-MpPreference -ModerateThreatDefaultAction Quarantine
Set-MpPreference -UnknownThreatDefaultAction Quarantine

# Enable Extended cloud check
Write-Host "Enable Extended Cloud Check"

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name "MpBafsExtendedTimeout" -Value 50 -PropertyType DWord -Force

# Set Defender Cloud Protection Level
# Note: This may detect legitimate files, however, you have the options to unblock or dispute this action

Write-Host "Setting Cloud Protection Level"

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name "MpCloudBlockLevel" -Value 4 -PropertyType DWord -Force

# Enable Defender ASR Rules

Write-Host "Enable Defender ASR Rules"

Set-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
Set-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
Set-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
Set-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
Set-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
Set-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
Set-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled

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

Set-NetFirewallProfile -Profile * -Enabled True -ErrorAction SilentlyContinue

# Disable Windows Update Automatic restart
##
Write-Host "Disabling Window Update Automatic restart"

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value 1 -ErrorAction SilentlyContinue

# Stop and disable Home Group services
##
Write-Host "Disabling Home Group services"
 
Stop-Service "HomeGroupListener" -ErrorAction SilentlyContinue
Set-Service "HomeGroupListener" -StartupType Disabled -ErrorAction SilentlyContinue
Stop-Service "HomeGroupProvider" -ErrorAction SilentlyContinue
Set-Service "HomeGroupProvider" -StartupType Disabled -ErrorAction SilentlyContinue

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

# Removing unnecessary scheduled tasks
##

Write-Host "Removing unnecessary scheduled tasks"

Get-ScheduledTask -TaskName XblGameSaveTaskLogon -ErrorAction SilentlyContinue | Disable-ScheduledTask
Get-ScheduledTask -TaskName XblGameSaveTask -ErrorAction SilentlyContinue | Disable-ScheduledTask
Get-ScheduledTask -TaskName Consolidator -ErrorAction SilentlyContinue | Disable-ScheduledTask
Get-ScheduledTask -TaskName UsbCeip -ErrorAction SilentlyContinue | Disable-ScheduledTask
Get-ScheduledTask -TaskName DmClient -ErrorAction SilentlyContinue | Disable-ScheduledTask
Get-ScheduledTask -TaskName DmClientOnScenarioDownload -ErrorAction SilentlyContinue | Disable-ScheduledTask

# Removing unnecessary registry keys
##

Write-Host "Removing unnecessary registry keys"

#Background Tasks
Remove-Item "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy" -Recurse -ErrorAction SilentlyContinue

#Windows File
Remove-Item "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0" -Recurse -ErrorAction SilentlyContinue

#Keys to delete if not deleted by RemoveAppXPackage/RemoveAppXProvisionedPackage
Remove-Item "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy" -Recurse -ErrorAction SilentlyContinue

#Sheduled Task
Remove-Item "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe" -Recurse -ErrorAction SilentlyContinue

#Windows Protocols
Remove-Item "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy" -Recurse -ErrorAction SilentlyContinue
Remove-Item "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy" -Recurse -ErrorAction SilentlyContinue

#Windows Share Targets
Remove-Item "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0" -Recurse -ErrorAction SilentlyContinue

##
# Remove Unwanted/unnecessary Windows Optional Features
##

# NOTE: Some services/Optional feaures thus listed may not be unwanted, but for this envrionment, they can be, at best problematic
# Example: optional feature 'print to PDF', may cause Windows Update to download printer drivers from 2006 
# for me, this causes problems when running the ZTIWindowsUpdate.wsf script - as this script will keep attempting to download updates and reboot
# the presence of this service (and others) may cause an infinite install/reboot loop

DISM /online /disable-feature /featurename:Microsoft-Windows-Printing-PrintToPDFServices-Package /norestart
DISM /online /disable-feature /featurename:Microsoft-Windows-Printing-XPSServices-Package /norestart
DISM /online /disable-feature /featurename:Xps-Foundation-Xps-Viewer /norestart

# List not complete, will add more if required

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

taskkill /f /im OneDrive.exe
Stop-Process -Name OneDrive -ErrorAction SilentlyContinue
Start-Sleep -s 3
$oneDrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
If (!(Test-Path $oneDrive)) {
    $oneDrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
}
Start-Process $oneDrive "/uninstall" -NoNewWindow -Wait -ErrorAction SilentlyContinue
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
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -ErrorAction SilentlyContinue | Out-Null
}
Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue

# Remove OneDrive ads being displayed in Explorer (Creators Update)
##
Write-Host "Removing OneDrive ads being displayed in Explorer (Creators Update)"

Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ -name ShowSyncProviderNotifications -Value 0 -ErrorAction SilentlyContinue

# Remove Default bloatware
##
Write-Host "Removing default bloatware"

Get-AppxPackage -AllUsers |
    Where-Object {$_.name -notlike "*Microsoft.FreshPaint*"} |
    Where-Object {$_.Name -notlike "*Microsoft.WindowsCalculator*"} |
    Where-Object {$_.Name -notlike "*Microsoft.WindowsStore*"} |
    Where-Object {$_.Name -notlike "*Microsoft.Windows.Photos*"} |
    Remove-AppxPackage -ErrorAction SilentlyContinue

Get-AppxProvisionedPackage -Online |
    Where-Object {$_.name -notlike "*Microsoft.FreshPaint*"} |
    Where-Object {$_.Name -notlike "*Microsoft.WindowsCalculator*"} |
    Where-Object {$_.Name -notlike "*Microsoft.WindowsStore*"} |
    Where-Object {$_.Name -notlike "*Microsoft.Windows.Photos*"} |
    Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    
# Remove New Microsoft Edge Button in IE
##
Write-Host "Removing 'Open in Edge' button in IE"

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "HideNewEdgeButton" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue

# Disable SMBv1
##
Write-Host "Disabling SMBv1"

Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue

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

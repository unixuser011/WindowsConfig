########################################################################################################################################################
#                                                                                                                                                       #
#                      WindowsConfig.sp1                                                                                                                #
#                      (c) 2017, Darius Anderson, All rights reserved                                                                                   #
#          This program is provided "as-is" and must be modified for your envrionment                                                                   #
#          The orriginal designer cannon be held accontable for any issues that may arrise because of your failure to read the small print              #
#          NOTE: This program containes highly optional choices, some choices may not be aplicable for your envrionment                                 #
#          As such, it much be modified. In a future release, I may add options or flags allowing users to decide what gets run, and what doesn't       #
#                                                                                                                                                       #
#########################################################################################################################################################

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

# Raise UAC Level
##
Write-host "Rasing UAC Level"

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConcentPromptBehaviorAdmin" -Type DWord -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConcentPromptBehaviorUser" -Type DWord -Value 3 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1 -ErrorAction SilentlyContinue

# Disable Bing Search in Start Menu
##
Write-Host "Disabling Bing Search in Start Menu"

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type Dword -Value 0 -ErrorAction SilentlyContinue

# Disable Start Menu Suggestions
##
Write-Host "Disabling Start Menu Suggestions"

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue

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
#Write-host "Disabling Windows Lockscreen Spotlight"

#Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Type DWord -Value 0 -ErrorAction SilentlyContinue

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

# Configure Windows Defender
##

Write-Host "Configuring Windows Defender"

Set-MpPreference -CheckForSignaturesBeforeRunningScan $True -ErrorAction SilentlyContinue
Set-MpPreference -DisableArchiveScanning $False -ErrorAction SilentlyContinue
Set-MpPreference -DisableBehaviorMonitoring $False -ErrorAction SilentlyContinue
Set-MpPreference -DisableBlockAtFirstSeen $False -ErrorAction SilentlyContinue
Set-MpPreference -DisableEmailScanning $False -ErrorAction SilentlyContinue
Set-MpPreference -DisableIOAVProtection $False -ErrorAction SilentlyContinue
Set-MpPreference -DisableIntrusionPreventionSystem $False -ErrorAction SilentlyContinue
Set-MpPreference -DisableRealtimeMonitoring $False -ErrorAction SilentlyContinue
Set-MpPreference -DisableRemovableDriveScanning $False -ErrorAction SilentlyContinue
Set-MpPreference -DisableScriptScanning $False -ErrorAction SilentlyContinue
Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $True -ErrorAction SilentlyContinue
Set-MpPreference -DisableScanningNetworkFiles $True -ErrorAction SilentlyContinue
Set-MpPreference -HighThreatDefaultAction Quarantine -ErrorAction SilentlyContinue
Set-MpPreference -LowThreatDefaultAction Quarantine -ErrorAction SilentlyContinue
Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
Set-MpPreference -ModerateThreatDefaultAction Quarantine -ErrorAction SilentlyContinue
Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
Set-MpPreference -RealTimeScanDirection Both -ErrorAction SilentlyContinue
Set-MpPreference -ScanParameters QuickScan -ErrorAction SilentlyContinue
Set-MpPreference -ScanScheduleDay Everyday -ErrorAction SilentlyContinue
Set-MpPreference -SevereThreatDefaultAction Quarantine -ErrorAction SilentlyContinue
Set-MpPreference -SignatureUpdateInterval 60 -ErrorAction SilentlyContinue
Set-MpPreference -SignatureFallbackOrder {MMPC | MicrosoftUpdateServer} -ErrorAction SilentlyContinue
Set-MpPreference -SubmitSamplesConsent Always -ErrorAction SilentlyContinue
Set-MpPreference -UnknownThreatDefaultAction Quarantine -ErrorAction SilentlyContinue
Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
Set-MpPreference -ControlledFolderAccessAllowedApplications "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ErrorAction SilentlyContinue
Set-MpPreference -ControlledFolderAccessAllowedApplications "C:\Windows\System32\WindowsPowershell\v1.0\powershell_ise.exe" -ErrorAction SilentlyContinue

Get-MpPreference >> C:\WindowsDefenderSettings.txt

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
Stop-Process -Name OneDrive -ErrorAction SilentlyContinue -ErrorAction SilentlyContinue
Start-Sleep -s 3
$oneDrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
If (!(Test-Path $oneDrive)) {
    $oneDrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
}
Start-Process $oneDrive "/uninstall" -NoNewWindow -Wait -ErrorAction SilentlyContinue
Start-Sleep -s 3
Stop-Process -Name Explorer -ErrorAction SilentlyContinue -ErrorAction SilentlyContinue
Start-Sleep -s 3
Remove-Item "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue -ErrorAction SilentlyContinue
Remove-Item "$env:LOCAPAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue -ErrorAction SilentlyContinue
Remove-Item "$env:PROGRAMDATA\Microsoft\Microsoft Onedrive" -Force -Recurse -ErrorAction SilentlyContinue -ErrorAction SilentlyContinue
If (Test-Path "$env:SYSTEMDRIVE\OneDriveTemp") {
    Remove-item "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue -ErrorAction SilentlyContinue
}
If (!(Test-Path "HKCR:")) {
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -ErrorAction SilentlyContinue | Out-Null
}
Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue -ErrorAction SilentlyContinue
Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue -ErrorAction SilentlyContinue

# Remove OneDrive ads being displayed in Explorer (Creators Update)
##
Write-Host "Removing OneDrive ads being displayed in Explorer (Creators Update)"

Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ -name ShowSyncProviderNotifications -Value 0 -ErrorAction SilentlyContinue

# Remove Default bloatware
##
Write-Host "Removing default bloatware"

Write-Host "Removing BingWeather"
Get-AppxPackage -AllUsers -Name Microsoft.BingWeather -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxProvisionedPackage -online | where-object {$_.packagename -like "*Microsoft.BingWeather*"} -ErrorAction SilentlyContinue | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue

Write-Host "Removing WindowsMaps"
Get-AppxPackage -AllUsers -Name Microsoft.WindowsMaps -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -like "*Microsoft.WindowsMaps*"} -ErrorAction SilentlyContinue | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue

Write-Host "Removing OneConnect"
Get-AppxPackage -AllUsers -Name Microsoft.OneConnect -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue
get-appxprovisionedpackage -online | where-object {$_.packagename -like "*Microsoft.OneConnect*"} -ErrorAction SilentlyContinue | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue

Write-Host "Removing Messaging"
Get-AppxPackage -AllUsers -Name Microsoft.Messaging -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue
get-appxprovisionedpackage -online | where-object {$_.packagename -like "*Microsoft.Messaging*"} -ErrorAction SilentlyContinue | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue

Write-Host "Removing 3DBuilder"
Get-AppxPackage -AllUsers -Name Microsoft.3DBuilder -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue
get-appxprovisionedpackage -online | where-object {$_.packagename -like "*Microsoft.3DBuilder*"} -ErrorAction SilentlyContinue | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue

Write-Host "Removing WindowsFeedbackHub"
Get-AppxPackage -AllUsers -Name Microsoft.WindowsFeedbackHub | Remove-AppxPackage -ErrorAction SilentlyContinue
get-appxprovisionedpackage -online | where-object {$_.packagename -like "*Microsoft.WindowsFeedbackHub*"} -ErrorAction SilentlyContinue | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue

Write-Host "Removing WindowsCamera"
Get-AppxPackage -AllUsers -Name Microsoft.WindowsCamera | Remove-AppxPackage -ErrorAction SilentlyContinue
get-appxprovisionedpackage -online | where-object {$_.packagename -like "*Microsoft.WindowsCamera*"} -ErrorAction SilentlyContinue | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue

Write-Host "Removing GetStarted"
Get-AppxPackage -AllUsers -Name Microsoft.GetStarted | Remove-AppxPackage -ErrorAction SilentlyContinue
get-appxprovisionedpackage -online | where-object {$_.packagename -like "*Microsoft.GetStarted*"} -ErrorAction SilentlyContinue | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue

Write-Host "Removing ZuneVideo"
Get-AppxPackage -AllUsers -Name Microsoft.ZuneVideo | Remove-AppxPackage -ErrorAction SilentlyContinue
get-appxprovisionedpackage -online | where-object {$_.packagename -like "*Microsoft.ZuneVideo*"} -ErrorAction SilentlyContinue | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue

Write-Host "Removing Twitter"
Get-AppxPackage -AllUsers -Name *Twitter* | Remove-AppxPackage -ErrorAction SilentlyContinue
get-appxprovisionedpackage -online | where-object {$_.packagename -like "*Twitter*"} -ErrorAction SilentlyContinue | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue

Write-Host "Removing Netflix"
Get-AppxPackage -AllUsers -Name *Netflix* | Remove-AppxPackage -ErrorAction SilentlyContinue
get-appxprovisionedpackage -online | where-object {$_.packagename -like "*Netflix*"} -ErrorAction SilentlyContinue | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue

Write-Host "Removing People"
Get-AppxPackage -AllUsers -Name Microsoft.People | Remove-AppxPackage -ErrorAction SilentlyContinue
get-appxprovisionedpackage -online | where-object {$_.packagename -like "*Microsoft.People*"} -ErrorAction SilentlyContinue | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue

Write-Host "Removing ZuneMusic"
Get-AppxPackage -AllUsers -Name Microsoft.ZuneMusic | Remove-AppxPackage -ErrorAction SilentlyContinue
get-appxprovisionedpackage -online | where-object {$_.packagename -like "*Microsoft.ZuneMusic*"} -ErrorAction SilentlyContinue | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue

Write-Host "Removing SkypeApp"
Get-AppxPackage -AllUsers -Name *SkypeApp* | Remove-AppxPackage -ErrorAction SilentlyContinue
get-appxprovisionedpackage -online | where-object {$_.packagename -like "*SkypeApp*"} -ErrorAction SilentlyContinue | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue

Write-Host "Removing WindowsSoundRecorder"
Get-AppxPackage -AllUsers -Name Microsoft.WindowsSoundRecorder | Remove-AppxPackage -ErrorAction SilentlyContinue
get-appxprovisionedpackage -online | where-object {$_.packagename -like "*Microsoft.WindowsSoundRecorder*"} -ErrorAction SilentlyContinue | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue

Write-Host "Removing MicrosoftStickyNotes"
Get-AppxPackage -AllUsers -Name Microsoft.MicrosoftStickyNotes | Remove-AppxPackage -ErrorAction SilentlyContinue
get-appxprovisionedpackage -online | where-object {$_.packagename -like "*Microsoft.MicrosoftStickyNotes*"} -ErrorAction SilentlyContinue | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue

Write-Host "Removing WindowsAlarms"
Get-AppxPackage -AllUsers -Name Microsft.WindowsAlarms | Remove-AppxPackage -ErrorAction SilentlyContinue
get-appxprovisionedpackage -online | where-object {$_.packagename -like "*Microsoft.WindowsAlarms*"} | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue

Write-Host "Removing MicrosoftSolitaireCollection"
Get-AppxPackage -AllUsers -Name Microsoft.MicrosoftSolitaireCollection | Remove-AppxPackage -ErrorAction SilentlyContinue
get-appxprovisionedpackage -online | where-object {$_.packagename -like "*Microsoft.MicrosoftSolitaireCollection*"} | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue

Write-host "Removing Facebook"
Get-AppxPackage -AllUsers -Name *Facebook* | Remove-AppxPackage -ErrorAction SilentlyContinue
get-appxprovisionedpackage -online | where-object {$_.packagename -like "*Facebook*"} -ErrorAction SilentlyContinue | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue

Write-host "Removing Minecraft"
Get-AppxPackage -AllUsers -Name *Minecraft* | Remove-AppxPackage -ErrorAction SilentlyContinue
get-appxprovisionedpackage -online | where-object {$_.packagename -like "*Minecraft*"} -ErrorAction SilentlyContinue | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue

Write-Host "Removing CandyCrush"
Get-AppxPackage -AllUsers -Name King.com.CandyCrushSodaSaga | Remove-AppxPackage -ErrorAction SilentlyContinue
get-appxprovisionedpackage -online | where-object {$_.packagename -like "*King.com.CandyCrushSodaSaga*"} -ErrorAction SilentlyContinue | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue

Write-Host "Removing TuneInRadio"
Get-AppxPackage -AllUsers -Name TuneIn.TuneInRadio | Remove-AppxPackage -ErrorAction SilentlyContinue
get-appxprovisionedpackage -online | where-object {$_.packagename -like "*TuneIn.TuneInRadio*"} -ErrorAction SilentlyContinue | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue

Write-Host "Removing PicsArt PhotoStudio"
Get-AppxPackage -AllUsers -Name 2FE3CB00.PicsArt-PhotoStudio | Remove-AppxPackage -ErrorAction SilentlyContinue
get-appxprovisionedpackage -online | where-object {$_.packagename -like "*2FE3CB00.PicsArt-PhotoStudio*"} -ErrorAction SilentlyContinue | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue

Write-Host "Removing Xbox Apps"
Get-AppxPackage -AllUsers -Name Microsoft.XboxIdentityProvider | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxPackage -AllUsers -Name Microsoft.XboxSpeechToTextOverlay | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxPackage -AllUsers -Name Microsoft.XboxApp | Remove-AppxPackage -ErrorAction SilentlyContinue
get-appxprovisionedpackage -online | where-object {$_.packagename -like "*Microsoft.XboxIdentityProvider*"} -ErrorAction SilentlyContinue | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue
get-appxprovisionedpackage -online | where-object {$_.packagename -like "*Microsoft.XboxSpeechToTextOverlay*"} -ErrorAction SilentlyContinue | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue
get-appxprovisionedpackage -online | where-object {$_.packagename -like "*Microsoft.XboxApp*"} -ErrorAction SilentlyContinue | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue

Write-Host "Removing OfficeHub"
Get-AppxPackage -AllUsers -Name Microsoft.MicrosoftOfficeHub | Remove-AppxPackage -ErrorAction SilentlyContinue
get-appxprovisionedpackage -online | where-object {$_.packagename -like "*Microsoft.MicrosoftOfficeHub*"} | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue

Write-Host "Removing OneNote"
Get-AppxPackage -AllUsers -Name Microsoft.Office.OneNote | Remove-AppxPackage -ErrorAction SilentlyContinue
get-appxprovisionedpackage -online | where-object {$_.packagename -like "*Microsoft.Office.OneNote*"} | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue

Write-Host "Removing 3DViewer"
Get-AppxPackage -AllUsers -Name Microsoft.3DViewer | Remove-AppxPackage -ErrorAction SilentlyContinue
get-appxprovisionedpackage -online | where-object {$_.packagename -like "*Microsoft.3DViewer*"} | Remove-appxprovisionedpackage -online -ErrorAction SilentlyContinue

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

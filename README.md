# WindowsConfig
PowerShell configuration script for post-install

WindowsConfig is a powershell script for post-install configuration of a system running Windows 10 
Anniversary update or above, this script will, among other things: 

Modifiy the system's privicy settings to ensure maximum security and privicy, these include:
disabling telemetry
disabling Wi-Fi Sence
Enabling the Windows SmartScreen filter
Increase the UAC to it's highest level
Disable the feedback and advertising ID
Disable Cortana
Disable and remove the auto-logger
Disable the Windows consumer features

Modify the system's security settings to ensure maximum system security, these include:
Enabling the system firewall
Configure Windows Defender (saves settings to: C:\WindowsDefenderSettings.txt)
Disables Windows Automatic update restart
Removes system bloatware and OneDrive (removes pre-installed apps also, in next release, will also remove apps
created during new profile creation)

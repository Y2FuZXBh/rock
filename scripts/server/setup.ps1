# Server - Install Script

# install & run windows update
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Confirm:$false
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name ("PSWindowsUpdate", "DockerMsftProvider") -Confirm:$false
Set-PSRepository -Name PSGallery -InstallationPolicy Untrusted
Import-Module -Name PSWindowsUpdate -Function Get-WUInstall -Force
Get-WUInstall –MicrosoftUpdate –AcceptAll

# install docker
Install-Package -Name docker -ProviderName DockerMsftProvider -Update -Confirm:$false
Enable-WindowsOptionalFeature -Online -FeatureName Containers -NoRestart

# add windows reboot check here

# chocolatey
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
(wget -UseBasicParsing https://community.chocolatey.org/install.ps1).content | iex

# circleci
choco install circleci-cli -y

<<<<<<< HEAD
# add windows reboot check here
=======
### Outside of VMWare - You Can Use Linux Subsystem > Docker > Linux SQL Image (Offical)
## IMPORTANT: Linux Subsystem /w No Default Distribution will Brake CircleCI Pipeline!
#Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart
#Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
#wsl.exe --install

Restart-Computer -Force
>>>>>>> dev

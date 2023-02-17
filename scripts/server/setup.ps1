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
Enable-WindowsOptionalFeature -Online -FeatureName Containers -Confirm:$false

# add windows reboot check here
#Restart-Computer -Force

# chocolatey
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
wget -UseBasicParsing https://community.chocolatey.org/install.ps1 | iex

# Server - Setup Script
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Confirm:$false
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted 
Install-Module -Name ("PSWindowsUpdate", "DockerMsftProvider") -Confirm:$false
Set-PSRepository -Name PSGallery -InstallationPolicy Untrusted
Install-Package -Name docker -ProviderName DockerMsftProvider -Confirm:$false
Import-Module -Name PSWindowsUpdate -Function Get-WUInstall
Enable-WindowsOptionalFeature -Online -FeatureName Containers -Confirm:$false
Get-WUInstall –MicrosoftUpdate –AcceptAll
#Restart-Computer -Force

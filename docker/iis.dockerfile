FROM mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2022

LABEL maintainer "Y2FuZXBh"

EXPOSE 80
EXPOSE 443

SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

# Requirements
RUN Add-WindowsFeature Web-Asp-Net45; \
    Add-WindowsFeature NET-Framework-45-ASPNET; \
    Add-WindowsFeature NET-Framework-Features; \
    Set-Service -Name wuauserv -StartupType Manual; \
    Start-Service wuauserv

# IIS
RUN Import-Module WebAdministration; \
    Set-ItemProperty IIS:\AppPools\DefaultAppPool -name processModel.identityType -value 0

# Application
COPY app/RockWeb /inetpub/wwwroot

# Cert
RUN $localhostCert = New-SelfSignedCertificate -Subject 'localhost' -DnsName "localhost" -CertStoreLocation "cert:\LocalMachine\My"; \
    #Assign Web binding to Default Web Site for port 443
    New-WebBinding -Name 'Default Web Site' -HostHeader "Rock" -IP "*" -Port "443" -Protocol "https" -SslFlags "1"; \
    #Connect the new cert to the web binding
    $bind = Get-WebBinding -Name 'Default Web Site' -Protocol "https"; \
    $bind.AddSslCertificate($localhostCert.GetCertHashString(), 'my')


WORKDIR /inetpub/wwwroot
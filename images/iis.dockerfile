FROM mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2022

LABEL maintainer "testing"

# Requirements
RUN powershell -Command \
    Add-WindowsFeature Web-Asp-Net45; \
    Add-WindowsFeature NET-Framework-45-ASPNET; \
    Add-WindowsFeature NET-Framework-Features; \
    Set-Service -Name wuauserv -StartupType Manual; \
    Start-Service wuauserv

# IIS
RUN powershell -Command \
    Import-Module WebAdministration; \
    Set-ItemProperty IIS:\AppPools\DefaultAppPool -name processModel.identityType -value 0

# Application
RUN powershell -Command \
    # demo files - https://github.com/crdschurch/rock-docker-public
    Invoke-WebRequest -UseBasicParsing "https://raw.githubusercontent.com/crdschurch/rock-docker-public/main/Start.aspx" -OutFile "c:\inetpub\wwwroot\Start.aspx"; \
    Invoke-WebRequest -UseBasicParsing "https://raw.githubusercontent.com/crdschurch/rock-docker-public/main/web.config" -OutFile "c:\inetpub\wwwroot\web.config"

# Cert
RUN powershell -Command \
    #Create a new localhost cert and save the thumbprint in a hash for future steps
    $localhostCert = New-SelfSignedCertificate -Subject 'localhost' -DnsName "localhost" -CertStoreLocation "cert:\LocalMachine\My"; \
    #Assign Web binding to Default Web Site for port 443
    New-WebBinding -Name 'Default Web Site' -HostHeader "Rock" -IP "*" -Port "443" -Protocol "https" -SslFlags "1"; \
    #Connect the new cert to the web binding
    $bind = Get-WebBinding -Name 'Default Web Site' -Protocol "https"; \
    $bind.AddSslCertificate($localhostCert.GetCertHashString(), 'my')


WORKDIR /inetpub/wwwroot

COPY ./RockWeb /inetpub/wwwroot

EXPOSE 80
EXPOSE 443
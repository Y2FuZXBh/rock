FROM mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2022

LABEL maintainer "Y2FuZXBh"

ENV SQL_IP="0.0.0.0"
ENV SQL_PORT="1433"
ENV SQL_PASSWORD="P@ssW0rd1234"

EXPOSE 80
EXPOSE 443

SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

# Requirements
RUN Add-WindowsFeature Web-Asp-Net45; \
    Add-WindowsFeature NET-Framework-45-ASPNET; \
    Add-WindowsFeature NET-Framework-Features; \
    Set-Service -Name wuauserv -StartupType Manual; \
    Start-Service wuauserv

# Application
COPY docker/scripts/iis.ps1 .
COPY app/RockWeb /inetpub/wwwroot

# Setup
RUN & .\iis.ps1

WORKDIR /inetpub/wwwroot
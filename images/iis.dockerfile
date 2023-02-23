FROM mcr.microsoft.com/windows/servercore:ltsc2022

#Configure IIS and .NET in container 
RUN powershell -Command \
    Add-WindowsFeature Web-Server; \
    Add-WindowsFeature Web-Asp-Net45; \
    Add-WindowsFeature NET-Framework-45-ASPNET; \
    Add-WindowsFeature NET-Framework-Features; \
    Set-Service -Name wuauserv -StartupType Manual; \
    Start-Service wuauserv; \
    Import-Module WebAdministration; \
    Set-ItemProperty IIS:\AppPools\DefaultAppPool -name processModel.identityType -value 0; \
    Invoke-WebRequest -UseBasicParsing "https://dotnetbinaries.blob.core.windows.net/servicemonitor/2.0.1.10/ServiceMonitor.exe" -OutFile "C:\ServiceMonitor.exe"

WORKDIR /inetpub/wwwroot

EXPOSE 80
EXPOSE 443

# Copy Site Files
#COPY . .

ENTRYPOINT ["C:\\ServiceMonitor.exe", "w3svc"]
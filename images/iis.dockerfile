FROM mcr.microsoft.com/windows/servercore:ltsc2022

#Configure IIS and .NET in container 
RUN powershell -Command `\
    Add-WindowsFeature -Name ([Microsoft.Windows.ServerManager.Commands.Feature[]]("Web-Server", "Web-Asp-Net45", "NET-Framework-45-ASPNET", "NET-Framework-Features")); `\
    Set-Service -Name wuauserv -StartupType Manual; `\
    Start-Service wuauserv; `\
    Import-Module WebAdministration; `\
    Set-ItemProperty IIS:\AppPools\DefaultAppPool -name processModel.identityType -value 0; `\
    Invoke-WebRequest -UseBasicParsing -Uri "https://dotnetbinaries.blob.core.windows.net/servicemonitor/2.0.1.10/ServiceMonitor.exe" -OutFile "C:\ServiceMonitor.exe"

WORKDIR /inetpub/wwwroot

EXPOSE 80
EXPOSE 443

# Copy Site Files
#COPY . .

ENTRYPOINT ["C:\\ServiceMonitor.exe", "w3svc"]
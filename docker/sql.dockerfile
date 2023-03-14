FROM mcr.microsoft.com/windows/servercore:ltsc2022

LABEL maintainer "Y2FuZXBh"

ENV SQL_PASSWORD="[NULL]"

EXPOSE 1433

SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

WORKDIR /

RUN Invoke-WebRequest 'https://download.microsoft.com/download/3/8/d/38de7036-2433-4207-8eae-06e247e17b25/SQLEXPR_x64_ENU.exe' -OutFile sqlexpress.exe

COPY docker/scripts/express.ps1 .
COPY docker/scripts/sql.ps1 .

RUN & .\express.ps1 -SQL_PASSWD $env:SQL_PASSWD; \
        Remove-Item express.ps1 ; \
        gc (Get-PSReadlineOption).HistorySavePath

USER sqlexpress

CMD .\sql.ps1 -Verbose

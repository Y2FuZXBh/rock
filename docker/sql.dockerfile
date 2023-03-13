FROM mcr.microsoft.com/windows/servercore:ltsc2022

LABEL maintainer "Y2FuZXBh"

ENV attach_dbs="[]"
EXPOSE 1433

SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

WORKDIR /

COPY scripts/express.ps1 .
COPY scripts/sql.ps1 .

RUN & .\sql.ps1 ; \
        Remove-Item sql.ps1 ; \
        gc (Get-PSReadlineOption).HistorySavePath

USER sqlexpress

CMD .\sql.ps1 -attach_dbs \"$env:attach_dbs\" -Verbose

FROM mcr.microsoft.com/windows/servercore:ltsc2022

LABEL maintainer "Y2FuZXBh"

ENV attach_dbs="[]"
EXPOSE 1433

SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

WORKDIR /

COPY scripts/ .

RUN & .\express.ps1 -Wait ; \
        Remove-Item express.ps1 ; \
        gc (Get-PSReadlineOption).HistorySavePath

USER sqlexpress

CMD .\start.ps1 -attach_dbs \"$env:attach_dbs\" -Verbose

FROM mcr.microsoft.com/windows/servercore:ltsc2022

LABEL maintainer "testing"

ENV attach_dbs="[]"

SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

WORKDIR /

COPY sql-express.ps1 .

RUN & .\sql-express.ps1 -Wait ; \
	Remove-Item sql-express.ps1 -Force

RUN stop-service MSSQL`$SQLEXPRESS ; \
        set-itemproperty -path 'HKLM:\software\microsoft\microsoft sql server\mssql16.SQLEXPRESS\mssqlserver\supersocketnetlib\tcp\ipall' -name tcpdynamicports -value '' ; \
        set-itemproperty -path 'HKLM:\software\microsoft\microsoft sql server\mssql16.SQLEXPRESS\mssqlserver\supersocketnetlib\tcp\ipall' -name tcpport -value 1433 ; \
        set-itemproperty -path 'HKLM:\software\microsoft\microsoft sql server\mssql16.SQLEXPRESS\mssqlserver\' -name LoginMode -value 2 ;

EXPOSE 1433

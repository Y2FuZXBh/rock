param(
    [Parameter(Mandatory = $false)]
    [string]$SQL_IP,
    [Parameter(Mandatory = $false)]
    [string]$SQL_Port,
    [Parameter(Mandatory = $false)]
    [string]$SQL_PASSWD
)

Import-Module WebAdministration

# ConnectionStrings
@"
<?xml version="1.0"?>
<connectionStrings>
	<add
	  name="RockContext"
	  connectionString="
	    Data Source=$SQL_IP\$SQL_Port;
        Initial Catalog=bccrock;
        Network Library=DBMSSOCN;
        User Id=sqlexpress;
        password=$SQL_PASSWD;
        Trusted_Connection=True;
        MultipleActiveResultSets=true"
	    providerName="System.Data.SqlClient"/>
</connectionStrings>
"@ | Out-File c:\inetpub\wwwroot\web.ConnectionStrings.config -Force

# IIS Config
Set-ItemProperty IIS:\AppPools\DefaultAppPool -name processModel.identityType -value 0

# SSL Cert
$localhostCert = New-SelfSignedCertificate -Subject 'localhost' -DnsName "localhost" -CertStoreLocation "cert:\LocalMachine\My"; \
#Assign Web binding to Default Web Site for port 443
New-WebBinding -Name 'Default Web Site' -HostHeader "Rock" -IP "*" -Port "443" -Protocol "https" -SslFlags "1"; \
#Connect the new cert to the web binding
$bind = Get-WebBinding -Name 'Default Web Site' -Protocol "https"; \
$bind.AddSslCertificate($localhostCert.GetCertHashString(), 'my')
$ProgressPreference = 'SilentlyContinue'
$USERNAME = "sqlexpress"

Invoke-WebRequest -UseBasicParsing 'https://download.microsoft.com/download/3/8/d/38de7036-2433-4207-8eae-06e247e17b25/SQLEXPR_x64_ENU.exe' -OutFile sqlexpress.exe

Start-Process ./sqlexpress.exe "/Q /x:/sqlexpress" -Wait

if (Get-LocalUser -Name $USERNAME -ErrorAction SilentlyContinue) {
  Remove-LocalUser -Name $USERNAME -Confirm:$false
}

$passwdSecure = ConvertTo-SecureString -String $env:SQL_PASSWORD -AsPlainText -Force
New-LocalUser $USERNAME -Password $passwdSecure -PasswordNeverExpires -AccountNeverExpires -UserMayNotChangePassword

Start-Process ./sqlexpress/setup.exe "/IACCEPTSQLSERVERLICENSETERMS /Q /USESQLRECOMMENDEDMEMORYLIMITS /ACTION=install /TCPENABLED=1 /SECURITYMODE=SQL /FEATURES=SQL /INSTANCEID=SQLEXPRESS /INSTANCENAME=SQLEXPRESS /UPDATEENABLED=FALSE /SQLSYSADMINACCOUNTS=`"$env:COMPUTERNAME\$USERNAME`" /SAPWD='$passwdSecure'" -Wait

Remove-Item ("./sqlexpress", "./sqlexpress.exe") -Recurse -Force

# Save As SYSTEM /f Ref
#[Environment]::SetEnvironmentVariable('PASSWD', $SQL_PASSWD, [System.EnvironmentVariableTarget]::User)

Stop-Service "MSSQL`$SQLEXPRESS"
Set-ItemProperty -path 'HKLM:\software\microsoft\microsoft sql server\mssql16.SQLEXPRESS\mssqlserver\supersocketnetlib\tcp\ipall' -name tcpdynamicports -value ''
Set-ItemProperty -path 'HKLM:\software\microsoft\microsoft sql server\mssql16.SQLEXPRESS\mssqlserver\supersocketnetlib\tcp\ipall' -name tcpport -value 1433
Set-ItemProperty -path 'HKLM:\software\microsoft\microsoft sql server\mssql16.SQLEXPRESS\mssqlserver\' -name LoginMode -value 2
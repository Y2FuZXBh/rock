$ProgressPreference = 'SilentlyContinue'
$USERNAME = "sqlexpress"

function New-Password($length, $minNonAlpha) {
  $alpha = [char]65..[char]90 + [char]97..[char]122
  $numeric = [char]48..[char]57
  # :;<=>?@!#$%&()*+,-./[\]^_`
  $symbols = [char]58..[char]64 + @([char]33) + [char]35..[char]38 + [char]40..[char]47 + [char]91..[char]96

  $nonAlpha = $numeric + $symbols
  $charSet = $alpha + $nonAlpha

  $pwdList = @()
  For ($i = 0; $i -lt $minNonAlpha; $i++) {
    $pwdList += $nonAlpha | Get-Random
  }
  For ($i = 0; $i -lt ($length - $minNonAlpha); $i++) {
    $pwdList += $charSet | Get-Random
  }

  $pwdList = $pwdList | Sort-Object { Get-Random }

  # a bug on Server 2016 joins as stringified integers unles we cast to [char[]]
  ([char[]] $pwdList) -join ""
}

Set-Location /

Invoke-WebRequest -UseBasicParsing 'https://download.microsoft.com/download/3/8/d/38de7036-2433-4207-8eae-06e247e17b25/SQLEXPR_x64_ENU.exe' -OutFile sqlexpress.exe

Start-Process ./sqlexpress.exe "/Q /x:/sqlexpress" -Wait

if (Get-LocalUser -Name $USERNAME -ErrorAction SilentlyContinue) {
  Remove-LocalUser -Name $USERNAME -Confirm:$false
}

$passwd = New-Password 127 57 # 45% int & special
$passwdSecure = ConvertTo-SecureString -String $passwd -AsPlainText -Force
New-LocalUser $USERNAME -Password $passwdSecure -PasswordNeverExpires -AccountNeverExpires -UserMayNotChangePassword

Start-Process ./sqlexpress/setup.exe "/IACCEPTSQLSERVERLICENSETERMS /Q /USESQLRECOMMENDEDMEMORYLIMITS /ACTION=install /TCPENABLED=1 /SECURITYMODE=SQL /FEATURES=SQL /INSTANCEID=SQLEXPRESS /INSTANCENAME=SQLEXPRESS /UPDATEENABLED=FALSE /SQLSYSADMINACCOUNTS=`"$env:COMPUTERNAME\$USERNAME`" /SAPWD='$passwdSecure'" -Wait

Remove-Item ("./sqlexpress", "./sqlexpress.exe") -Recurse -Force

# Save As SYSTEM /f Ref
[Environment]::SetEnvironmentVariable('PASSWD', $passwd, [System.EnvironmentVariableTarget]::User)

Stop-Service "MSSQL`$SQLEXPRESS"
Set-ItemProperty -path 'HKLM:\software\microsoft\microsoft sql server\mssql16.SQLEXPRESS\mssqlserver\supersocketnetlib\tcp\ipall' -name tcpdynamicports -value ''
Set-ItemProperty -path 'HKLM:\software\microsoft\microsoft sql server\mssql16.SQLEXPRESS\mssqlserver\supersocketnetlib\tcp\ipall' -name tcpport -value 1433
Set-ItemProperty -path 'HKLM:\software\microsoft\microsoft sql server\mssql16.SQLEXPRESS\mssqlserver\' -name LoginMode -value 2
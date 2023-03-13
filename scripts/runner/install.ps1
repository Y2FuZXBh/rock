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

$USERNAME = "circleci"
$AUTH_TOKEN = Get-Content "Z:\share\circleci.txt"
$platform = "windows/amd64"
$installDirPath = "$env:ProgramFiles\CircleCI\runner"
$runnerStartPath = "$env:HOMEDRIVE\Users\$USERNAME\runner"

# Install Git
choco install -y git --params "'/GitAndUnixToolsOnPath'"
choco install -y gzip
choco install -y nssm

# mkdir
if (-not (Test-Path $installDirPath -PathType "Container")) {
  New-Item "$installDirPath" -ItemType "Directory" -Force
}

$passwd = New-Password 127 57 # 45% int & special
$passwdSecure = ConvertTo-SecureString -String $passwd -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($USERNAME, $passwdSecure)

# Create a user with the generated password
Write-Host "Creating a new administrator user to run CircleCI tasks"
if (Get-LocalUser -Name $USERNAME -ErrorAction SilentlyContinue) {
  Remove-LocalUser -Name $USERNAME -Confirm:$false
}
$account = New-LocalUser $USERNAME -Password $passwdSecure -PasswordNeverExpires -AccountNeverExpires -UserMayNotChangePassword

# Add user an administrators & docker-users
Add-LocalGroupMember Administrators $account
#Add-LocalGroupMember docker-users $account

# Save the credential to Credential Manager for sans-prompt MSTSC
# First for the current user, and later for the runner user
Write-Host "Saving the password to Credential Manager"
Start-Process cmdkey.exe -ArgumentList ("/add:TERMSRV/localhost", "/user:$USERNAME", "/pass:$passwd")
Start-Process cmdkey.exe -ArgumentList ("/add:TERMSRV/localhost", "/user:$USERNAME", "/pass:$passwd") -Credential $cred

Write-Host "Configuring Remote Desktop Client"
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0 -Force
[void](reg.exe ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" "/v" "AllowSavedCredentialsWhenNTLMOnly" /t REG_DWORD /d 0x1 /f)
[void](reg.exe ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" "/v" "ConcatenateDefaults_AllowSavedNTLMOnly" /t REG_DWORD /d 0x1 /f)
[void](reg.exe ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentialsWhenNTLMOnly" /v "1" /t REG_SZ /d "TERMSRV/localhost" /f)

# Configure MSTSC to suppress interactive prompts on RDP connection to localhost
Start-Process reg.exe -ArgumentList ("ADD", '"HKCU\Software\Microsoft\Terminal Server Client"', "/v", "AuthenticationLevelOverride", "/t", "REG_DWORD", "/d", "0x0", "/f") -Credential $cred
$rdp_cert = (wmic /namespace:\\root\CIMV2\TerminalServices PATH Win32_TSGeneralSetting get SSLCertificateSHA1Hash)[2].trim()
Start-Process reg.exe -ArgumentList (
  "ADD", 
  '"HKCU\Software\Microsoft\Terminal Server Client\Servers\localhost"', 
  "/v", "CertHash", 
  "/t", "REG_BINARY", 
  "/d", "$rdp_cert",
  "/f"
) -Credential $cred

# Stop starting Server Manager at logon
Start-Process reg.exe -ArgumentList ("ADD", '"HKCU\Software\Microsoft\ServerManager"', "/v", "DoNotOpenServerManagerAtLogon", "/t", "REG_DWORD", "/d", "0x1", "/f") -Credential $cred

# Update policy
gpupdate /force

$SCALE = 5

# mkdir
if (-not (Test-Path "$installDirPath\lib" -PathType "Container")) {
  New-Item "$installDirPath\lib" -ItemType "Directory" -Force
}
if (-not (Test-Path "$installDirPath\conf" -PathType "Container")) {
  New-Item "$installDirPath\conf" -ItemType "Directory" -Force
}

foreach ($c in (1..$SCALE)) {

  $SERVICE_NAME = "CircleCI Runner $c"


  # Preparing config template
  # ref: https://circleci.com/docs/runner-config-reference/#self-hosted-runner-configuration-reference
  @"
api:
    url: https://runner.circleci.com
    auth_token: $AUTH_TOKEN
runner:
    mode: continuous
    name: windows-runner-$($env:COMPUTERNAME.ToLower())
    working_directory: $runnerStartPath\$c\%s
    cleanup_working_directory: true
    #max_run_time: 5m
    #command_prefix: ["powershell.exe", "-NoLogo"]
logging:
    file: $installDirPath\log\runner-$c.log
"@ -replace "([^`r])`n", "`$1`r`n" | Out-File "$installDirPath\conf\runner-$c.yaml" -Encoding unicode -Force

  # Download Service Agent
  $agentDist = "https://circleci-binary-releases.s3.amazonaws.com/circleci-launch-agent"
  $agentVer = (Invoke-WebRequest -UseBasicParsing "$agentDist/release.txt").Content.Trim()
  $agentChecksum = ((Invoke-WebRequest -UseBasicParsing "$agentDist/$agentVer/checksums.txt").Content.Split("`n") | Select-String $platform).Line.Split(" ")
  $agentHash = $agentChecksum[0]
  $agentFile = $agentChecksum[1].Split("/")[-1]
  Invoke-WebRequest -UseBasicParsing "$agentDist/$agentVer/$platform/$agentFile" -OutFile "$installDirPath\lib\runner-$c.exe"
  Write-Host "Verifying CircleCI Launch Agent download"
  if ((Get-FileHash "$installDirPath\lib\runner-$c.exe" -Algorithm "SHA256").Hash.ToLower() -ne $agentHash.ToLower()) {
    throw "Invalid checksum for CircleCI Launch Agent, please try download again"
  }

  sc.exe stop "$($SERVICE_NAME.Replace(' ', '-').ToLower())" "4:5:3"

  sc.exe delete "$($SERVICE_NAME.Replace(' ', '-').ToLower())"

  nssm install "$($SERVICE_NAME.Replace(' ', '-').ToLower())" "$($env:SystemRoot.tolower())\system32\windowspowershell\v1.0\powershell.exe"
  nssm set "$($SERVICE_NAME.Replace(' ', '-').ToLower())" AppParameters "`"& '$installDirPath\lib\runner-$c.exe' --config '$installDirPath\conf\runner-$c.yaml' 2>`$null`""
  nssm set "$($SERVICE_NAME.Replace(' ', '-').ToLower())" AppDirectory "$installDirPath"
  nssm set "$($SERVICE_NAME.Replace(' ', '-').ToLower())" AppExit Default Restart
  nssm set "$($SERVICE_NAME.Replace(' ', '-').ToLower())" AppPriority HIGH_PRIORITY_CLASS
  nssm set "$($SERVICE_NAME.Replace(' ', '-').ToLower())" Description "$SERVICE_NAME, based on install script at: https://raw.githubusercontent.com/CircleCI-Public/runner-installation-files/main/windows-install/Install-CircleCIRunner.ps1"
  nssm set "$($SERVICE_NAME.Replace(' ', '-').ToLower())" DisplayName "$SERVICE_NAME"
  nssm set "$($SERVICE_NAME.Replace(' ', '-').ToLower())" ObjectName .\circleci "$passwd"
  nssm set "$($SERVICE_NAME.Replace(' ', '-').ToLower())" Start SERVICE_DELAYED_AUTO_START
  nssm set "$($SERVICE_NAME.Replace(' ', '-').ToLower())" Type SERVICE_WIN32_OWN_PROCESS

  Start-Service -Name "$($SERVICE_NAME.Replace(' ', '-').ToLower())"

}
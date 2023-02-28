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
$AUTH_TOKEN = Get-Content Z:\share\circleci.txt
$platform = "windows/amd64"
$installDirPath = "$env:ProgramFiles\CircleCI"

# Install Git
choco install -y git --params "'/GitAndUnixToolsOnPath'"
choco install -y gzip
  
# mkdir
if (-not (Test-Path $installDirPath -PathType Container)) {
  New-Item "$installDirPath" -ItemType Directory -Force
}
Push-Location "$installDirPath"

# Download launch-agent
$agentDist = "https://circleci-binary-releases.s3.amazonaws.com/circleci-launch-agent"
$agentVer = (Invoke-WebRequest -UseBasicParsing "$agentDist/release.txt").Content.Trim()
$agentChecksum = ((Invoke-WebRequest -UseBasicParsing "$agentDist/$agentVer/checksums.txt").Content.Split("`n") | Select-String $platform).Line.Split(" ")
$agentHash = $agentChecksum[0]
$agentFile = $agentChecksum[1].Split("/")[-1]
Invoke-WebRequest -UseBasicParsing "$agentDist/$agentVer/$platform/$agentFile" -OutFile "$agentFile"
Write-Host "Verifying CircleCI Launch Agent download"
if ((Get-FileHash "$agentFile" -Algorithm SHA256).Hash.ToLower() -ne $agentHash.ToLower()) {
  throw "Invalid checksum for CircleCI Launch Agent, please try download again"
}

$passwd = New-Password 95 40 # 42 10
$passwdSecure = $(ConvertTo-SecureString -String $passwd -AsPlainText -Force)
$cred = New-Object System.Management.Automation.PSCredential ($USERNAME, $passwdSecure)

# Create a user with the generated password
Write-Host "Creating a new administrator user to run CircleCI tasks"
if (Get-LocalUser -Name $USERNAME -ErrorAction SilentlyContinue) {
  Remove-LocalUser -Name $USERNAME -Confirm:$false
}
$account = New-LocalUser $USERNAME -Password $passwdSecure -PasswordNeverExpires -AccountNeverExpires -UserMayNotChangePassword

# Add user an administrators & docker-users
Add-LocalGroupMember Administrators $account
Add-LocalGroupMember docker-users $account

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
[void](gpupdate.exe /force)

# Configure scheduled tasks to run launch-agent
Write-Host "Registering CircleCI Launch Agent tasks to Task Scheduler"
$commonTaskSettings = New-ScheduledTaskSettingsSet -Compatibility Vista -AllowStartIfOnBatteries -ExecutionTimeLimit (New-TimeSpan)
[void](Register-ScheduledTask -Force -TaskName "CircleCI Launch Agent" -User $USERNAME -Action (New-ScheduledTaskAction -Execute powershell.exe -Argument "-Command `"& `'$installDirPath\$agentFile`' --config `'$installDirPath\launch-agent-config.yaml`'; & logoff.exe (Get-Process -Id ```$PID).SessionID`"") -Settings $commonTaskSettings -Trigger (New-ScheduledTaskTrigger -AtLogon -User $USERNAME) -RunLevel Highest)
$keeperTask = Register-ScheduledTask -Force -TaskName "CircleCI Launch Agent session keeper" -User $USERNAME -Password $passwd -Action (New-ScheduledTaskAction -Execute powershell.exe -Argument "-Command `"while (```$true) { if ((query session ```$env:USERNAME 2> ```$null).Length -eq 0) { mstsc.exe /v:localhost; Start-Sleep 5 } Start-Sleep 1 }`"") -Settings $commonTaskSettings -Trigger (New-ScheduledTaskTrigger -AtStartup)

# Preparing config template
@"
api:
  url: https://runner.circleci.com
  auth_token: $AUTH_TOKEN
runner:
  mode: single-task
  name: windows-runner-$($env:COMPUTERNAME.ToLower())
  working_directory: $("$env:HOMEDRIVE\Users\$USERNAME\CircleCI")\%s
  cleanup_working_directory: true
  #max_run_time: 5m
  #command_prefix: ["powershell.exe", "-NoLogo"]
logging:
  file: $env:ProgramFiles\CircleCI\log\runner-$($env:COMPUTERNAME.ToLower()).log
"@ -replace "([^`r])`n", "`$1`r`n" | Out-File $env:ProgramFiles\CircleCI\launch-agent-config.yaml -Encoding unicode -Force

# Start runner!
Write-Host "Starting CircleCI Launch Agent"
Pop-Location
Start-ScheduledTask -InputObject $keeperTask
Write-Host ""
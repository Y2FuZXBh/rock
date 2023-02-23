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
$AUTH_TOKEN = gc Z:\share\circleci.txt
$platform = "windows/amd64"
$installDirPath = "$env:ProgramFiles\CircleCI"

# Install Git
choco install -y git --params "'/GitAndUnixToolsOnPath'"
choco install -y gzip
    
# mkdir
[void](New-Item "$installDirPath" -ItemType Directory -Force)
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
  
$passwd = Random-Password 42 10
$passwdSecure = $(ConvertTo-SecureString -String $passwd -AsPlainText -Force)
$cred = New-Object System.Management.Automation.PSCredential ($USERNAME, $passwdSecure)
  
# Create a user with the generated password
Write-Host "Creating a new administrator user to run CircleCI tasks"
Get-LocalUser -Name
$user = New-LocalUser $USERNAME -Password $passwdSecure -PasswordNeverExpires -AccountNeverExpires -UserMayNotChangePassword
  
# Make the user an administrator
Add-LocalGroupMember Administrators $user
  
# Save the credential to Credential Manager for sans-prompt MSTSC
# First for the current user, and later for the runner user
Write-Host "Saving the password to Credential Manager"
Start-Process cmdkey.exe -ArgumentList ("/add:TERMSRV/localhost", "/user:$USERNAME", "/pass:$passwd")
Start-Process cmdkey.exe -ArgumentList ("/add:TERMSRV/localhost", "/user:$USERNAME", "/pass:$passwd") -Credential $cred
  
Write-Host "Configuring Remote Desktop Client"
  
[void](reg.exe ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" "/v" "AllowSavedCredentialsWhenNTLMOnly" /t REG_DWORD /d 0x1 /f)
[void](reg.exe ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" "/v" "ConcatenateDefaults_AllowSavedNTLMOnly" /t REG_DWORD /d 0x1 /f)
[void](reg.exe ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentialsWhenNTLMOnly" /v "1" /t REG_SZ /d "TERMSRV/localhost" /f)
gpupdate.exe /force
  
# Configure MSTSC to suppress interactive prompts on RDP connection to localhost
Start-Process reg.exe -ArgumentList ("ADD", '"HKCU\Software\Microsoft\Terminal Server Client"', "/v", "AuthenticationLevelOverride", "/t", "REG_DWORD", "/d", "0x0", "/f") -Credential $cred
  
# Stop starting Server Manager at logon
Start-Process reg.exe -ArgumentList ("ADD", '"HKCU\Software\Microsoft\ServerManager"', "/v", "DoNotOpenServerManagerAtLogon", "/t", "REG_DWORD", "/d", "0x1", "/f") -Credential $cred
  
# Configure scheduled tasks to run launch-agent
Write-Host "Registering CircleCI Launch Agent tasks to Task Scheduler"
$commonTaskSettings = New-ScheduledTaskSettingsSet -Compatibility Vista -AllowStartIfOnBatteries -ExecutionTimeLimit (New-TimeSpan)
[void](Register-ScheduledTask -Force -TaskName "CircleCI Launch Agent" -User $username -Action (New-ScheduledTaskAction -Execute powershell.exe -Argument "-Command `"& `"`"$installDirPath\$agentFile`"`"`"`" --config `"`"$installDirPath\launch-agent-config.yaml`"`"`"; & logoff.exe (Get-Process -Id `$PID).SessionID`"") -Settings $commonTaskSettings -Trigger (New-ScheduledTaskTrigger -AtLogon -User $username) -RunLevel Highest)
$keeperTask = Register-ScheduledTask -Force -TaskName "CircleCI Launch Agent session keeper" -User $username -Password $passwd -Action (New-ScheduledTaskAction -Execute powershell.exe -Argument "-Command `"while (`$true) { if ((query session $username).Length -eq 0) { mstsc.exe /v:localhost; Start-Sleep 5 } Start-Sleep 1 }`"") -Settings $commonTaskSettings -Trigger (New-ScheduledTaskTrigger -AtStartup)
  
# Preparing config template
@"
  api:
    url: https://runner.circleci.com
    auth_token: $AUTH_TOKEN
  runner:
    mode: continuous
    name: windows-runner-$($env:COMPUTERNAME.ToLower())
    working_directory: $("$env:HOMEDRIVE\Users\$USERNAME\CircleCI\")\%s
    cleanup_working_directory: true
    max_run_time: 5m
    #command_prefix: ["powershell.exe", "-NoLogo"]
  logging:
    file: $env:ProgramFiles\CircleCI\log\runner-%s.log
"@ -replace "([^`r])`n", "`$1`r`n" | Out-File $env:ProgramFiles\CircleCI\launch-agent-config.yaml -Encoding unicode -Force
  
# Start runner!
Write-Host "Starting CircleCI Launch Agent"
Pop-Location
Start-ScheduledTask -InputObject $keeperTask
Write-Host ""
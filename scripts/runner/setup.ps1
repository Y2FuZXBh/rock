# CircleCI - Runner
## https://circleci.com/docs/runner-overview/
$install = https://raw.githubusercontent.com/CircleCI-Public/runner-installation-files/main/windows-install/Install-CircleCIRunner.ps1
$uninstall = https://raw.githubusercontent.com/CircleCI-Public/runner-installation-files/main/windows-install/Uninstall-CircleCIRunner.ps1

Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072

iex 
#Invoke-WebRequest -UseBasicParsing -Uri $runner_install

# CircleCI - Runner

# install
choco install -y git gh circleci-cli

# pass user read token & auth through git
gc Z:\share\pat.txt | gh auth login --with-token $_

# pull secret with gh
#gh secret list --repo github.com/Y2FuZXBh/rock
#gh api /repos/Y2FuZXBh/rock/actions/secrets/CIRCLECI_RUNNER_WINDOWS22

# copy & replace template(s)

# setup circleci connection (add this with built-in token+name)
(wget -UseBasicParsing https://raw.githubusercontent.com/CircleCI-Public/runner-installation-files/main/windows-install/Install-CircleCIRunner.ps1).content | iex


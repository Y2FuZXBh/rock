# run docker containers here after build tests...

$USERNAME = ($env:username).ToLower()
Set-Location ~/Desktop

## IIS ##
#docker build ./iis --force-rm --pull --compress --tag rock:latest
#docker run --detach --name "rock-$USERNAME" -p 80:80 -p 443:443 rock:latest

## SQL ##
docker build ./sql --force-rm --pull --compress --tag sql:latest
docker run --detach --name "sql-$USERNAME" -p 1433:1433 sql:latest
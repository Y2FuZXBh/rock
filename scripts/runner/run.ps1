# run docker containers here after build tests...

$USERNAME = $env:username

Set-Location ~/Desktop

docker build . --force-rm --pull --compress --tag rock:latest

docker run --detach --name "rock-$USERNAME" -p 80:80 -p 443:443 rock:latest
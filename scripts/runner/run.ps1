function Remove-Container ([String]$Name) {
    $container = docker container ls -a --format '{{json .}}' | ConvertFrom-Json | where { $_.Names -eq $Name }
    if ($container) {
        if ($container.State -ne 'exited') {
            docker container stop $container.ID
            Write-Output "Stopped Container $($images.Names)"
        }
        docker container rm $container.ID
        Write-Output "Removed Container $($images.Names)"
    }
}

function Remove-Images {
    $images = docker image ls --format '{{json .}}' | ConvertFrom-Json | Where-Object { $_.Containers -eq 'N/A' -and $_.Repository -eq '<none>' -and $_.Tag -eq '<none>' }
    if ($images) {
        $images.ID.ForEach({ docker image rm $_ })
        Write-Output "Cleaned $($images.count) Images"
    }
}

# SET THIS or ADD API Call to Project
$MASTER = "main"
$USERNAME = ($env:CIRCLE_USERNAME).ToLower()

## MAIN ##
if($env:CIRCLE_BRANCH -ne $MASTER){

    # Change This If Needed:
    $IIS_DOCKERFILE = "https://raw.githubusercontent.com/Y2FuZXBh/rock/dev/images/iis.dockerfile"
    $SQL_DOCKERFILE = "https://raw.githubusercontent.com/Y2FuZXBh/rock/dev/images/sql.dockerfile"

    ## IIS ##
    (Invoke-WebRequest -UseBasicParsing $IIS_DOCKERFILE).content | docker build - --force-rm --pull --compress --tag rock:latest
    Remove-Images
    Remove-Container -Name "rock-$USERNAME"
    docker run --detach --name "rock-$USERNAME" -p 80:80 -p 443:443 rock:latest

    ## SQL ##
    (Invoke-WebRequest -UseBasicParsing $SQL_DOCKERFILE).content | docker build - --force-rm --pull --compress --tag sql:latest
    Remove-Images
    Remove-Container -Name "sql-$USERNAME"
    docker run --detach --name "sql-$USERNAME" -p 1433:1433 sql:latest

}

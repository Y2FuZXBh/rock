function Remove-Container ([String]$Name) {
    $container = docker container ls -a --format '{{json .}}' | ConvertFrom-Json | Where-Object { $_.Names -eq $Name }
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

function Get-ContainerIP ([string]$Name) {
    return (docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $Name)
}

function Get-ContainerPorts ([string]$Name) {
    return (docker container port $Name).foreach({ $_.split('/')[0] })
}
function Get-OpenPort {
    $allowed = 8500..9000
    $active = (docker container ls --format "{{.Names}}|{{.Ports}}" -a).split('>|/').where({ if ($_ -match "^\d+$") { $_ } })
    return ((Compare-Object -ReferenceObject $allowed -DifferenceObject $active).where({ $_.SideIndicator -eq '<=' }).InputObject[0, 1])
}

# SET THIS or ADD API Call to Project
$MASTER = "main"
$USERNAME = ($env:CIRCLE_USERNAME).ToLower()

## MAIN ##
if ($env:CIRCLE_BRANCH -ne $MASTER) {

    $PORTS = Get-OpenPort

    ## IIS ##
    docker build -f iis.dockerfile --force-rm --pull --compress --tag rock:latest .\docker
    Remove-Images
    Remove-Container -Name "rock-$USERNAME"
    docker run --detach --name "rock-$USERNAME" -p "80:$($PORTS[0])" rock:latest
    Write-Output "Container Created: rock-$USERNAME"

    ## SQL ##
    docker build -f sql.dockerfile --force-rm --pull --compress --tag sql:latest .\docker
    Remove-Images
    Remove-Container -Name "sql-$USERNAME"
    docker run --detach --name "sql-$USERNAME" -p "1433:$($PORTS[1])" sql:latest
    Write-Output "Container Created: sql-$USERNAME"

    ## URL ##
    foreach ($_ in Get-ContainerPorts -Name "rock-$USERNAME") {
        $ip = Get-ContainerIP -Name "rock-$USERNAME"
        Write-Output "http://${ip}:$_/Start.aspx"
    }
}

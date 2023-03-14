<<<<<<< HEAD
# run docker containers here after build tests...

=======
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
    $PASSWD = New-Password
    #Set-Location docker

    ## BUILD ##
    docker build -f docker/sql.dockerfile --force-rm --pull --compress --tag sql:latest .\
    docker build -f docker/iis.dockerfile --force-rm --pull --compress --tag rock:latest .\

    ## CLEAN ##
    Remove-Images
    Remove-Container -Name "rock-$USERNAME"
    Remove-Container -Name "sql-$USERNAME"

    ## SQL ##
    docker run --detach --name "sql-$USERNAME" -e "SQL_PASSWD=$PASSWD" -p "1433:$($PORTS[0])" sql:latest
    Write-Output "Container Created: sql-$USERNAME"

    ## IIS ##
    docker run --detach --name "rock-$USERNAME" -e "SQL_IP=$(Get-ContainerIP -Name "sql-$USERNAME")" -e "SQL_PORT=$($PORTS[0])" -e "SQL_PASSWD=$PASSWD" -p "80:$($PORTS[1])" rock:latest
    Write-Output "Container Created: rock-$USERNAME"

    ## URL ##
    foreach ($_ in Get-ContainerPorts -Name "rock-$USERNAME") {
        $ip = Get-ContainerIP -Name "rock-$USERNAME"
        Write-Output "http://${ip}:$_"
    }
}
>>>>>>> dev

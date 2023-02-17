$mof_location = "C:\Users\$env:USERNAME\IIS"

configuration "IIS-10.0-STIG" {

    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'xWebAdministration'
    Import-DscResource -ModuleName 'AccessControlDsc'
    Import-DscResource -ModuleName 'cNtfsAccessControl'
    Import-DscResource -ModuleName 'CertificateDsc'

    [string]$SiteName = 'Default Site'
    [char]$Drive = 'W'
    [int]$Size = 5
    [string]$Label = 'IIS'
    [bool]$CAC = $false
    [string]$AuthMode = "Anonymous"

    # Install IIS /w standard features
    WindowsFeatureSet 'IIS-Install' {
        Ensure               = 'Present'
        IncludeAllSubFeature = $false
        Name                 = @(
            "Web-Server",
            "Web-WebServer",
            "Web-Common-Http",
            "Web-Dir-Browsing",
            "Web-Http-Errors",
            "Web-Http-Redirect",
            "Web-Health",
            "Web-Http-Logging",
            "Web-Custom-Logging",
            "Web-Http-Tracing",
            "Web-Performance",
            "Web-Stat-Compression",
            "Web-Dyn-Compression",
            "Web-Security",
            "Web-Filtering",
            "Web-App-Dev",
            "Web-Net-Ext45",
            "Web-Asp-Net45",
            "Web-ISAPI-Ext",
            "Web-ISAPI-Filter",
            "Web-WebSockets",
            "Web-Basic-Auth",
            "Web-Windows-Auth",
            "Web-Client-Auth",
            "Web-Mgmt-Tools",
            "Web-Url-Auth"
        )      
    }

    # Partition Drive if needed
    Script 'Verify - IIS Drive' {
        DependsOn  = "[WindowsFeatureSet]IIS-Install"
        GetScript  = {
            $GetVolumes = (Get-Volume -Verbose:$false | Where-Object { $_.DriveLetter -ne $null }).DriveLetter
            Write-Verbose "Existing Drives: $($GetVolumes -join ',')"
            return $GetVolumes
        }
        TestScript = { 
            $state = [scriptblock]::Create($GetScript).Invoke()
            if ($state -contains $using:Drive) {
                Write-Verbose "$($using:Drive) = True"
                return $true
            }
            else {
                Write-Verbose "$($using:Drive) = False"
                return $false
            }
        }
        SetScript  = {

            # Make Room for new Partition
            Get-PSDrive | Out-Null
            $OSVolume = Get-Volume -Verbose:$false | Where-Object { $_.DriveLetter -eq 'C' }    

            # select os par from initial test
            $OS = $OSVolume | Get-Partition
            $OSMax = ($OSVolume | Get-PartitionSupportedSize).sizemax
   
            # Clean up unallocated space
            if ($OS.Size -lt $OSMax) {
                try {
                    $OS | Resize-Partition -Size $OSMax -Confirm:$false -ErrorAction 'SilentlyContinue'
                }
                catch { '' }
                Get-PSDrive | Out-Null
                $OS = $OSVolume | Get-Partition
            }
   
            # collect needed variables
            $reqvalue = [Int64][scriptblock]::Create("$using:Size" + "Gb").Invoke()[0]
            $OS = [psobject]@{
                'DiskNumber'      = $OS.DiskNumber
                'PartitionNumber' = $OS.PartitionNumber
                'RequestedSize'   = $reqvalue
                'ResizeValue'     = ($OS.Size - $reqvalue)
            }
   
            # Make new partition
            Resize-Partition -DiskNumber $OS.DiskNumber -PartitionNumber $OS.PartitionNumber -Size $OS.ResizeValue -Confirm:$false
   
            # Format New Partition
            New-Partition -DiskNumber $OS.DiskNumber -UseMaximumSize -DriveLetter $using:Drive -confirm:$False -Verbose:$False
            Format-Volume -DriveLetter $using:Drive -FileSystem 'NTFS' -NewFileSystemLabel $using:Label -confirm:$False -Verbose:$False

            # Kill pop-up
            Start-Sleep -Milliseconds 500
            try {
                ((New-Object -ComObject Shell.Application).Windows() | Where-Object { $_.LocationURL -eq "file:///$($using:Drive):/" }).quit()
            }
            catch { '' }

            # Wait for drive-path setup
            Do {
                $test = $False
                if (Test-Path "$($using:Drive):\") {
                    $test = $true
                }
                else {
                    Get-PSDrive | Out-Null
                    Start-Sleep -Seconds 1
                }
            }until($test -eq $true)
           

        }
    }

    # Move IIS
    Script 'IIS-Move' {
        DependsOn  = "[Script]Verify - IIS Drive"
        GetScript  = {
            $inetpub = Test-Path "C:\inetpub"
            if ($inetpub -eq $true) {
                Write-Verbose "C:\inetpub"
                return $true
            }
            else {
                Write-Verbose "$($using:Drive):\inetpub"
                return $false
            }
        }
        TestScript = { 
            $state = [scriptblock]::Create($GetScript).Invoke()
            if ($state) {
                Write-Verbose "IIS Moved = False"
                return $false
            }
            else {
                Write-Verbose "IIS Moved = True"
                return $true
            }
        }
        SetScript  = {

            #// Create variables
            $OldPath = "%SystemDrive%\inetpub"
            $NewPath = "$($using:Drive):\inetpub"

            #// stop services
            & iisreset /stop | Out-Null
            Start-Sleep -Seconds 2

            #// move inetpub directory
            & Robocopy "$env:SystemDrive\inetpub" $NewPath *.* /MOVE /S /E /COPYALL /R:0 /W:0 | Out-Null

            #// modify reg
            New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\InetStp" -Name "PathWWWRoot" -Value "$NewPath\wwwroot" -PropertyType ExpandString -Force | Out-Null
            New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\WAS\Parameters" -Name "ConfigIsolationPath" -Value "$NewPath\temp\appPools" -PropertyType String -Force | Out-Null
            New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\InetStp" -Name "PathWWWRoot" -Value "$NewPath\wwwroot" -PropertyType ExpandString -Force | Out-Null

            #// Backup and modify applicationHost.config file
            Copy-Item "$env:SystemDrive\Windows\System32\inetsrv\config\applicationHost.config" "$env:SystemDrive\Windows\System32\inetsrv\config\applicationHost.config.bak"
            Start-Sleep 5

            #// Replace "%SystemDrive%\inetpub" with $NewDrive":\inetpub"
            (Get-Content "$env:SystemDrive\Windows\System32\inetsrv\config\applicationHost.config").replace("$OldPath", "$NewPath") `
            | Set-Content "$env:SystemDrive\Windows\System32\inetsrv\config\applicationHost.config"

            Start-Sleep -Seconds 2

            #// Update IIS Config
            & "$env:SystemDrive\Windows\system32\inetsrv\appcmd" set config -section:system.applicationhost/configHistory -path:$NewPath\history | Out-Null
           
            #// Start services
            & iisreset /start | Out-Null

            # Needed for V-100167 file ownership
            $Account = New-Object System.Security.Principal.NTAccount("BUILTIN\Administrators")
            $FileSecurity = new-object System.Security.AccessControl.FileSecurity
            $FileSecurity.SetOwner($Account)
            [System.IO.File]::SetAccessControl("C:\windows\system32\inetsrv\InetMgr.exe", $FileSecurity)
        }
    }

    # V-100103 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100103" [medium]
    # V-100157 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100157" [high]
    # V-100159 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100159" [medium]
    Registry 'V-100103,V-100157 - Server - Remove WebManagement REG Key' {
        Ensure    = "Absent"
        Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WebManagement\Server"
        ValueName = ""
    }

    Service 'V-100103,V-100157 - Server -  Stop & Disable (wmsvc)' {
        Name        = 'wmsvc'
        State       = 'Stopped'
        StartupType = 'Disabled'
        Ensure      = 'Absent'
    }

    # V-100105 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100105" [medium]
    xWebConfigProperty 'V-100105 - Server - Log File Flags' {
        WebsitePath  = 'MACHINE/WEBROOT/APPHOST'
        Filter       = 'system.applicationHost/sites/siteDefaults/logFile'
        PropertyName = 'logExtFileFlags'
        Value        = 'Date,Time,ClientIP,UserName,Method,UriQuery,HttpStatus,Referer'
        Ensure       = 'Present'
    }

    # V-100107 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100107" [medium]
    xWebConfigProperty 'V-100107 - Server - W3C (Both log file and ETW event)' {
        WebsitePath  = 'MACHINE/WEBROOT/APPHOST'
        Filter       = 'system.applicationHost/sites/siteDefaults/logFile'
        PropertyName = 'logTargetW3C'
        Value        = 'File,ETW'
        Ensure       = 'Present'
    }

    xIisLogging 'V-100105 - Server - (Logflags,LogCustomFields)' {
        # V-100111 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100111" [medium] (LogFormat=W3C)
        # V-100113 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100113" [medium] (LogFormat=W3C)
        LogFormat            = 'W3C'
        # V-100165 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100165" [medium] (set path=..\inetpub\logs\server)
        LogPath              = "${Drive}:\inetpub\logs\server"
        LogTargetW3C         = 'File,ETW'
        LoglocalTimeRollover = $true
        # V-100165 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100165" [medium] (not LogPeriod=MaxSize)
        LogPeriod            = 'Daily'
        LogTruncateSize      = '4294967295'
        # V-100105 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100105" [medium] ('Date,Time,ClientIP,UserName,Method,UriQuery,HttpStatus,Referer')
        # V-100113 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100113" [medium] ('UserAgent,UserName,Referer')
        Logflags             = @('Date', 'Time', 'ClientIP', 'UserName', 'Method', 'UriQuery', 'HttpStatus', 'Referer', 'UserAgent')
        LogCustomFields      = @(
            # V-100109 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100109" [medium] (SourceName=X-Forwarded-For)
            MSFT_xLogCustomField {
                LogFieldName = "X-Forwarded-For"
                SourceName   = "X-Forwarded-For"
                SourceType   = "RequestHeader"
            }
            # V-100111 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100111" [medium] (SourceName=Warning)
            MSFT_xLogCustomField {
                LogFieldName = "Warning"
                SourceName   = "Warning"
                SourceType   = "RequestHeader"
            }
            # V-100111 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100111" [medium] (SourceName=Connection)
            MSFT_xLogCustomField {
                LogFieldName = "Connection"
                SourceName   = "Connection"
                SourceType   = "RequestHeader"
            }
            # V-100113 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100113" [medium] (SourceName=Authorization)
            MSFT_xLogCustomField {
                LogFieldName = "Authorization"
                SourceName   = "Authorization"
                SourceType   = "RequestHeader"
            }
            # V-100113 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100113" [medium] (SourceName=Authorization)
            MSFT_xLogCustomField {
                LogFieldName = "Content-Type"
                SourceName   = "Content-Type"
                SourceType   = "ResponseHeader"
            }
        )
    }

    # V-100115 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100115" [medium]
    NTFSAccessEntry "V-100115 - Server - Rights Management (${Drive}:\inetpub\logs)" {
        Path              = "${Drive}:\inetpub\logs"
        Force             = $true
        AccessControlList = @(
            NTFSAccessControlList {
                Principal          = "System"
                ForcePrincipal     = $false
                AccessControlEntry = @(
                    NTFSAccessControlEntry {
                        AccessControlType = 'Allow'
                        FileSystemRights  = 'FullControl'
                        Inheritance       = 'This folder subfolders and files'
                        Ensure            = 'Present'
                    }
                )               
            }
            NTFSAccessControlList {
                Principal          = "Administrators"
                ForcePrincipal     = $true
                AccessControlEntry = @(
                    NTFSAccessControlEntry {
                        AccessControlType = 'Allow'
                        FileSystemRights  = 'FullControl'
                        Inheritance       = 'This folder subfolders and files'
                        Ensure            = 'Present'
                    }
                )               
            }
        )
    }

    # V-100117 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100117" [medium]
    # Configure system backups to include the directory paths of all IIS 10.0 web server and website log files.

    # V-100119 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100119" [medium]
    # Document how the hosted application user management is accomplished.

    # V-100121 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100121" [medium]
    # Remove all unapproved programs and roles from the production IIS 10.0 web server.

    # V-100123 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100123" [medium]
    xWebConfigProperty 'V-100123 - Server - Disable Proxy' {
        WebsitePath  = 'MACHINE/WEBROOT'
        Filter       = 'system.net/defaultProxy'
        PropertyName = 'enabled'
        Value        = $false
        Ensure       = 'Present'
    }

    # V-100125 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100125" [high]
    file "V-100125 - Server - Remove (${Drive}:\inetpub\wwwroot\iisstart.htm)" {
        Ensure          = "Absent"
        Type            = "File"
        DestinationPath = "${Drive}:\inetpub\wwwroot\iisstart.htm"
        Force           = $true        
    }
    file "V-100125 - Server - Remove (${Drive}:\inetpub\wwwroot\iisstart.png)" {
        Ensure          = "Absent"
        Type            = "File"
        DestinationPath = "${Drive}:\inetpub\wwwroot\iisstart.png"
        Force           = $true
    }
    file "V-100125 - Server - Remove (${Drive}:\inetpub\custerr\en-US)" {
        Ensure          = "Absent"
        Type            = "Directory"
        Recurse         = $true
        DestinationPath = "${Drive}:\inetpub\custerr\en-US"
        Force           = $true
    }
    file "V-100125 - Server - Remove (${Drive}:\Program Files\Common Files\System\msadc)" {
        Ensure          = "Absent"
        Type            = "Directory"
        Recurse         = $true
        DestinationPath = "${Drive}:\Program Files\Common Files\System\msadc"
        Force           = $true
    }
    file "V-100125 - Server - Remove (${Drive}:\Program Files (x86)\Common Files\System\msadc)" {
        Ensure          = "Absent"
        Type            = "Directory"
        Recurse         = $true
        DestinationPath = "${Drive}:\Program Files (x86)\Common Files\System\msadc"
        Force           = $true
    }

    # V-100127 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100127" [medium]
    # V-100181 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100181" [high]
    # Delete any local accounts which were created by features which have been uninstalled or are not used.

    # V-100129 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100129" [medium]
    # V-100169 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100169" [medium]
    # Remove all utility programs, Operating System features, or modules installed that are not necessary for web server operation.

    # V-100131 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100131" [medium]
    xIisMimeTypeMapping 'V-100131 - Server - Remove Mime (.exe)' {
        Extension         = '.exe'
        MimeType          = 'application/octet-stream'
        Ensure            = 'Absent'
        ConfigurationPath = 'MACHINE/WEBROOT/APPHOST'
    }
    xIisMimeTypeMapping 'V-100131 - Server - Remove Mime (.dll)' {
        Extension         = '.dll'
        MimeType          = 'application/x-msdownload'
        Ensure            = 'Absent'
        ConfigurationPath = 'MACHINE/WEBROOT/APPHOST'
    }
    xIisMimeTypeMapping 'V-100131 - Server - Remove Mime (.com)' {
        Extension         = '.com'
        MimeType          = 'application/octet-stream'
        Ensure            = 'Absent'
        ConfigurationPath = 'MACHINE/WEBROOT/APPHOST'
    }
    xIisMimeTypeMapping 'V-100131 - Server - Remove Mime (.bat)' {
        Extension         = '.bat'
        MimeType          = 'application/bat'
        Ensure            = 'Absent'
        ConfigurationPath = 'MACHINE/WEBROOT/APPHOST'
    }    
    xIisMimeTypeMapping 'V-100131 - Server - Remove Mime (.csh)' {
        Extension         = '.csh'
        MimeType          = 'application/x-csh'
        Ensure            = 'Absent'
        ConfigurationPath = 'MACHINE/WEBROOT/APPHOST'
    }

    # V-100133 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100133" [medium]
    WindowsFeature 'V-100133 - Server - Disable (Web-DAV-Publishing)' {
        Ensure = 'Absent'
        Name   = 'Web-DAV-Publishing'
    }

    # V-100135 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100135" [medium]
    if ($CAC) {
        CertReq 'V-100135 - Server - Request DoD IIS Certificate' {
            CARootName          = 'test-dc01-ca'
            CAServerFQDN        = 'dc01.test.pha'
            Subject             = 'foodomain.test.net'
            KeyLength           = '2048'
            Exportable          = $true
            ProviderName        = 'Microsoft RSA SChannel Cryptographic Provider'
            OID                 = '1.3.6.1.5.5.7.3.1'
            KeyUsage            = '0xa0'
            CertificateTemplate = 'WebServer'
            AutoRenew           = $true
            FriendlyName        = 'SSL Cert for IIS Container'
            Credential          = $Credential
            KeyType             = 'RSA'
            RequestType         = 'CMC'
        }
    }
    else {
        Write-Verbose "V-100135 - Server - CAC Mode Disabled! No Cert Requested"
    }

    # V-100137 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100137" [medium]
    Script "V-100137 - Server - Remove .java and .jpp files" {
        GetScript  = {
            @{
                $JavaFiles = (Get-ChildItem "${using:Drive}:\" -Recurse -File -Include * .jpp, * .java -EA SilentlyContinue).FullName
                'Result'   = $JavaFiles -join ''
            }
        }
        TestScript = {
            if (($using:JavaFiles).count -ge 1) {
                Write-Verbose '.java or .jpp files = present'
                return $true
            }
            Write-Verbose '.java or .jpp files = absent'
            return $false
        }
        SetScript  = {
            foreach ($file in $using:JavaFiles) {
                remove-item "$file" -Force
            }
        }
    }

    # V-100139 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100139" [high]
    xWebAppPool "Setting AppPool (${SiteName} AppPool)" {
        Name                           = "${SiteName} AppPool"
        Ensure                         = 'Present'
        State                          = 'Started'
        autoStart                      = $true
        CLRConfigFile                  = ''
        enable32BitAppOnWin64          = $false
        enableConfigurationOverride    = $true
        managedPipelineMode            = 'Integrated'
        managedRuntimeLoader           = 'webengine4.dll'
        managedRuntimeVersion          = 'v4.0'
        passAnonymousToken             = $true
        startMode                      = 'OnDemand'
        queueLength                    = 1000
        cpuAction                      = 'NoAction'
        cpuLimit                       = 90000
        cpuResetInterval               = (New-TimeSpan -Minutes 5).ToString()
        cpuSmpAffinitized              = $false
        cpuSmpProcessorAffinityMask    = 4294967295
        cpuSmpProcessorAffinityMask2   = 4294967295
        # V-100139 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100139" [high] (identityType='ApplicationPoolIdentity' & loadUserProfile=$true)
        identityType                   = 'ApplicationPoolIdentity'
        loadUserProfile                = $true
        # V-100245 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100245" [medium]
        idleTimeout                    = (New-TimeSpan -Minutes 20).ToString()
        idleTimeoutAction              = 'Terminate'
        logEventOnProcessModel         = 'IdleTimeout'
        logonType                      = 'LogonBatch'
        manualGroupMembership          = $false
        maxProcesses                   = 1
        # V-100273 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100273" [medium]
        pingingEnabled                 = $true
        pingInterval                   = (New-TimeSpan -Seconds 30).ToString()
        pingResponseTime               = (New-TimeSpan -Seconds 90).ToString()
        setProfileEnvironment          = $false
        shutdownTimeLimit              = (New-TimeSpan -Seconds 90).ToString()
        startupTimeLimit               = (New-TimeSpan -Seconds 90).ToString()
        orphanActionExe                = ''
        orphanActionParams             = ''
        orphanWorkerProcess            = $false
        loadBalancerCapabilities       = 'HttpLevel'
        # V-100275 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100275" [medium]
        rapidFailProtection            = $true
        # V-100277 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100277" [medium]
        rapidFailProtectionInterval    = (New-TimeSpan -Minutes 5).ToString()
        rapidFailProtectionMaxCrashes  = 5
        autoShutdownExe                = ''
        autoShutdownParams             = ''
        disallowOverlappingRotation    = $false
        disallowRotationOnConfigChange = $false
        logEventOnRecycle              = 'Time,Requests,Schedule,Memory,IsapiUnhealthy,OnDemand,ConfigChange,PrivateMemory'
        # V-100267 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100267" [medium]
        restartMemoryLimit             = 4294967295
        # V-100269 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100269" [medium]
        restartPrivateMemoryLimit      = 4294967295
        # V-100265 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100265" [medium]
        restartRequestsLimit           = 100000
        # V-100271 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100271" [medium]
        restartTimeLimit               = (New-TimeSpan -Minutes 1440).ToString()
        restartSchedule                = @('00:00:00', '06:00:00', '18:00:00', '21:00:00')
    }

    # V-100141 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100141" [medium]
    # Develop a method to manage the hosted applications, either by moving its management functions off of the IIS 10.0 web server or by accessing the application's management via a uniquely assigned IP address.
    
    # V-100143 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100143" [medium]
    # V-100145 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100145" [medium]
    xWebConfigProperty 'V-100143,V-100145 - Server - system.web/sessionState/cookieless' {
        WebsitePath  = 'MACHINE/WEBROOT'
        Filter       = 'system.web/sessionState'
        PropertyName = 'cookieless'
        Value        = 'UseCookies'
        Ensure       = 'Present'
    }

    # V-100145 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100145" [medium]
    xWebConfigProperty 'V-100145 - Server - system.web/sessionState/timeout' {
        WebsitePath  = 'MACHINE/WEBROOT'
        Filter       = 'system.web/sessionState'
        PropertyName = 'timeout'
        Value        = '00:20:00'
        Ensure       = 'Present'
    }

    # V-100147 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100147" [medium]
    # Prepare documentation for disaster recovery methods for the IIS 10.0 web server in the event of the necessity for rollback.
    # Document and test the disaster recovery methods designed.

    # V-100149 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100149" [medium]
    xWebConfigProperty 'V-100149 - Server - system.web/machineKey/validation' {
        WebsitePath  = 'MACHINE/WEBROOT'
        Filter       = "system.web/machineKey"
        PropertyName = 'validation'
        Value        = 'HMACSHA256'
        Ensure       = 'Present'
    }

    # V-100151 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100151" [medium]
    xWebConfigProperty 'V-100151 - Server - system.webServer/directoryBrowse/enabled' {
        WebsitePath  = 'MACHINE/WEBROOT/APPHOST'
        Filter       = "system.webServer/directoryBrowse"
        PropertyName = 'enabled'
        Value        = $False
        Ensure       = 'Present'
    }

    # V-100153 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100153" [medium]
    Registry 'V-100153 - Server - HKLM:\SYSTEM\CurrentControlSet\Control\ContentIndex\Catalogs' {
        Ensure    = "Absent"
        Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ContentIndex\Catalogs"
        ValueName = ""
    }

    # V-100155 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100155" [medium]
    xWebConfigProperty 'V-100155 - Server - System.WebServer/HttpErrors/errorMode' {
        WebsitePath  = 'MACHINE/WEBROOT/APPHOST'
        Filter       = "System.WebServer/HttpErrors"
        PropertyName = 'errorMode'
        Value        = 'DetailedLocalOnly'
        Ensure       = 'Present'
    }

    # V-100161 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100161" [medium]
    # V-100249 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100249" [medium]
    # V-100163 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100163" [medium]
    NTFSAccessEntry "V-100163 - Server - Rights Management (${Drive}:\inetpub)" {
        Path              = "${Drive}:\inetpub"
        Force             = $true
        AccessControlList = @(
            NTFSAccessControlList {
                Principal          = "SYSTEM"
                ForcePrincipal     = $false
                AccessControlEntry = @(
                    NTFSAccessControlEntry {
                        AccessControlType = 'Allow'
                        FileSystemRights  = 'FullControl'
                        Inheritance       = 'This folder and subfolders'
                        Ensure            = 'Present'
                    }
                )               
            }
            NTFSAccessControlList {
                Principal          = "Administrators"
                ForcePrincipal     = $true
                AccessControlEntry = @(
                    NTFSAccessControlEntry {
                        AccessControlType = 'Allow'
                        FileSystemRights  = 'FullControl'
                        Inheritance       = 'This folder and subfolders'
                        Ensure            = 'Present'
                    }
                )               
            }
            NTFSAccessControlList {
                Principal          = "TrustedInstaller"
                ForcePrincipal     = $false
                AccessControlEntry = @(
                    NTFSAccessControlEntry {
                        AccessControlType = 'Allow'
                        FileSystemRights  = 'FullControl'
                        Inheritance       = 'This folder and files'
                        Ensure            = 'Present'
                    }
                )               
            }
            NTFSAccessControlList {
                Principal          = "ALL APPLICATION PACKAGES"
                ForcePrincipal     = $false
                AccessControlEntry = @(
                    NTFSAccessControlEntry {
                        AccessControlType = 'Allow'
                        FileSystemRights  = 'ReadandExecute'
                        Inheritance       = 'This folder and files'
                        Ensure            = 'Present'
                    }
                )               
            }
            NTFSAccessControlList {
                Principal          = "ALL RESTRICTED APPLICATION PACKAGES"
                ForcePrincipal     = $false
                AccessControlEntry = @(
                    NTFSAccessControlEntry {
                        AccessControlType = 'Allow'
                        FileSystemRights  = 'ReadandExecute'
                        Inheritance       = 'This folder and files'
                        Ensure            = 'Present'
                    }
                )               
            }
            NTFSAccessControlList {
                Principal          = "Users"
                ForcePrincipal     = $false
                AccessControlEntry = @(
                    NTFSAccessControlEntry {
                        AccessControlType = 'Allow'
                        FileSystemRights  = 'ReadandExecute'
                        Inheritance       = 'This folder and files'
                        Ensure            = 'Present'
                    }
                    NTFSAccessControlEntry {
                        AccessControlType = 'Allow'
                        FileSystemRights  = 'ListDirectory'
                        Inheritance       = 'This folder and files'
                        Ensure            = 'Present'
                    }
                )               
            }
        )
    }

    # V-100167 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100167" [medium]
    if (test-path "${Drive}:\windows\system32\inetsrv\InetMgr.exe") {
        # Create Script Block
    }

    # V-100171 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100171" [medium]
    WindowsFeatureSet 'V-100171 - Server - Disable Service (Print-Services)' {
        Ensure = 'Absent'
        Name   = @('Print-Services')
    }

    # V-100173 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100173" [medium]
    Registry 'V-100173 - Server - Set (HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\URIEnableCache)' {
        Ensure    = "Present"
        Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"
        ValueName = "URIEnableCache"
        ValueType = "DWord"
        ValueData = 1
    }
    Registry 'V-100173 - Server - Set (HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\ParametersUriMaxUriBytes)' {
        Ensure    = "Present"
        Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"
        ValueName = "UriMaxUriBytes"
        ValueType = "DWord"
        ValueData = 262144
    }
    Registry 'V-100173 - Server - Set (HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\UriScavengerPeriod)' {
        Ensure    = "Present"
        Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"
        ValueName = "UriScavengerPeriod"
        ValueType = "DWord"
        ValueData = 120
    }

    # V-100175 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100175" [medium]
    xWebConfigProperty 'V-100175 - Server - system.webServer/asp/session/keepSessionIdSecure' {
        WebsitePath  = 'MACHINE/WEBROOT/APPHOST'
        Filter       = 'system.webServer/asp/session'
        PropertyName = 'keepSessionIdSecure'
        Value        = $true
        Ensure       = 'Present'
    }

    # V-100177 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100177" [high]
    # V-100179 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100179" [medium]
    Registry 'V-100177,V-100179 - Server - Set (HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server\DisabledByDefault)' {
        Ensure    = "Present"
        Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
        ValueName = "DisabledByDefault"
        ValueType = "DWord"
        ValueData = 1
    }
    Registry 'V-100177,V-100179 - Server - Set (HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server\Enabled)' {
        Ensure    = "Present"
        Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
        ValueName = "Enabled"
        ValueType = "DWord"
        ValueData = 0
    }
    Registry 'V-100177,V-100179 - Server - Set (HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server\DisabledByDefault)' {
        Ensure    = "Present"
        Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"
        ValueName = "DisabledByDefault"
        ValueType = "DWord"
        ValueData = 1
    }
    Registry 'V-100177,V-100179 - Server - Set (HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server\Enabled)' {
        Ensure    = "Present"
        Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"
        ValueName = "Enabled"
        ValueType = "DWord"
        ValueData = 0
    }
    Registry 'V-100177 - Server - Set (HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server\DisabledByDefault)' {
        Ensure    = "Present"
        Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
        ValueName = "DisabledByDefault"
        ValueType = "DWord"
        ValueData = 0
    }
    Registry 'V-100177 - Server - Set (HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server\DisabledByDefault)' {
        Ensure    = "Present"
        Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server"
        ValueName = "DisabledByDefault"
        ValueType = "DWord"
        ValueData = 1
    }
    Registry 'V-100177 - Server - Set (HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server\Enabled)' {
        Ensure    = "Present"
        Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server"
        ValueName = "Enabled"
        ValueType = "DWord"
        ValueData = 0
    }
    Registry 'V-100177 - Server - Set (HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server\DisabledByDefault)' {
        Ensure    = "Present"
        Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"
        ValueName = "DisabledByDefault"
        ValueType = "DWord"
        ValueData = 1
    }
    Registry 'V-100177 - Server - Set (HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server\Enabled)' {
        Ensure    = "Present"
        Key       = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"
        ValueName = "Enabled"
        ValueType = "DWord"
        ValueData = 0
    }

    # V-100183 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100183" [medium]
    xWebConfigProperty 'V-100183 - Server - system.webServer/security/isapiCgiRestriction/notListedIsapisAllowed' {
        WebsitePath  = 'MACHINE/WEBROOT/APPHOST'
        Filter       = 'system.webServer/security/isapiCgiRestriction'
        PropertyName = 'notListedIsapisAllowed'
        Value        = $false
        Ensure       = 'Present'
    }
    xWebConfigProperty 'V-100183 - Server - system.webServer/security/isapiCgiRestriction/notListedCgisAllowed' {
        WebsitePath  = 'MACHINE/WEBROOT/APPHOST'
        Filter       = 'system.webServer/security/isapiCgiRestriction'
        PropertyName = 'notListedCgisAllowed'
        Value        = $false
        Ensure       = 'Present'
    }

    # V-100185 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100185" [medium]
    xWebConfigPropertyCollection "V-100185 - Server - system.web/authorization/authorization" {
        WebsitePath       = 'MACHINE/WEBROOT'
        Filter            = 'system.web/authorization'
        CollectionName    = '.'
        ItemName          = 'allow'
        ItemKeyName       = 'users'
        ItemKeyValue      = 'Administrator'
        ItemPropertyName  = 'verbs'
        ItemPropertyValue = ''
        Ensure            = 'Present'
    }

    # V-100187 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100187" [medium]
    xWebConfigProperty 'V-100187 - Server - system.applicationHost/sites/siteDefaults/limits/maxConnections' {
        WebsitePath  = 'MACHINE/WEBROOT/APPHOST'
        Filter       = 'system.applicationHost/sites/siteDefaults/limits'
        PropertyName = 'maxConnections'
        Value        = 4294967295
        Ensure       = 'Present'
    }

    # V-100189 | 'Microsoft IIS 10.0 Server' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_server/2020-03-24/finding/V-100189" [low]
    xWebConfigPropertyCollection "V-100189 - Server -  system.webServer/httpProtocol/Strict-Transport-Security (HSTS)" {
        WebsitePath       = 'MACHINE/WEBROOT/APPHOST'
        Filter            = 'system.webServer/httpProtocol'
        CollectionName    = 'customHeaders'
        ItemName          = 'add'
        ItemKeyName       = 'name'
        ItemKeyValue      = 'Strict-Transport-Security'
        ItemPropertyName  = 'value'
        ItemPropertyValue = 'max-age=63072000; includeSubDomains; preload'
        Ensure            = 'Present'
    }

    NTFSAccessEntry "Set Auth: (${Drive}:\inetpub\wwwroot)" {
        Path              = "${Drive}:\inetpub\wwwroot"
        Force             = $true
        AccessControlList = @(
            NTFSAccessControlList {
                Principal          = "System"
                ForcePrincipal     = $true
                AccessControlEntry = @(
                    NTFSAccessControlEntry {
                        AccessControlType = 'Allow'
                        FileSystemRights  = 'FullControl'
                        Inheritance       = 'This folder subfolders and files'
                        Ensure            = 'Present'
                    }
                )               
            }
            NTFSAccessControlList {
                Principal          = "Administrators"
                ForcePrincipal     = $false
                AccessControlEntry = @(
                    NTFSAccessControlEntry {
                        AccessControlType = 'Allow'
                        FileSystemRights  = 'FullControl'
                        Inheritance       = 'This folder subfolders and files'
                        Ensure            = 'Present'
                    }
                )               
            }
            NTFSAccessControlList {
                Principal          = "Users"
                ForcePrincipal     = $false
                AccessControlEntry = @(
                    NTFSAccessControlEntry {
                        AccessControlType = 'Allow'
                        FileSystemRights  = 'ReadandExecute'
                        Inheritance       = 'This folder subfolders and files'
                        Ensure            = 'Present'
                    }
                    NTFSAccessControlEntry {
                        AccessControlType = 'Allow'
                        FileSystemRights  = 'ListDirectory'
                        Inheritance       = 'This folder subfolders and files'
                        Ensure            = 'Present'
                    }
                )               
            }
            NTFSAccessControlList {
                Principal          = "IIS_IUSRS"
                ForcePrincipal     = $false
                AccessControlEntry = @(
                    NTFSAccessControlEntry {
                        AccessControlType = 'Allow'
                        FileSystemRights  = 'ReadandExecute'
                        Inheritance       = 'This folder subfolders and files'
                        Ensure            = 'Present'
                    }
                    NTFSAccessControlEntry {
                        AccessControlType = 'Allow'
                        FileSystemRights  = 'ListDirectory'
                        Inheritance       = 'This folder subfolders and files'
                        Ensure            = 'Present'
                    }
                )               
            } 
        )
    }

    # V-100263 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100263" [medium]
    Script 'Remove Extra Site(s)' {
        GetScript  = {
            Reset-IISServerManager -Confirm:$false -Verbose:$false
            $RemoveSites = Get-IISSite | Where-Object { $_.Name -ne "$($using:SiteName)" }
            if ( ($RemoveApps.count -eq 0) -and ($RemoveSites.count -eq 0) ) {
                Write-Verbose "AppPool(s) & Site(s) = Good"
                return $true
            }
            else {
                Write-Verbose "AppPool(s) & Site(s) = Bad"
                return $false
            }
        }
        TestScript = {

            $RemoveSites = Get-IISSite | Where-Object { $_.Name -ne "$($using:SiteName)" }
            if ( $RemoveSites.count -eq 0 ) {
                Write-Verbose "AppPool(s) & Site(s) = True"
                return $true
            }
            else {
                Write-Verbose "AppPool(s) & Site(s) = False"
                return $false
            }

        }
        SetScript  = {
            $RemoveSites = Get-IISSite | Where-Object { $_.Name -ne "$($using:SiteName)" }
            foreach ($Site in $RemoveSites) {
                Remove-Website -Name "$($Site.Name)" -Confirm:$false
                Write-Verbose "$($Site.Name) Removed"
            }

        }
    }

    xWebSite "Setting WebSite: ($SiteName)" {
        Ensure                  = "Present"
        Name                    = "$SiteName"
        SiteId                  = 1
        State                   = "Started"
        ServerAutoStart         = $true
        PhysicalPath            = "${Drive}:\inetpub\wwwroot"
        # V-100263 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100263" [medium]
        ApplicationPool         = "${SiteName} AppPool"
        ServiceAutoStartEnabled = $false
        PreloadEnabled          = $true
        EnabledProtocols        = "http,https"
        BindingInfo             = @(
            MSFT_xWebBindingInformation {
                # V-100253 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100253" [medium]
                Protocol  = 'http'
                Port      = '80'
                # V-100217 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100217" [medium]
                HostName  = "$env:computername"
                IPAddress = ((Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected" }).IPv4Address.IPAddress)
            }
            if ($CAC) {
                MSFT_xWebBindingInformation {
                    # V-100253 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100253" [medium]
                    Protocol  = 'https'
                    Port      = '443'
                    # V-100255 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100255" [medium]
                    CertificateSubject = ''
                    CertificateStoreName = 'My'
                    SSLFlags  = '1'
                    # V-100217 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100217" [medium]
                    HostName  = "$env:computername"
                    IPAddress = ((Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected" }).IPv4Address.IPAddress)
                }
            }
        )
        LogPath                 = "${Drive}:\inetpub\logs\$SiteName"
        # V-100203 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100203" [medium]
        # V-100205 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100205" [medium]
        LogFormat               = "W3C"
        # V-100199 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100199" [medium]
        LogTargetW3C            = "File,ETW"
        LogTruncateSize         = 4294967295
        # V-100251 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100251" [medium]
        LoglocalTimeRollover    = $true
        LogFlags = @('Date', 'Time', 'ClientIP', 'UserName', 'Method', 'UriQuery', 'HttpStatus', 'Referer', 'UserAgent')
        # V-100251 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100251" [medium]
        LogPeriod = 'Daily'
        LogCustomFields         = @(
            # V-100201 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100201" [medium]
            MSFT_xLogCustomFieldInformation {
                LogFieldName = "X-Forwarded-For"
                SourceName   = "X-Forwarded-For"
                SourceType   = "RequestHeader"
            }
            # V-100203 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100203" [medium]
            MSFT_xLogCustomFieldInformation {
                LogFieldName = "Warning"
                SourceName   = "Warning"
                SourceType   = "RequestHeader"
            }
            # V-100203 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100203" [medium]
            MSFT_xLogCustomFieldInformation {
                LogFieldName = "Connection"
                SourceName   = "Connection"
                SourceType   = "RequestHeader"
            }
            # V-100205 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100205" [medium]
            MSFT_xLogCustomFieldInformation {
                LogFieldName = "Authorization"
                SourceName   = "Authorization"
                SourceType   = "RequestHeader"
            }
            # V-100205 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100205" [medium]
            MSFT_xLogCustomFieldInformation {
                LogFieldName = "Content-Type"
                SourceName   = "Content-Type"
                SourceType   = "ResponseHeader"
            }
        )  
    }

    # V-100191 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100191" [medium]
    # V-100223 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100223" [medium]
    xWebConfigProperty "V-100191,V-100223 - Site - system.web/sessionState/mode" {
        WebsitePath  = "IIS:\Sites\$SiteName"
        Filter       = 'system.web/sessionState'
        PropertyName = 'mode'
        Value        = 'InProc'
        Ensure       = 'Present'
    }

    # V-100193 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100193" [medium]
    xWebConfigProperty "V-100191 - Site - system.web/sessionState/cookieless" {
        WebsitePath  = "IIS:\Sites\$SiteName"
        Filter       = 'system.web/sessionState'
        PropertyName = 'cookieless'
        Value        = 'UseCookies'
        Ensure       = 'Present'
    }

    if ($CAC -eq $true) {
        # V-100195 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100195" [medium]
        # V-100197 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100197" [medium]
        # V-100219 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100219" [medium]
        # V-100257 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100257" [medium]
        # V-100261 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100261" [medium]
        xSslSettings "V-100195 & V-100197" {
            Ensure   = 'Present'
            Name     = $SiteName
            Bindings = @('Ssl', 'SslNegotiateCert', 'SslRequireCert', 'Ssl128')
        }
    }
    else {
        xSslSettings "V-100195 & V-100197" {
            Ensure   = 'Present'
            Name     = $SiteName
            Bindings = ''
        }
    }

    # V-100207 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100207" [medium]
    xIisMimeTypeMapping 'V-100207 - Site - Remove Mime (.exe)' {
        Extension         = '.exe'
        MimeType          = 'application/octet-stream'
        Ensure            = 'Absent'
        ConfigurationPath = "IIS:\Sites\$SiteName"
    }
    xIisMimeTypeMapping 'V-100207 - Site - Remove Mime (.dll)' {
        Extension         = '.dll'
        MimeType          = 'application/x-msdownload'
        Ensure            = 'Absent'
        ConfigurationPath = "IIS:\Sites\$SiteName"
    }
    xIisMimeTypeMapping 'V-100207 - Site - Remove Mime (.com)' {
        Extension         = '.com'
        MimeType          = 'application/octet-stream'
        Ensure            = 'Absent'
        ConfigurationPath = "IIS:\Sites\$SiteName"
    }
    xIisMimeTypeMapping 'V-100207 - Site - Remove Mime (.bat)' {
        Extension         = '.bat'
        MimeType          = 'application/bat'
        Ensure            = 'Absent'
        ConfigurationPath = "IIS:\Sites\$SiteName"
    }    
    xIisMimeTypeMapping 'V-100207 - Site - Remove Mime (.csh)' {
        Extension         = '.csh'
        MimeType          = 'application/x-csh'
        Ensure            = 'Absent'
        ConfigurationPath = "IIS:\Sites\$SiteName"
    }

    # V-100209 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100209" [medium]
    # V-100211 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100211" [medium]
    # No black list

    # V-100213 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100213" [medium]
    WindowsFeature "V-100213 - Site - Disable WebDAV" {
        Name = 'Web-DAV-Publishing'
        Ensure = 'Absent'
    }

    # V-100215 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100215" [medium]
    xWebConfigProperty "V-100215 - Site - system.web/trust/level" {
        WebsitePath  = "IIS:\Sites\$SiteName"
        Ensure       = 'Present'
        Filter       = "system.web/trust"
        PropertyName = 'level'
        Value        = 'Full'
    }

    # V-100221 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100221" [high]
    if ($AuthMode -eq "Domain Users") {
        xWebConfigPropertyCollection 'IIS.Auth.Users' {
            WebsitePath       = "IIS:\Sites\$SiteName"
            Filter            = 'system.webServer/security'
            CollectionName    = 'authorization'
            ItemName          = 'add'
            ItemKeyName       = 'accessType'
            ItemKeyValue      = 'Allow'
            ItemPropertyName  = 'Users'
            ItemPropertyValue = 'Domain Users'
            Ensure            = 'Present'
        }
        xWebConfigProperty 'Disable anonymousAuthentication' {
            WebsitePath  = "IIS:\Sites\$SiteName"
            Filter       = 'system.webServer/security/authentication/anonymousAuthentication'
            PropertyName = 'enabled'
            Value        = $true
            Ensure       = 'Present'
        }
        xWebConfigProperty 'Enable windowsAuthentication' {
            WebsitePath  = "IIS:\Sites\$SiteName"
            Filter       = 'system.webServer/security/authentication/windowsAuthentication'
            PropertyName = 'enabled'
            Value        = $true
            Ensure       = 'Present'
        }
        xWebConfigProperty 'Enable windowsAuthentication' {
            WebsitePath  = "IIS:\Sites\$SiteName"
            Filter       = 'system.webServer/security/authentication/basicAuthentication'
            PropertyName = 'defaultLogonDomain'
            Value        = "$Domain"
            Ensure       = 'Present'
        }
    }
    if ($AuthMode -eq "Anonymous") {
        xWebConfigPropertyCollection 'IIS.Auth.Users' {
            WebsitePath       = "IIS:\Sites\$SiteName"
            Filter            = 'system.webServer/security'
            CollectionName    = 'authorization'
            ItemName          = 'add'
            ItemKeyName       = 'accessType'
            ItemKeyValue      = 'Allow'
            ItemPropertyName  = 'Users'
            ItemPropertyValue = '*'
            Ensure            = 'Present'
        }
        xWebConfigProperty 'IIS.Auth.anonymous-enabled' {
            WebsitePath  = "IIS:\Sites\$SiteName"
            Filter       = "system.webServer/security/authentication/anonymousAuthentication"
            PropertyName = 'enabled'
            Value        = $true
            Ensure       = 'Present'
        }
        xWebConfigProperty 'IIS.Auth.anonymous-apppool' {
            WebsitePath  = "IIS:\Sites\$SiteName"
            Filter       = "system.webServer/security/authentication/anonymousAuthentication"
            PropertyName = 'userName'
            Value        = ''
            Ensure       = 'Present'
        }
        xWebConfigProperty 'Enable windowsAuthentication' {
            WebsitePath  = "IIS:\Sites\$SiteName"
            Filter       = 'system.webServer/security/authentication/windowsAuthentication'
            PropertyName = 'enabled'
            Value        = $false
            Ensure       = 'Present'
        }
    }

    # V-100225 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100225" [medium]
    # Partition Drive / Site Path dif from IIS service

    # V-100227 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100227" [medium]
    xWebConfigProperty "V-100227 - Site - system.webServer/security/requestFiltering/maxUrl" {
        WebsitePath  = "IIS:\Sites\$SiteName"
        Ensure       = 'Present'
        Filter       = "system.webServer/security/requestFiltering/requestLimits"
        PropertyName = 'maxUrl'
        Value        = '4096'
    }

    # V-100229 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100229" [medium]
    xWebConfigProperty "V-100229 - Site - system.webServer/security/requestFiltering/maxAllowedContentLength" {
        WebsitePath  = "IIS:\Sites\$SiteName"
        Ensure       = 'Present'
        Filter       = "system.webServer/security/requestFiltering/requestLimits"
        PropertyName = 'maxAllowedContentLength'
        Value        = '30000000'
    }

    # V-100231 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100231" [medium]
    xWebConfigProperty "V-100231 - Site - system.webServer/security/requestFiltering/requestLimits/maxQueryString" {
        WebsitePath  = "IIS:\Sites\$SiteName"
        Ensure       = 'Present'
        Filter       = "system.webServer/security/requestFiltering/requestLimits"
        PropertyName = 'maxQueryString'
        Value        = '2048'
    }

    # V-100233 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100233" [medium]
    xWebConfigProperty "V-100233 - Site - system.webServer/security/requestFiltering/allowHighBitCharacters" {
        WebsitePath  = "IIS:\Sites\$SiteName"
        Ensure       = 'Present'
        Filter       = "system.webServer/security/requestFiltering"
        PropertyName = 'allowHighBitCharacters'
        Value        = $false
    }

    # V-100235 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100235" [medium]
    xWebConfigProperty "V-100235 - Site - system.webServer/security/requestFiltering/allowDoubleEscaping" {
        WebsitePath  = "IIS:\Sites\$SiteName"
        Ensure       = 'Present'
        Filter       = "system.webServer/security/requestFiltering"
        PropertyName = 'allowDoubleEscaping'
        Value        = $false
    }

    # V-100237 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100237" [medium]
    xWebConfigProperty "V-100237 - Site - system.webServer/security/requestFiltering/fileExtensions/allowUnlisted" {
        WebsitePath  = "IIS:\Sites\$SiteName"
        Ensure       = 'Present'
        Filter       = "system.webServer/security/requestFiltering/fileExtensions"
        PropertyName = 'allowUnlisted'
        Value        = $false
    }

    # V-100239 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100239" [medium]
    xWebConfigProperty 'V-100239 - Site - system.webServer/directoryBrowse/enabled' {
        WebsitePath  = "IIS:\Sites\$SiteName"
        Filter       = "system.webServer/directoryBrowse"
        PropertyName = 'enabled'
        Value        = $False
        Ensure       = 'Present'
    }

    # V-100241 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100241" [medium]
    xWebConfigProperty "V-100241 - Site - System.WebServer/HttpErrors/errorMode" {
        WebsitePath  = "IIS:\Sites\$SiteName"
        Ensure       = 'Present'
        Filter       = "System.WebServer/HttpErrors"
        PropertyName = 'errorMode'
        Value        = 'DetailedLocalOnly'
    }

    # V-100243 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100243" [medium]
    xWebConfigProperty "V-100243 - Site - system.web/compilation/debug" {
        WebsitePath  = "IIS:\Sites\$SiteName"
        Ensure       = 'Present'
        Filter       = "system.web/compilation"
        PropertyName = 'debug'
        Value        = $false
    }

    # V-100247 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100247" [medium]
    xWebConfigProperty "V-100247 - Site - system.web/sessionState/timeout" {
        WebsitePath  = "IIS:\Sites\$SiteName"
        Filter       = 'system.web/sessionState'
        PropertyName = 'timeout'
        Value        = '00:05:00'
        Ensure       = 'Present'
    }

    # V-100259 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100259" [medium]
    xWebConfigProperty "V-100259 - Site - system.webServer/asp/session/keepSessionIdSecure" {
        WebsitePath  = "IIS:\Sites\$SiteName"
        Ensure       = 'Present'
        Filter       = "system.webServer/asp/session"
        PropertyName = 'keepSessionIdSecure'
        Value        = $true
    }

    # V-100261 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100261" [medium]
    xWebConfigProperty "V-100261 - Site - system.web/sessionState/compressionEnabled" {
        WebsitePath  = "IIS:\Sites\$SiteName"
        Ensure       = 'Present'
        Filter       = "system.web/sessionState"
        PropertyName = 'compressionEnabled'
        Value        = $false
    }

    # V-100279 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100279" [medium]
    # V-100281 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100281" [medium]
    # V-100283 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100283" [medium]
    # Application owner must review these. This is application specific

    # V-100285 | 'Microsoft IIS 10.0 Site' - "https://www.stigviewer.com/stig/microsoft_iis_10.0_site/2020-03-24/finding/V-100285" [medium]
    # Add Banner Application
}

IIS-10.0-STIG -OutputPath $mof_location
Start-DscConfiguration -Path $mof_location -Wait -Force -Verbose
# Clear Error State & Set Error Preferences
$Error.Clear()
$ErrorActionPreference = "stop"
$ErrVar = ""

$LogFile = $OutputDir + "\0_LOG_PAD_Results.txt"
$ErrorLogFile = $OutputDir + "\0_LOG_PAD_Error_Details.txt"
$startTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
Add-Content -Path $LogFile -Value "Remediation-PAD Script Started: $startTime"
Add-Content -Path $ErrorLogFile -Value "Remediation-PAD Script Started: $startTime"

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Output "Unable to import module ActiveDirectory! Ensure it is available on this system." -BackgroundColor Yellow -ForegroundColor Black
    Break
}

try {
    # $serversOuPath = 'OU=Servers,DC=powerlab,DC=local'
    # $servers = Get-ADComputer -SearchBase $serversOuPath -Filter * | Select-Object -ExpandProperty Name
    # $servers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name
#    $servers = Get-ADComputer -Filter * -Properties DNSHostName, Enabled, IPV4Address, Name, LastLogonDate, OperatingSystem, OperatingSystemVersion -ErrorVariable ErrVar -ErrorAction SilentlyContinue
    $servers = Get-ADComputer -Filter * -Properties *
    
    foreach ($server in $servers) {
        
        Write-Output "Start of foreach"

        $output = @{
            'ServerName'                  = $null
            'DNSHostName'                 = $null
            'IPAddress'                   = $null
            'OperatingSystem'             = $null
            'AvailableDriveSpace (GB)'    = $null
            'Memory (GB)'                 = $null
            'UserProfilesSize (MB)'       = $null
            'StoppedServices'             = $null
        }
        
        $output.ServerName = $server.Name
        $output.DNSHostName = $server.DNSHostName
        $output.IPAddress = $server.IPV4Address
        $output.OperatingSystem = $server.Caption
     
        Write-Output "Evaluating Host Name: "$output.ServerName
        Write-Output "Evaluating DNSHostName: "$output.DNSHostName
        Write-Output "Evaluating IPAddress: "$output.IPAddress
        Write-Output "Evaluating OperatingSystem: "$output.OperatingSystem      

        #    $ComputerSystem = $null
        #    $getCimInstParams = @{
        #        CimSession = New-CimSession -ComputerName $ipAddress
        #        $ComputerSystem  = Get-WmiObject -ComputerName $ipAddress -Class Win32_ComputerSystem
        #        $ComputerSystem = Get-CimInstance -ComputerName $ipAddress -ClassName Win32_OperatingSystem
        #    }
        #    $output.'UserProfilesSize (MB)' = (Get-ChildItem -Path "\\$server\c$\Users\" -File | Measure-Object -Property Length -Sum).Sum
        #    $output.'AvailableDriveSpace (GB)' = [Math]::Round(((Get-CimInstance @getCimInstParams -ClassName Win32_LogicalDisk).FreeSpace / 1GB),1)
        #    $output.'OperatingSystem' = (Get-CimInstance @getCimInstParams -ClassName Win32_OperatingSystem).Caption
        #    $output.'Memory (GB)' = (Get-CimInstance @getCimInstParams -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum /1GB
        #    $output.'IPAddress' = (Get-CimInstance @getCimInstParams -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = 'True'").IPAddress[0]
        #    $output.StoppedServices = (Get-Service -ComputerName $server | Where-Object { $_.Status -eq 'Stopped' }).DisplayName
        #    Remove-CimSession -CimSession $getCimInstParams.CimSession
        [pscustomobject]$output
    }
} catch {
    Write-Output "Unable to execute Get-ADComputer PowerShell command!" -BackgroundColor Yellow -ForegroundColor Black
}


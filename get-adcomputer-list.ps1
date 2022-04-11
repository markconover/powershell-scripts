<#
.SYNOPSIS

Pulls a list of computer objects from AD and outputs list to ".csv" file

.DESCRIPTION

    Script will scan AD Domain Computers for alive hosts
    Writes out status to screen and lists of hosts to CSV files
    
.PARAMETER None

.EXAMPLE
    #The following will run and output all collected data to directory specified
    .\get-adcomputer-list.ps1 -OutputDir 'C:\ADComputerOutput\'

.EXAMPLE 
    #The following example will simply prompt you for an output directory
    .\get-adcomputer-list.ps1

Version 20220406-01
PowerShell v2.0 compatible version - works with PS v2.0 and above
#>

param (
    [string]$OutputDir = (Read-Host prompt 'Output Path (e.g. "c:\temp")')
)

# Clear Error State & Set Error Preferences
$OldErrorState = $ErrorActionPreference
$Error.Clear()
$ErrorActionPreference = "Stop"

New-Variable ErrorText
If (-Not (Test-Path -Path $OutputDir -PathType Container)) {
    $ErrorText = $OutputDir + " is not a valid directory. "
} Else {
    $OutputDir = (Get-item $OutputDir).FullName.Trim('\')
}
If ($ErrorText) {
    Write-Host $ErrorText
    Exit
}

$LogFile = $OutputDir + "\0_LOG_Get-ADComputer-List_Results.txt"
$ErrorLogFile = $OutputDir + "\0_LOG_Get-ADComputer-List_Error_Details.txt"

$startTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
Add-Content -Path $LogFile -Value "Get-ADComputer List Script Started: $startTime"
Add-Content -Path $ErrorLogFile -Value "Get-ADComputer List Script Started: $startTime"

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
If (-Not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    Write-Host 'PowerShell session is not elevated! Please re-run from a elevated session.' -BackgroundColor Yellow -ForegroundColor Black
    Exit
}

$version = $PSVersionTable.PSVersion.Major
If ($version -gt 2){
    $compInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $compInfo2 = Get-CimInstance -ClassName CIM_ComputerSystem
} Else {
    $compInfo = Get-WMIObject -Class Win32_OperatingSystem
    $compInfo2 = Get-WMIObject -Class CIM_ComputerSystem
}
$fqdn = ($compInfo2.DNSHostName + '.' + $compInfo2.Domain)
Add-Content -Path $LogFile -Value "----------------------------------------------------"
Add-Content -Path $LogFile -Value "PowerShell Version: $version"
Add-Content -Path $LogFile -Value "Operating System: $($compInfo.Caption)"
Add-Content -Path $LogFile -Value "Computer: $fqdn"
Add-Content -Path $LogFile -Value "User: $env:USERDNSDOMAIN\$env:USERNAME"

If ($version -le 5){
    $(Get-Culture).DateTimeFormat.ShortDatePattern = 'yyyy-MM-dd'
} ElseIf ($version -ge 7){
    $currentThread = [System.Threading.Thread]::CurrentThread
    $culture = [CultureInfo]::InvariantCulture.Clone()
    $culture.DateTimeFormat.ShortDatePattern = 'yyyy-MM-dd'
    $currentThread.CurrentCulture = $culture
    $currentThread.CurrentUICulture = $culture
} Else {
    Write-Host "Unsupported PowerShell Version!" -BackgroundColor Yellow -ForegroundColor Black
    Exit
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Host "Unable to import module ActiveDirectory! Ensure it is available on this system." -BackgroundColor Yellow -ForegroundColor Black
    Break
}
try {
    Import-Module GroupPolicy -ErrorAction Stop
} catch {
    Write-Host "Unable to import module GroupPolicy! Ensure it is available on this system." -BackgroundColor Yellow -ForegroundColor Black
    Break
}
$ForestInfo = Get-ADForest -Current LocalComputer
$DomainInfo = Get-ADDomain -Current LocalComputer
$SearchBase = $DomainInfo.DistinguishedName
Add-Content -Path $LogFile -Value "Domain FQDN: $($DomainInfo.DNSRoot)"
Add-Content -Path $LogFile -Value "Domain NetBIOS: $($DomainInfo.NetBIOSName)"
Add-Content -Path $LogFile -Value "----------------------------------------------------"
If ($DomainInfo.DomainSID.GetType().Name -eq 'String'){
    $DomainSID = $DomainInfo.DomainSID
} Else {
    $DomainSID = ($DomainInfo | Select-Object -ExpandProperty DomainSID).Value
}
$ChildDomainStatus = foreach ($child in $DomainInfo.ChildDomains){
    If ((Test-Netconnection $child -Port 389).TcpTestSucceeded){
        New-Object -TypeName PSObject -Property @{
            DomainName = $child
            Online = $True
        }
    } Else {
        New-Object -TypeName PSObject -Property @{
            DomainName = $child
            Online = $False
        }
    }
}
$Groups = [PSObject] @{
    "Domain Admins" = $DomainSID+"-512"
    "Enterprise Admins" = $DomainSID+"-519"
    "Schema Admins" = $DomainSID+"-518"
    "Administrators" = "S-1-5-32-544"
    "Account Operators" = "S-1-5-32-548"
    "Backup Operators" = "S-1-5-32-551"
    "Cert Publishers" = $DomainSID+"-517"
    "Print Operators" = "S-1-5-32-550"
    "Server Operators" = "S-1-5-32-549"
    "Replicator" = "S-1-5-32-552"
    "Group Policy Creator Owners" = $DomainSID+"-520"
    "Denied RODC Password Replication Group" = $DomainSID+"-572"
    "Distributed COM Users" = "S-1-5-32-562"
}
$additionalGroups = 'DNSAdmins'
foreach ($grp in $additionalGroups){
    try {$grpInfo = Get-ADGroup $grp}catch{}
    if ($grpInfo){
        $Groups.Add($grpInfo.Name,$grpInfo.sid)
        Clear-Variable grpInfo
    }
}

# Functions
function LogProgress ([switch]$Failure, [switch]$Success, [switch]$Skipped, $ProgressID, $CheckID, $CheckName, $ErrVar){
    If ($Failure){
        Write-Progress -Id $ProgressID -Activity "$CheckID - Failure - $CheckName" -Status "Failed" -CurrentOperation ""
        Add-Content -Path $LogFile -Value "$CheckID - Failure - $CheckName"
        if ($ErrVar) {Add-Content -Path $ErrorLogFile -Value "Check $CheckID :  $ErrVar"}
    } ElseIf ($Success){
        if ($ErrVar) {Add-Content -Path $ErrorLogFile -Value "Check $CheckID :  $ErrVar"}
        Write-Progress -Id $ProgressID -Activity "$CheckID - Complete - $CheckName" -Status "Complete" -CurrentOperation "" 
        Add-Content -Path $LogFile -Value "$CheckID - Success - $CheckName"
    } ElseIf ($Skipped){
        if ($ErrVar) {Add-Content -Path $ErrorLogFile -Value "Check $CheckID :  $ErrVar"}
        Write-Progress -Id $ProgressID -Activity "$CheckID - Skipped - $CheckName" -Status "Skipped" -CurrentOperation ""
        Add-Content -Path $LogFile -Value "$CheckID - Skipped - $CheckName"
    }
}

# Get-ADComputer List
$CheckID = 'Get-ADComputer List'
$CheckName = "Get-ADComputer List"
$OutFile = "$CheckID-AD-Computer_Listing.csv"
$ProgressID = 0
Write-Progress -Id $ProgressID -Activity "$CheckID - $CheckName" -Status "Running" -CurrentOperation "Collecting Info"

# Get Local Host Information
$LocalIPAddresses = Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPAddress
$ComputerName = $env:COMPUTERNAME

# Define empty arrays
$Unavailable = @()

Try
{
    $ProgParams = @{
        'Id' = $ProgressID
        'Activity' = "$CheckID - $CheckName"
        'Status' = 'Running'
        'CurrentOperation' = "Retrieving results & writing output to $OutputDir\$OutFile"
    }
    Write-Progress @ProgParams
    
    # Get AD Domain Computers
    $attributes = 'Name','DisplayName','DNSHostName','IPv4Address','Enabled','Description','DistinguishedName','CanonicalName','SamAccountName','isCriticalSystemObject','OperatingSystem','OperatingSystemServicePack','OperatingSystemVersion','ObjectClass','ObjectGUID','whenCreated','whenChanged','PasswordLastSet','userAccountControl','SID','UserPrincipalName','LastLogonDate'

    $compobjects = Get-ADComputer -Filter * -Property $attributes -ErrorVariable ErrVar -ErrorAction SilentlyContinue
    
    if ($ErrVar) {Add-Content -Path $ErrorLogFile -Value "$($CheckID): $ErrVar"}
    
    Write-Host "Inside the Tryy - Get-ADComputer-List"
    Write-Host "ErrVar is: $ErrVar"
    
    $compobjects | Export-Csv -path $OutputDir\$OutFile -NoTypeInformation -Encoding utf8
    
    $NumIPs = $compobjects.Count
    Write-Host "Inside the Tryy - before foreachh - Get-ADComputer-List"
    Write-Host "Inside the Tryy - before foreachh - Get-ADComputer-List - NumIPs count is: $NumIPs"
    Write-Host "ErrVar is: $ErrVar"     
    
 <#    # Loop through each IP Address in the range
    ForEach ($compobject in $compobjects) {
        Write-Host "Inside the Tryy - Start of the foreachh - Get-ADComputer-List"
        Write-Host "ErrVar is: $ErrVar"     

        # Get the IP Address from the computer object
        $ipAddress = $compobject.IPV4Address
        
        $Msg = "Evaluating: " + $ipAddress
        Write-Host $Msg

        # Skip IP Address if it is the same as the host we're running from
        $IsLocalIP = $LocalIPAddresses.IPAddress.Contains($ipAddress)
        If (-Not $IsLocalIP) {
            
            Write-Host "Inside the Tryy - foreachh - start of if not localip - Get-ADComputer-List"
            Write-Host "ErrVar is: $ErrVar"     
            
            $isAlive = $False
            
            # Test the connection to the target IP address
            # Returns $True if target IP address responds to a ping
            Try {
                $isAlive = Test-Connection -ComputerName $ipAddress -Quiet -Count 2 -ErrorVariable ErrVar -ErrorAction SilentlyContinue
            } Catch [System.Net.NetworkInformation.PingException] {
                Write-Host "isAlive - Inside the catchh ping exception - Get-ADComputer-List"
                Write-Host "ErrVar is: $ErrVar"
            } Catch {
                Write-Host "isAlive - Inside the catchh unknown exception - Get-ADComputer-List"
                Write-Host "ErrVar is: $ErrVar"
            }
            
            Write-Host "Before isAlive equal to True if statement - Get-ADComputer-List"
            Write-Host "ErrVar is: $ErrVar"

            # If the target responds, continue
            If ($isAlive -eq $True) {
                Write-Host "isAlive is true"
                
                $Msg = "`t" + $ipAddress + " is alive"
                Write-Host $Msg

            } Else {
                Write-Host "isAlive is false"

                $Msg = "`t" + $ipAddress + " is NOT alive"
                Write-Host $Msg

                # Add this machine information to the array
                $Unavailable += $ipAddress
            }
        }
        
        Write-Host "Inside the Tryy - At end of the foreachh - Get-ADComputer-List"
        Write-Host "Finished-Evaluating: " + $ipAddress
        Write-Host "ErrVar is: $ErrVar"
    } #>
    
    Write-Host "Inside the Tryy - End of Tryy - Get-ADComputer-List"
    Write-Host "ErrVar is: $ErrVar"
    LogProgress -ProgressID $ProgressID -CheckID $CheckID -CheckName $CheckName -ErrVar $ErrVar -Success
}
Catch
{
    Write-Host "Inside the catchh - Get-ADComputer-List"
    Write-Host "ErrVar is: $ErrVar"
    LogProgress -ProgressID $ProgressID -CheckID $CheckID -CheckName $CheckName -ErrVar $ErrVar -Failure
}

Write-Host "`n"
Write-Host "STATISTICS:"
Write-Host "Total IP Addresses evaluated    :" $NumIPs
#Write-Host "Not responding to ping          :" ($Unavailable.Count).ToString()

# Export objects to CSVs
#$Unavailable | Export-Csv -Path .\HostsUnavailable.csv -NoTypeInformation -Encoding utf8


# Get Scope of Exchange Servers
$CheckID = 'Get Scope of Exchange Servers'
$CheckName = "Get Scope of Exchange Servers"
$OutFile = "$CheckID-Get Scope of Exchange Servers_Listing.csv"
$ProgressID = 0
$Error.Clear()
Try
{
    Write-Progress -Id 0 -Activity "$CheckID - $CheckName" -Status "Running" -CurrentOperation "Retrieving results & writing output to $OutputDir\cmdlet_exchangeservers_1.csv"
    
    # get-ADComputer -Filter *  -Properties serviceprincipalname,name,distinguishedname -ErrorVariable ErrVar -ErrorAction SilentlyContinue | Where-Object {$_.serviceprincipalname -like '*exchange*'} | select-object name,distinguishedname | export-csv -path $OutputDir\cmdlet_exchangeservers_1.csv -NoTypeInformation
    get-ADComputer -Filter *  -Properties * -ErrorVariable ErrVar -ErrorAction SilentlyContinue | Where-Object {$_.serviceprincipalname -like '*exchange*'} | export-csv -path $OutputDir\cmdlet_exchangeservers_1.csv -NoTypeInformation    
    
    if ($ErrVar) {Add-Content -Path $ErrorLogFile -Value "$($CheckID): $ErrVar"}
    
    get-ADObject -LDAPFilter "(objectClass=msExchExchangeServer)" -SearchBase $Searchbase -ErrorVariable ErrVar -ErrorAction SilentlyContinue | Select-Object name,distinguishedname | export-csv -path $OutputDir\cmdlet_exchangeservers_2.csv -NoTypeInformation
    
    if ($ErrVar) {Add-Content -Path $ErrorLogFile -Value "$($CheckID): $ErrVar"}
    
    get-adtrust -filter * -ErrorVariable ErrVar -ErrorAction SilentlyContinue >> $OutputDir\cmdlet_ad-trusts.txt
    
    if ($ErrVar) {Add-Content -Path $ErrorLogFile -Value "$($CheckID): $ErrVar"}
    
    LogProgress -ProgressID $ProgressID -CheckID $CheckID -CheckName $CheckName -ErrVar $ErrVar -Success
}
Catch
{
    LogProgress -ProgressID $ProgressID -CheckID $CheckID -CheckName $CheckName -ErrVar $ErrVar -Failure
}


# Get Scope of Read Only Domain Controllers
$CheckID = 'Get Scope of Read Only Domain Controllers'
$CheckName = "Get Scope of Read Only Domain Controllers"
$OutFile = "$CheckID-Get Scope of Read Only Domain Controllers_Listing.csv"
$ProgressID = 0
$Error.Clear()
Try
{
    Write-Progress -Id 0 -Activity "$CheckID - $CheckName" -Status "Running" -CurrentOperation "Retrieving results & writing output to $OutputDir\cmdlet_RODCs_1.csv"
    
    get-addomaincontroller -filter {ISReadOnly -eq $True} -ErrorVariable ErrVar -ErrorAction SilentlyContinue | select-object Hostname,ComputerObjectDN,Site,OperatingSystem,IPv4Address,msDS-KrbTgtLink | export-csv -path $OutputDir\cmdlet_RODCs_1.csv -NoTypeInformation
    
    if ($ErrVar) {Add-Content -Path $ErrorLogFile -Value "$($CheckID): $ErrVar"}
    
    get-adcomputer -filter {primaryGroupID -eq 521} -Property name,DistinguishedName,OperatingSystem,IPv4Address,msDS-KrbTgtLink -ErrorVariable ErrVar -ErrorAction SilentlyContinue | select-object name,DistinguishedName,OperatingSystem,IPv4Address,msDS-KrbTgtLink | export-csv -path $OutputDir\cmdlet_RODCs_2.csv -NoTypeInformation
    
    if ($ErrVar) {Add-Content -Path $ErrorLogFile -Value "$($CheckID): $ErrVar"}
    
    LogProgress -ProgressID $ProgressID -CheckID $CheckID -CheckName $CheckName -ErrVar $ErrVar -Success
}
Catch
{  
    LogProgress -ProgressID $ProgressID -CheckID $CheckID -CheckName $CheckName -ErrVar $ErrVar -Failure
}


# Get Output of AD User Accounts
$CheckID = 'Get Output of AD User Accounts'
$CheckName = "Get Output of AD User Accounts"
$OutFile = "$CheckID-Get Output of AD User Accounts_Listing.csv"
$ProgressID = 0
$Error.Clear()
Try
{
    Write-Progress -Id 0 -Activity "$CheckID - $CheckName" -Status "Running" -CurrentOperation "Retrieving results & writing output to $OutputDir\AD-User_Listing.csv"
    Get-ADUser -filter * -properties name,samaccountname,sid,enabled,adminCount,DistinguishedName,PasswordNeverExpires,PasswordNotRequired,LastLogonDate,PasswordLastSet,created,Description,Manager,TrustedForDelegation,servicePrincipalNames -ErrorVariable ErrVar -ErrorAction SilentlyContinue | 
        select name,samaccountname,sid,enabled,adminCount,DistinguishedName,PasswordNeverExpires,PasswordNotRequired,LastLogonDate,PasswordLastSet,created,Description,Manager,TrustedForDelegation, @{name="servicePrincipalNames";expression={$_.servicePrincipalNames -join ";"}} |
        export-csv -path $OutputDir\AD-User_Listing.csv -NoTypeInformation
 
    if ($ErrVar) {Add-Content -Path $ErrorLogFile -Value "$($CheckID): $ErrVar"}
    
    LogProgress -ProgressID $ProgressID -CheckID $CheckID -CheckName $CheckName -ErrVar $ErrVar -Success
}
Catch
{
    LogProgress -ProgressID $ProgressID -CheckID $CheckID -CheckName $CheckName -ErrVar $ErrVar -Failure
}


$endTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$elapsed = [datetime]$endTime - [datetime]$startTime
Add-Content -Path $LogFile -Value "Get-ADComputer List Script Completed:  $endTime"
Add-Content -Path $LogFile -Value "Total Elapsed Time:  $elapsed"
Add-Content -Path $ErrorLogFile -Value "Get-ADComputer List Script Completed:  $endTime"
Add-Content -Path $ErrorLogFile -Value "Total Elapsed Time:  $elapsed"
$ErrorActionPreference = $OldErrorState
Write-Progress -Activity "Script has completed" -Status "Completed" -Completed

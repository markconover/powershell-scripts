<#
.SYNOPSIS
    Provides asset details in an exported asset inventory report

.DESCRIPTION
    This script will run various PowerShell cmdlets to retrieve asset details

    This script requires PowerShell 7+ and the following two PS Modules:
    ActiveDirectory
    GroupPolicy
    
    Script will scan AD Domain Computers for alive assets (hosts)
    For any alive asset (host), attempt to connect via WMI 
    Writes out to screen and exports asset details to CSV file

.PARAMETER
    None. This script does not require any parameters.

.INPUTS
    None.

.OUTPUTS
    None.
    
.EXAMPLE
    The following will run and output a CSV file
    .\Get-Computer-Asset-Details.ps1 -OutputDir "C:\TEMP"

.LINK
    No links

.NOTES
    Additional information about the function or script.
#>

param (
    [Parameter(Mandatory = $false)]
    [string]$OutputDir = (Read-Host prompt 'Output Path (e.g. "C:\TEMP")')
)

# Validate the parameter values
$ErrorText = ''
If (-Not (Test-Path -Path $OutputDir -PathType Container)) {
    $ErrorText = $OutputDir + " is not a valid directory. "
} Else {
    $OutputDir = (Get-item $OutputDir).FullName.Trim('\')
}
If ($ErrorText) {
    Write-Output $ErrorText
    Exit
}

# Verify running as Administrator user
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
If (-not $isAdmin) {
    Write-Output 'PowerShell session is not elevated! Please re-run from a elevated session.' -BackgroundColor Yellow -ForegroundColor Black
    Exit
}

# Set ErrorState
$OldErrorState = $ErrorActionPreference
$Error.Clear()
$ErrorActionPreference = "Stop"

# Setup Log File and ErrorLogFile
$LogFile = $OutputDir + "\0_LOG_GetComputerAssetDetails_Results.txt"
$ErrorLogFile = $OutputDir + "\0_LOG_GetComputerAssetDetails_Error_Details.txt"
$startTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
Add-Content -Path $LogFile -Value "GetComputerAssetDetails Script Started: $startTime"
Add-Content -Path $ErrorLogFile -Value "GetComputerAssetDetails Script Started: $startTime"

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
    Write-Output "Unsupported PowerShell Version!" -BackgroundColor Yellow -ForegroundColor Black
    Exit
}

# Import required PowerShell modules
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Output "Unable to import module ActiveDirectory! Ensure it is available on this system." -BackgroundColor Yellow -ForegroundColor Black
    Break
}
try {
    Import-Module GroupPolicy -ErrorAction Stop
} catch {
    Write-Output "Unable to import module GroupPolicy! Ensure it is available on this system." -BackgroundColor Yellow -ForegroundColor Black
    Break
}

# Write Progress 0%
$ScriptText = [System.Management.Automation.PsParser]::Tokenize((Get-Content "$($MyInvocation.MyCommand.Path)"), [ref]$null)
$CheckCount = ($ScriptText | Where-Object { $_.Type -eq 'Variable' -and $_.Content -eq 'ItemCount' -and $_.StartColumn -eq 1}).Count - 1
$ProgressID = 0
Write-Progress -Id $ProgressID -Activity "Initial Setup" -Status "Running" -CurrentOperation "Collecting Info" -PercentComplete (0 /  (($CheckCount) * 100))

# Output Active Directory (AD) Forest and Domain information
$ForestInfo = Get-ADForest -Current LocalComputer
$DomainInfo = Get-ADDomain -Current LocalComputer
$SearchBase = $DomainInfo.DistinguishedName
Add-Content -Path $LogFile -Value "Domain FQDN: $($DomainInfo.DNSRoot)"
Add-Content -Path $LogFile -Value "Domain NetBIOS: $($DomainInfo.NetBIOSName)"
Add-Content -Path $LogFile -Value "Script Reference: $($ScriptText[0].Content)"
Add-Content -Path $LogFile -Value "----------------------------------------------------"
If ($DomainInfo.DomainSID.GetType().Name -eq 'String'){
    $DomainSID = $DomainInfo.DomainSID
} Else {
    $DomainSID = ($DomainInfo | Select-Object -ExpandProperty DomainSID).Value
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


# Check 1 - Output of Computer Objects
$ItemCount = 1
$Error.Clear()
$CheckName = "Output of Computer Objects"
$OutFile = "cmdlet_AD-Computer_Listing.csv"
Try
{
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Running" -CurrentOperation "Retrieving results & writing output to $OutputDir\$OutFile" -PercentComplete (($ItemCount /  $CheckCount) * 100)
     
    # Enumerate all computers in the domain with all properties
    #$compobjects = Get-ADComputer -Filter * -Properties *

    # Enumerate all computers in the domain, but only query some of their properties
    # Get-ADComputer -Filter * -Properties DnsHostName,OperatingSystem,OperatingSystemServicePack | 
    # Format-List DNSHostName,DistinguishedName,OperatingSystem,OperatingSystemServicePack

    # Enumerate all computers in the 'Domain Controllers' OU with all properties:
    # Get-ADComputer -SearchBase "OU=Domain Controllers,DC=testing,DC=local" -Filter * -Properties *

    $compobjects = Get-ADComputer -Filter * -Property Name,DNSHostName,Enabled,isCriticalSystemObject,ManagedBy,DisplayName,DistinguishedName,CanonicalName,ObjectCategory,ObjectClass,ObjectSID,OperatingSystem,OperatingSystemServicePack,OperatingSystemVersion,IPv4Address,Description,DisplayName,whenCreated,whenChanged,PasswordLastSet,userAccountControl,MemberOf,PrimaryGroup,adminCount
    
    # "Get-ADComputer" - Properties
    # PSComputerName
    # RunspaceId
    # PSShowComputerName
    # AccountExpirationDate
    # accountExpires
    # AccountLockoutTime
    # AccountNotDelegated
    # adminCount
    # AllowReversiblePasswordEncryption
    # AuthenticationPolicy
    # AuthenticationPolicySilo
    # BadLogonCount
    # CannotChangePassword
    # CanonicalName
    # Certificates
    # CN
    # codePage
    # CompoundIdentitySupported
    # countryCode
    # Created
    # createTimeStamp
    # Deleted
    # Description
    # DisplayName
    # DistinguishedName
    # DNSHostName
    # DoesNotRequirePreAuth
    # dSCorePropagationData
    # Enabled
    # HomedirRequired
    # HomePage
    # instanceType
    # IPv4Address
    # IPv6Address
    # isCriticalSystemObject
    # isDeleted
    # KerberosEncryptionType
    # LastBadPasswordAttempt
    # LastKnownParent
    # LastLogonDate
    # lastLogonTimestamp
    # localPolicyFlags
    # Location
    # LockedOut
    # ManagedBy
    # MemberOf
    # MNSLogonAccount
    # Modified
    # modifyTimeStamp
    # msDFSR-ComputerReferenceBL
    # msDS-SupportedEncryptionTypes
    # msDS-User-Account-Control-Computed
    # Name
    # nTSecurityDescriptor
    # ObjectCategory
    # ObjectClass
    # ObjectGUID
    # objectSid
    # OperatingSystem
    # OperatingSystemHotfix
    # OperatingSystemServicePack
    # OperatingSystemVersion
    # PasswordExpired
    # PasswordLastSet
    # PasswordNeverExpires
    # PasswordNotRequired
    # PrimaryGroup
    # primaryGroupID
    # PrincipalsAllowedToDelegateToAccount
    # ProtectedFromAccidentalDeletion
    # pwdLastSet
    # rIDSetReferences
    # SamAccountName
    # sAMAccountType
    # sDRightsEffective
    # serverReferenceBL
    # ServiceAccount
    # servicePrincipalName
    # ServicePrincipalNames
    # SID
    # SIDHistory
    # TrustedForDelegation
    # TrustedToAuthForDelegation
    # UseDESKeyOnly
    # userAccountControl
    # userCertificate
    # UserPrincipalName
    # uSNChanged
    # uSNCreated
    # whenChanged
    # whenCreated
      
    $compobjects | export-csv -path $OutputDir\$OutFile -NoTypeInformation -Encoding utf8
    
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Complete" -CurrentOperation ""
    Add-Content -Path $LogFile -Value "Check $ItemCount of $CheckCount - $CheckName - Success"
}
Catch
{
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Failed" -CurrentOperation ""
    Add-Content -Path $LogFile -Value "Check $ItemCount of $CheckCount - $CheckName - Failed"
}
$ItemCount++

# Check 2 - Forest Functional Level Information
$Error.Clear()
$CheckName = "Domain Functional Level Information"
$OutFile = "cmdlet_ad-forest-info.csv"
Try
{
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Running" -CurrentOperation "Retrieving results & writing output to $OutputDir\$OutFile" -PercentComplete (($ItemCount /  $CheckCount) * 100)
    
    Get-ADForest | Select-Object Name,ForestMode,DomainNamingMaster,SchemaMaster | Export-Csv -Path $OutputDir\$OutFile -NoTypeInformation -Encoding utf8
    
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Complete" -CurrentOperation ""
    Add-Content -Path $LogFile -Value "Check $ItemCount of $CheckCount - $CheckName - Success"
}
Catch
{
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Failed" -CurrentOperation ""
    Add-Content -Path $LogFile -Value "Check $ItemCount of $CheckCount - $CheckName - Failed"
}
$ItemCount++

# Check 3 - Domain Functional Level Information
$Error.Clear()
$CheckName = "Get Forest Functional Level"
$OutFile = "cmdlet_domain-functional-level.txt"
Try
{
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Running" -CurrentOperation "Retrieving results & writing output to $OutputDir\$OutFile" -PercentComplete (($ItemCount /  $CheckCount) * 100)
    
    get-addomain | select DistinguishedName,DomainMode >> $OutputDir\$OutFile
    
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Complete" -CurrentOperation ""
    Add-Content -Path $LogFile -Value "Check $ItemCount of $CheckCount - $CheckName - Success"
}
Catch
{
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Failed" -CurrentOperation ""
    Add-Content -Path $LogFile -Value "Check $ItemCount of $CheckCount - $CheckName - Failed"
}
$ItemCount++

# Check 4 - Listing of Domain Controllers
$Error.Clear()
$CheckName = "Listing of Domain Controllers"
$OutFile = "cmdlet_Domain-Controller-List.csv"
Try
{
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Running" -CurrentOperation "Retrieving results & writing output to $OutputDir\$OutFile" -PercentComplete (($ItemCount /  $CheckCount) * 100)
    
    $getdomain = [System.Directoryservices.Activedirectory.Domain]::GetCurrentDomain()
    $getdomain | ForEach-Object {$_.DomainControllers} | 
    ForEach-Object {
      $hEntry= [System.Net.Dns]::GetHostByName($_.Name)
      New-Object -TypeName PSObject -Property @{
          Name = $_.Name
          IPAddress = $hEntry.AddressList[0].IPAddressToString
     }
    } | Export-CSV -path $outputdir\$OutFile -NoTypeInformation -Encoding UTF8
    
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Complete" -CurrentOperation ""
    Add-Content -Path $LogFile -Value "Check $ItemCount of $CheckCount - $CheckName - Success"
}
Catch
{
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Failed" -CurrentOperation ""
    Add-Content -Path $LogFile -Value "Check $ItemCount of $CheckCount - $CheckName - Failed"
}
$ItemCount++

# Check 5 - Listing of All KRBTGT Accounts
$Error.Clear()
$CheckName = "Listing of All KRBTGT Accounts"
$OutFile = "cmdlet_KRBTGT-Accounts.csv"
Try
{
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Running" -CurrentOperation "Retrieving results & writing output to $OutputDir\$OutFile" -PercentComplete (($ItemCount /  $CheckCount) * 100)
    
    $ADForestRootDomain = (Get-ADForest).RootDomain
    $AllADForestDomains = (Get-ADForest).Domains
    $ForestKRBTGTInfo = @()
    ForEach ($AllADForestDomainsItem in $AllADForestDomains)
    {
        [string]$DomainDC = (Get-ADDomainController -Discover -Force -Service "PrimaryDC" -DomainName $AllADForestDomainsItem).HostName
        [array]$ForestKRBTGTInfo += Get-ADUser -filter {name -like "krbtgt*"} -Server $DomainDC -Prop Name,Created,logonCount,Modified,PasswordLastSet,PasswordExpired,msDS-KeyVersionNumber,CanonicalName,msDS-KrbTgtLinkBl
    }
    $ForestKRBTGTInfo | Select-Object Name,Created,logonCount,PasswordLastSet,PasswordExpired,msDS-KeyVersionNumber,msds-KrbTgtLinkBl,CanonicalName | Export-CSV -path $outputdir\$OutFile -NoTypeInformation -Encoding UTF8

    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Complete" -CurrentOperation ""
    Add-Content -Path $LogFile -Value "Check $ItemCount of $CheckCount - $CheckName - Success"
}
Catch
{
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Failed" -CurrentOperation ""
    Add-Content -Path $LogFile -Value "Check $ItemCount of $CheckCount - $CheckName - Failed"
}
$ItemCount++

# Check 6 - Output of AD User Accounts
$Error.Clear()
$CheckName = "Output of AD User Accounts"
$OutFile = "cmdlet_AD-User_Listing.csv"
Try
{
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Running" -CurrentOperation "Retrieving results & writing output to $OutputDir\$OutFile" -PercentComplete (($ItemCount /  $CheckCount) * 100)

    # Get-ADUser -Filter * -Properties * | export-csv -path $OutputDir\$OutFile -NoTypeInformation -Encoding utf8
    
    Get-ADUser -filter * -properties name,samaccountname,sid,enabled,adminCount,DistinguishedName,PasswordNeverExpires,PasswordNotRequired,LastLogonDate,PasswordLastSet,created,Description,Manager,TrustedForDelegation,servicePrincipalNames | 
        select name,samaccountname,sid,enabled,adminCount,DistinguishedName,PasswordNeverExpires,PasswordNotRequired,LastLogonDate,PasswordLastSet,created,Description,Manager,TrustedForDelegation, @{name=”servicePrincipalNames”;expression={$_.servicePrincipalNames -join “;”}} |
        Export-Csv -path $OutputDir\$OutFile -NoTypeInformation -Encoding utf8
    
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Complete" -CurrentOperation ""
    Add-Content -Path $LogFile -Value "Check $ItemCount of $CheckCount - $CheckName - Success"
}
Catch
{
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Failed" -CurrentOperation ""
    Add-Content -Path $LogFile -Value "Check $ItemCount of $CheckCount - $CheckName - Failed"
}
$ItemCount++

# Check 7 - Scope of Disabled Accounts
$Error.Clear()
$CheckName = "Scope of Disabled Accounts"
$OutFile = "cmdlet_Accounts-Disabled.csv"
Try
{
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Running" -CurrentOperation "Retrieving results & writing output to $OutputDir\$OutFile" -PercentComplete (($ItemCount /  $CheckCount) * 100)
    
    get-ADUser -Filter {Enabled -eq $false} | export-csv -path $OutputDir\$OutFile -NoTypeInformation -Encoding utf8
    
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Complete" -CurrentOperation ""
    Add-Content -Path $LogFile -Value "Check $ItemCount of $CheckCount - $CheckName - Success"
}
Catch
{
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Failed" -CurrentOperation ""
    Add-Content -Path $LogFile -Value "Check $ItemCount of $CheckCount - $CheckName - Failed"
}
$ItemCount++

# Check 8 - Scope of Inactive User Accounts
$Error.Clear()
$CheckName = "Scope of Inactive User Accounts"
$OutFile = "cmdlet_Inactive-UserAccounts-30Days.csv"
Try
{
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Running" -CurrentOperation "Retrieving results & writing output to $OutputDir\$OutFile" -PercentComplete (($ItemCount /  $CheckCount) * 100)
    
    $Inactive = (get-date).AddDays(-30)
    get-Aduser -filter {(LastLogonDate -le $Inactive) -AND (PasswordLastSet -le $Inactive) -AND (Enabled -eq $True)} -property SAMAccountName,DisplayName,LastLogonDate,PasswordLastSet,Description,Created,UserPrincipalName | select SamAccountName,DistinguishedName,Description,LastLogonDate,PasswordLastSet | Export-Csv -Path $OutputDir\$OutFile -NoTypeInformation -Encoding utf8
    
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Complete" -CurrentOperation ""
    Add-Content -Path $LogFile -Value "Check $ItemCount of $CheckCount - $CheckName - Success"
}
Catch
{
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Failed" -CurrentOperation ""
    Add-Content -Path $LogFile -Value "Check $ItemCount of $CheckCount - $CheckName - Failed"
}
$ItemCount++

# Check 9 - Scope of Inactive Computer Accounts
$Error.Clear()
$CheckName = "Scope of Inactive Computer Accounts"
$OutFile = "cmdlet_Inactive-ComputerAccounts-30Days.csv"
Try
{
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Running" -CurrentOperation "Retrieving results & writing output to $OutputDir\$OutFile" -PercentComplete (($ItemCount /  $CheckCount) * 100)
    
    $Inactive = (get-date).AddDays(-30)
    get-AdComputer -filter {(LastLogonDate -le $Inactive) -AND (PasswordLastSet -le $Inactive) -AND (Enabled -eq $True)} -property Name,IPv4Address,LastLogonDate,PasswordLastSet,Description,Created,DNSHostName | select SamAccountName,DistinguishedName,IPv4Address,LastLogonDate,PasswordLastSet | Export-Csv -Path $Outputdir\$OutFile -NoTypeInformation -Encoding utf8
    
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Complete" -CurrentOperation ""
    Add-Content -Path $LogFile -Value "Check $ItemCount of $CheckCount - $CheckName - Success"
}
Catch
{
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Failed" -CurrentOperation ""
    Add-Content -Path $LogFile -Value "Check $ItemCount of $CheckCount - $CheckName - Failed"
}
$ItemCount++

# Check 10 - Scope of User Accounts Not Requiring Password to be Set
$Error.Clear()
$CheckName = "Scope of User Accounts Not Requiring Password to be Set"
$OutFile = "cmdlet_UserAccounts-NoPassword.csv"
$OutFile2 = "cmdlet_UserAccounts-Enabled-NoPassword.csv" 
Try
{
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Running" -CurrentOperation "Retrieving results & writing output to $OutputDir\$OutFile" -PercentComplete (($ItemCount /  $CheckCount) * 100)   
    
    get-AdUser -Filter 'useraccountcontrol -band 32 -and samaccounttype -ne 805306370' -Properties useraccountcontrol | select-object Name,DistinguishedName | export-csv -path $OutputDir\$OutFile -NoTypeInformation -Encoding utf8
    
    get-ADUser -Filter 'useraccountcontrol -band 32 -and Enabled -eq $True' -Properties useraccountcontrol | select-object Name,DistinguishedName | export-csv -path $OutputDir\$OutFile2 -NoTypeInformation -Encoding utf8
    
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Complete" -CurrentOperation ""
    Add-Content -Path $LogFile -Value "Check $ItemCount of $CheckCount - $CheckName - Success"
}
Catch
{
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Failed" -CurrentOperation ""
    Add-Content -Path $LogFile -Value "Check $ItemCount of $CheckCount - $CheckName - Failed"
}
$ItemCount++

# Check 11 - Trusted Information
$Error.Clear()
$CheckName = "Trust Information"
$OutFile = "$cmdlet_ad-trusts-all.csv"
Try
{
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount" -Status "Running" -CurrentOperation "Retrieving results & writing output to $OutputDir\$OutFile" -PercentComplete (($ItemCount /  $CheckCount) * 100)
    
    If (!($DomainInfo)){
        $DomainInfo = Get-ADDomain
    }
    If (!($SearchBase)){
        $SearchBase = $DomainInfo.DistinguishedName
    }
    If (!($version)){
        $version = $PSVersionTable.PSVersion.Major
    }
    If (!($compInfo)){
        If ($version -gt 2){
            $compInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        } Else {
            $compInfo = Get-WMIObject -Class Win32_OperatingSystem
        }
    }
    Function Get-TrustType {
        Param (
            [Parameter(Mandatory = $True)]
            [int32]$Value
        )
        switch ($Value)
        {
            "1" {"Windows NT (Downlevel)"}
            "2" {"Active Directory (Uplevel)"}
            "3" {"Kerberos v5 REALM (Non-Windows environment)"}
            "4" {"DCE"}
            Default {"N/A"}
        }
    }
    Function Get-TrustDirection {
        Param(
            [Parameter(Mandatory = $True)]
            [int32]$Value
        )
        switch ($Value)
        {
            "1" {"Inbound"}
            "2" {"Outbound"}
            "3" {"Bi-directional"}
            Default {"N/A"}
        }
    }
    Function Get-TrustEncryption {
        Param (
            [int32]$Value
        )
        If (($null -eq $Value) -or ($Value -eq '')){
            return 'RC4 (Default)'
        } Else {
            $TrustEncryption = @()
            if($Value -band 0x00000001){$TrustEncryption+='CRC'}
            if($Value -band 0x00000002){$TrustEncryption+='MD5'}
            if($Value -band 0x00000004){$TrustEncryption+='RC4'}
            if($Value -band 0x00000008){$TrustEncryption+='AES128'}
            if($Value -band 0x00000010){$TrustEncryption+='AES256'}
            return $TrustEncryption
        }
    }
    $params = @{
        Class = 'Microsoft_DomainTrustStatus'
        Namespace = 'root\MicrosoftActiveDirectory'
    }
    If ($version -gt 2){
        If ($compInfo.ProductType -eq 2){
            $query = Get-CIMInstance @params -ErrorVariable TrustErr
        } Else {
            $query = Get-CIMInstance @params -ComputerName $DomainInfo.PDCEmulator -ErrorVariable TrustErr
        }
    } Else {
        If ($compInfo.ProductType -eq 2){
            $query = @(Get-WMIObject @params -ErrorVariable TrustErr)
        } Else {
            $query = @(Get-WMIObject @params -ComputerName $DomainInfo.PDCEmulator -ErrorVariable TrustErr)
        }
    }
    $ADTrustObjs = Get-ADObject -SearchBase "CN=System,$SearchBase" -Filter "ObjectClass -eq 'trustedDomain'" -Properties *
    if ($query){
        $Data = foreach ($trust in $query){
            $ADObj = $ADTrustObjs | Where-Object {$_.securityIdentifier.Value -eq $trust.SID}
            New-Object -TypeName PSObject -Property @{
                'Direction' = Get-TrustDirection $trust.TrustDirection
                'DisallowTransivity' = [Boolean]($trust.TrustAttributes -band 0x00000001)
                'DistinguishedName' = $ADObj.DistinguishedName
                'ForestTransitive' = [Boolean]($trust.TrustAttributes -band 0x00000008)
                'IntraForest' = [Boolean]($trust.TrustAttributes -band 0x000000020)
                'Name' = $ADObj.Name
                'ObjectClass' = $ADObj.ObjectClass
                'ObjectGUID' = $ADObj.ObjectGUID
                'SelectiveAuthentication' = [Boolean]($trust.TrustAttributes -band 0x000000010)
                'SIDFilteringForestAware' = [Boolean]($trust.TrustAttributes -band 0x000000040)
                'SIDFilteringQuarantined' = [Boolean]($trust.TrustAttributes -band 0x000000004)
                'Source' = $DomainInfo.DistinguishedName
                'Target' = $ADObj.trustPartner
                'TGTDelegation' = [Boolean]($trust.TrustAttributes -band 0x000000800)
                'TrustAttributes' = $trust.TrustAttributes
                'TrustType' = Get-TrustType $trust.TrustType
                'TrustIsOk' = $trust.TrustIsOk
                'SupportedEncryptionTypes' = [string](Get-TrustEncryption $ADObj.'msDS-SupportedEncryptionTypes')
                'RemoteDomainSID' = $trust.SID
            }
        }
        $Data |
            Select-Object Direction,DisallowTransivity,DistinguishedName,ForestTransitive,IntraForest,
            Name,ObjectClass,ObjectGUID,SelectiveAuthentication,SIDFilteringForestAware,
            SIDFilteringQuarantined,Source,Target,TGTDelegation,TrustAttributes,TrustType,
            TrustIsOk,SupportedEncryptionTypes,RemoteDomainSID |
            Export-Csv -Path $OutputDir\$OutFile -NoTypeInformation -Encoding utf8
    }
    
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Complete" -CurrentOperation ""
    Add-Content -Path $LogFile -Value "Check $ItemCount of $CheckCount - $CheckName - Success"
}
Catch
{
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Failed" -CurrentOperation ""
    Add-Content -Path $LogFile -Value "Check $ItemCount of $CheckCount - $CheckName - Failed"
}
$ItemCount++


$endTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$elapsed = [datetime]$endTime - [datetime]$startTime
Add-Content -Path $LogFile -Value "GetComputerAssetDetails Script Completed:  $endTime"
Add-Content -Path $LogFile -Value "Total Elapsed Time:  $elapsed"
Add-Content -Path $ErrorLogFile -Value "GetComputerAssetDetails Script Completed:  $endTime"
Add-Content -Path $ErrorLogFile -Value "Total Elapsed Time:  $elapsed"
$ErrorActionPreference = $OldErrorState
Write-Progress -Activity "Script has completed" -Status "Completed" -Completed

# Check to ensure path is valid
# Check - Forest Functional Level Information
# Check - Domain Functional Level Information
# Check - Trust Information
# Check - Scope of Exchange Servers
# Check - Scope of Read Only Domain Controllers
# Check - Listing of GPOs where inheritence is blocked
# Check - Listing of GPOs where "Authenticated Users" Group is not referenced for Security Filtering
# Check - Listing of Computer Accounts with the ManagedBy Attribute Configured
# Check - Fine-Grained Password Policies
# Check - Listing of Configured Groups, Scope, Category and SID
# Check - Scope of Privileged Groups
# Check - Scope of Mail-Enabled Privileged Accounts
# Check - Non-Computer Accounts with SPN
# Check - Scope of Protected Accounts - AdminSDHolder Attribute
# Check - Scope of Managed Service Accounts
# Check - Built In Admin Account Last Password Set
# Check - Scope of Protected Users Group
# Check - MS Exchange On-Prem Group Membership
# Check - Scope of Accounts Not Requiring Kerberos Pre-Auth
# Check - Scope of Accounts Using Kerberos DES Encryption
# Check - Scope of Accounts Where Password Does Not Expire
# Check - Scope of Accounts Where Password Is Not Required
# Check - Accounts with "Sensitive and Can/Cannot Be Delegated Attribute"
# Check - Non-Computer Accounts Configured for Unconstrained Delegation (Kerberos)"
# Check - Non-Computer Accounts Configured for Constrained Delegation (Kerberos)"
# Check - Non-Computer Accounts Configured for Constrained Delegation (Any Authentication Protocol)"
# Check - Accounts Configured to Allow Reversible Encryption"
# Check - Accounts Configured to Allow Reversible Encryption"
# Check - Scope of Disabled Accounts"
# Check - Scope of Inactive User Accounts"
# Check - Scope of Inactive Computer Accounts"
# Check - Scope of User Accounts Not Requiring Password to be Set"
# Check - Scope of Computer Accounts Not Requiring Password to be Set"
# Check - Interdomain Trust Accounts
# Check - Workstation Trust Accounts
# Check - Server Trust Accounts
# Check - DSRM Remote Login
# Check - Scope of accounts with SHA1 hashes stored in the "orclCommonAttribute" or "UserPassword" attributes
# Check - Scope of accounts with the confidential attributes set
# Check - Scope of accounts with SID History Attribute Set
# Check - Scope of accounts Where ACL Inheritence is Disabled
# Check - Number of Accounts That Can Be Added to Domain by Domain Users Group
# Check - Scope of Computer Accounts Created by Domain Users
# Check - Scope of Accounts with Delegation Permissions
# Check - Scope of Accounts with ability to modify AdminSDHolder Permissions (requires PS 5.0)
# Check - Domain Controller Ownership
# Check - Scope of Accounts with Cached Passwords on RODC
# Check - Listing of All Permissions of GPOs in Domain
# Check - Listing of Domain Controllers
# Check - Listing of All KRBTGT Accounts
# Check - Output of AD User Accounts
# Check - Unlinked GPOs
# Check - Scope of Accounts with AD Extended Rights Permissions
# Check - Scope of Accounts with DC Replication Permissions
# Check - Scope of Computer Accounts with Resource-Based Contrained Delegation Configured
# Check - Scope of User Accounts with Resource-Based Contrained Delegation Configured
# Check - Listing All GPOs for Domain
# Check - Listing of Domain Controllers with IP Address Associations
# Check - Output of Computer Objects
# Check - AD Recycle Bin Check
# Check - AD Site Information Check
# Check - Get LAPS Status of Computer Objects in the Domain
# Check - Get Elevated Site Level Permissions in the Domain
# Check - Get Get AdminSDHolder-Permissions in the Domain


# function Get-SslCertificate {
# function Get-AccessedFile{
# function Get-ActiveComputer{
# function Get-ActiveFile{
# function Get-ActiveUser{
# function Get-ChildItemLastAccessTime{
# function Get-ChildItemLastWriteTime{
# function Get-ComputerCurrentUser{
# function Get-ComputerDriveInformation{
# function Get-ComputerFailedLogonEvent{
# function Get-ComputerInformation{
# function Get-ComputerIPAddress{
# function Get-ComputerLastBootUpTime{
# function Get-ComputerLastLogonTime{
# function Get-ComputerMemory{
# function Get-ComputerModel{
# function Get-ComputerOS{
# function Get-ComputerPhysicalDiskInformation{
# function Get-ComputerProcessor{
# function Get-ComputerShareFolder{
# function Get-ComputerSoftware{
# function Get-ComputerSystemEvent{
# function Get-CredentialExportToXML{
# function Get-DHCPReservation{
# function Get-DirectorySize{
# function Get-DisabledComputer{
# function Get-DisabledUser{
# function Get-InactiveComputer{
# function Get-InactiveFile{
# function Get-InactiveUser{
# function Get-ItemLastAccessTime{
# function Get-ItemLastWriteTime{
# function Get-LargeFile{
# function Get-LockedOutUser{
# function Get-LockedOutUserEvent{
# function Get-OfflineComputer{
# function Get-OnlineComputer{
# function Get-OUComputer{
# function Get-OUUser{
# function Get-SubDirectorySize{
# function Get-UserActiveLogon{
# function Get-UserLastLogonTime{


# ---------------------------------------------------------
# Old Notes
# ---------------------------------------------------------
<# Enumerate all computers in the domain with all properties:
# Get-ADComputer -Filter * -Properties * 

Enumerate all computers in the domain, but only query some of their properties:
# Get-ADComputer -Filter * -Properties DnsHostName,OperatingSystem,OperatingSystemServicePack | 
# Format-List DNSHostName,DistinguishedName,OperatingSystem,OperatingSystemServicePack

Enumerate all computers in the 'Domain Controllers' OU with all properties:
# Get-ADComputer -SearchBase "OU=Domain Controllers,DC=testing,DC=local" -Filter * -Properties * 

Capture the names of all computers in the domain to an array of strings:
# $computers = Get-ADComputer -Filter * -Properties Name | ForEach-Object { $_.Name }

Capture the X.500 distinguished names of all computers in the domain to an array of strings:
# $computers = Get-ADComputer -Filter * -Properties DistinguishedName | ForEach-Object { $_.DistinguishedName }

Capture the DNS names of all computers in the domain to an array of strings, but
note that this requires a DNS query for every name, which may fail:
# $computers = Get-ADComputer -Filter * -Properties DnsHostName | ForEach-Object { $_.DNSHostName }
 #>


<# # Find users with AdminCount = 1:
Get-ADUser -Filter { AdminCount -eq 1 } -Properties * 
 #>

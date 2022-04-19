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
    .\Get-Computer-Asset-Details.ps1

.LINK
    No links

.NOTES
    Additional information about the function or script.
#>

param (
    [string]$OutputDir = (Read-Host prompt 'Output Path (e.g. "c:\temp")')
)

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

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
If (-Not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
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
$CheckCount = ($ScriptText | Where-Object { $_.Type -eq 'Variable' -and $_.Content -eq 'ItemCount' -and $_.StartColumn -eq 1}).Count
$ProgressID = 0
Write-Progress -Id $ProgressID -Activity "Initial Setup" -Status "Running" -CurrentOperation "Collecting Info" -PercentComplete (0 /  (($CheckCount) * 100))

# Check 1 - Output of Computer Objects
$ItemCount = 1
$Error.Clear()
$CheckName = "Output of Computer Objects"
$OutFile = "cmdlet_AD-Computer_Listing.csv"
Try
{
    Write-Progress -Id $ProgressID -Activity "Check $ItemCount of $CheckCount - $CheckName" -Status "Running" -CurrentOperation "Retrieving results & writing output to $OutputDir\$OutFile" -PercentComplete (($ItemCount /  $CheckCount) * 100)
    
    $compobjects = Get-ADComputer -Filter * -Property Name,DistinguishedName,ObjectSID,OperatingSystem,OperatingSystemServicePack,OperatingSystemVersion,IPv4Address,whenCreated,whenChanged,PasswordLastSet,userAccountControl
      
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
    
    Get-ADForest | Select-Object Name,ForestMode,DomainNamingMaster,SchemaMaster | Export-Csv -Path $OutputDir\$OutFile -NoTypeInformation
    
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
    
    Get-ADUser -filter * -properties name,samaccountname,sid,enabled,adminCount,DistinguishedName,PasswordNeverExpires,PasswordNotRequired,LastLogonDate,PasswordLastSet,created,Description,Manager,TrustedForDelegation,servicePrincipalNames | 
        select name,samaccountname,sid,enabled,adminCount,DistinguishedName,PasswordNeverExpires,PasswordNotRequired,LastLogonDate,PasswordLastSet,created,Description,Manager,TrustedForDelegation, @{name=”servicePrincipalNames”;expression={$_.servicePrincipalNames -join “;”}} |
        export-csv -path $OutputDir\$OutFile -NoTypeInformation
 
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
    
    get-ADUser -Filter {Enabled -eq $false} | export-csv -path $OutputDir\$OutFile -NoTypeInformation
    
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
    get-Aduser -filter {(LastLogonDate -le $Inactive) -AND (PasswordLastSet -le $Inactive) -AND (Enabled -eq $True)} -property SAMAccountName,DisplayName,LastLogonDate,PasswordLastSet,Description,Created,UserPrincipalName | select SamAccountName,DistinguishedName,Description,LastLogonDate,PasswordLastSet | Export-Csv -Path $OutputDir\$OutFile -NoTypeInformation
    
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
    get-AdComputer -filter {(LastLogonDate -le $Inactive) -AND (PasswordLastSet -le $Inactive) -AND (Enabled -eq $True)} -property Name,IPv4Address,LastLogonDate,PasswordLastSet,Description,Created,DNSHostName | select SamAccountName,DistinguishedName,IPv4Address,LastLogonDate,PasswordLastSet | Export-Csv -Path $Outputdir\$OutFile -NoTypeInformation
    
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
    
    get-AdUser -Filter 'useraccountcontrol -band 32 -and samaccounttype -ne 805306370' -Properties useraccountcontrol | select-object Name,DistinguishedName | export-csv -path $OutputDir\$OutFile -NoTypeInformation
    
    get-ADUser -Filter 'useraccountcontrol -band 32 -and Enabled -eq $True' -Properties useraccountcontrol | select-object Name,DistinguishedName | export-csv -path $OutputDir\$OutFile2 -NoTypeInformation
    
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

Import-Module -Name ActiveDirectory

Get-ADUser -Filter { AdminCount -eq 1 } -Properties * 
 #>

######################################################################

<# This is a template for creating an advanced function (aka, "script
cmdlet") in PowerShell 2.0 and later.  See the following help:

   get-help about_Functions_Advanced
   get-help about_Functions_Advanced_Methods
   get-help about_Functions_Advanced_Parameters
   get-help about_Functions_CmdletBindingAttribute
   get-help about_Functions_OutputTypeAttribute #>

######################################################################



# <#
# .SYNOPSIS
   # Short description of function

# .DESCRIPTION
   # Long description

# .EXAMPLE
   # Example of how to use this function

# .EXAMPLE
   # Another example of how to use this function

# .INPUTS
   # Inputs to this function, if any

# .OUTPUTS
   # Output from this function, if any

# .COMPONENT
   # The component this function belongs to

# .ROLE
   # The role this function belongs to

# .FUNCTIONALITY
   # The functionality that best describes this function

# .NOTES
   # General notes, author, version, licensing
# >
# function Verb-Noun
# {
    # [CmdletBinding(DefaultParameterSetName='Parameter Set 1', 
                  # SupportsShouldProcess=$true, 
                  # PositionalBinding=$false,
                  # HelpUri = 'http://www.sans.org/sec505',
                  # ConfirmImpact='Medium')]
    # [OutputType([String])]
    # Param
    # (
        # Param1 help description
        # [Parameter(Mandatory=$true, 
                   # ValueFromPipeline=$true,
                   # ValueFromPipelineByPropertyName=$true, 
                   # ValueFromRemainingArguments=$false, 
                   # Position=0,
                   # ParameterSetName='Parameter Set 1')]
        # [ValidateNotNull()]
        # [ValidateNotNullOrEmpty()]
        # [ValidateCount(0,5)]
        # [ValidateSet("List", "of", "valid", "arguments")]
        # [Alias("p1")] 
        # $Param1,

        # Param2 help description
        # [Parameter(ParameterSetName='Parameter Set 1')]
        # [AllowNull()]
        # [AllowEmptyCollection()]
        # [AllowEmptyString()]
        # [ValidateScript({ script block to validate arg, must return $true or $false })]
        # [ValidateRange(0,5)]
        # [int]
        # $Param2,

        # Param3 help description
        # [Parameter(ParameterSetName='Another Parameter Set')]
        # [ValidatePattern("regex pattern to match")]
        # [ValidateLength(0,15)]
        # [String]
        # $Param3
    # )

    # BEGIN
    # {
        # Optional BEGIN block executed first and only once.
    # }

    # PROCESS
    # {
        # PROCESS block executed for each piped-in object, if any,
        # or run only once if the function is the first command in
        # a statement or pipeline of commands.  The block is mandatory
        # if any parameter is set to accept ValueFromPipeline=$True.
    # }
    
    # END
    # {
        # Optional END block executed last and only once.
    # }
# }
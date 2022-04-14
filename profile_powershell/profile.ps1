# PowerShell - Profile Settings
# This is a customized version of Windows 10 All Hosts, All Users
# profile settings

# Set command prompt maximum history commands limit
$MaximumHistoryCount = 32700

function prompt {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal] $identity
  $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator

  $(if (Test-Path variable:/PSDebugContext) { '[DBG]: ' }
    elseif($principal.IsInRole($adminRole)) { "[ADMIN]: " }
    else { '' }
  ) + 'PS ' + $(Get-Location) +
    $(if ($NestedPromptLevel -ge 1) { '>>' }) + '> '
}

Set-PSReadLineOption -colors @{
  Operator           = 'Cyan'
  Parameter          = 'Cyan'
  String             = 'White'
}

$Env:PSModulePath = $Env:PSModulePath + ";C:\Program Files\PowerShell\Modules;c:\program files\powershell\7\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\windows\system32\WindowsPowerShell\v1.0\Modules;C:\Program Files (x86)\Universal\Modules"

Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine

$env:PSModulePath -split ';'   

# ---------------------------------------------------------
# Help - PowerShell Commands
# ---------------------------------------------------------
# Get-Help * -Parameter ComputerName
# Update-Help -Force -Verbose
# Save-Help -DestinationPath "<DESTINATION_PATH>" -Force -Verbose

# ---------------------------------------------------------
# Install PowerShell (and other packages)
# ---------------------------------------------------------
# References:
#   https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.2
#   https://docs.microsoft.com/en-us/powershell/
#   https://docs.microsoft.com/en-us/powershell/module/powershellget/install-module?view=powershell-7.2
#   https://docs.microsoft.com/en-us/powershell/scripting/samples/working-with-software-installations?view=powershell-7.2#listing-windows-installer-applications
#   https://github.com/PowerShell/PowerShellGet
#   https://www.powershellgallery.com/
#   https://docs.microsoft.com/en-us/learn/browse/?terms=PowerShell

# Set-ExecutionPolicy Unrestricted
# Update-Help -Force -Verbose
# Save-Help -DestinationPath "<DESTINATION_PATH>" -Force -Verbose
# notepad++ (Get-PSReadLineOption | select -ExpandProperty HistorySavePath)

# ---------------------------------------------------------
# Install - Chocolatey ("choco") - PowerShell Commands
# ---------------------------------------------------------
# Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
# choco install advanced-ip-scanner -y --force
# choco install angryip -y --force
# choco install curl -y --force
# choco install diff -y --force
# choco install grep -y --force
# choco install ip-query -y --force
# choco install jupyter-powershell -y --force
# choco install lansweeper -y --force
# choco install man -y --force
# choco install ndiff -y --force
# choco install nmap -y --force
# choco install oh-my-posh -y --force
# choco install openssl -y --force
# choco install pip -y --force
# choco install pip_search -y --force
# choco install poshgit -y --force
# choco install pslist -y --force
# choco install psreadline -y --force
# choco install python2 -y --force
# choco install python3 -y --force
# choco install sysinternals -y --force
# choco install version -y --force
# choco install which -y --force
# choco install zenmap -y --force

# ---------------------------------------------------------
# Install - "pip - PowerShell Commands
# ---------------------------------------------------------
# py -m pip install --upgrade pip --force
# py -m pip install pip_search -v
# py -m pip install --user pipx
# py -m pip install requests
# pip install *bigquery*
# pip install google-cloud-bigquery
# pip install google-cloud-storage
# pip install --upgrade google-api-python-client
# pip install --upgrade google-auth-oauthlib
# pip install --upgrade google-cloud-bigquery
# pip install --upgrade google-cloud-storage -v
# pip install --upgrade setuptools
# pip install BeautifulSoup
# pip install SQLAlchemy
# pip install bottle
# pip install google-api-utils
# pip install google-cloud
# pip install google-drive-api
# pip install google_documents
# pip install google_spreadsheet
# pip install ip-query -v
# pip install jupyter-console
# pip install man
# pip install matplotlib 
# pip install notebook
# pip install numpy
# pip install openpyxl
# pip install pandas
# pip install psreadline
# pip install py2exe
# pip install pyscreenshot
# pip install pyserial
# pip install pyusb
# pip install pywin32
# pip install pyxlsb
# pip install uspp
# pip install which
# pip install xlsxwriter
# pip install zenmap

# ---------------------------------------------------------
# "Install-Module" - PowerShell Commands
# ---------------------------------------------------------
# Install-Module -Name PowerShellGet -Force -Verbose
# Install-Module PSReadLine -Force -Verbose
# Install-Module PSScriptTools -Force -Verbose
# Install-Module pester -SkipPublisherCheck -Force -Verbose
# Install-Module -Name ActiveDirectoryTools -Force -Verbose
# Update-Module -Verbose
# Get-Module -ListAvailable -All

# ---------------------------------------------------------
# "Install-Script" - PowerShell Commands
# ---------------------------------------------------------
# Install-Script -Name CertificateScanner
# Install-Script -Name Download-AllGalleryModules
# Install-Script -Name Get-ComputerInfo
# Install-Script -Name GettingTLSVersionsFromAllComputers
# Install-Script -Name PSGalleryInfo
# Install-Script -Name PSGalleryModule
# Install-Script -Name set-nsssl

# ---------------------------------------------------------
# PowerShell Commands - Notes
# ---------------------------------------------------------
# Get-PSRepository | Format-List

# ---------------------------------------------------------
# Modules - PowerShell Commands
# ---------------------------------------------------------
# Find-Module *install*
# Find-Module -Repository PSGallery
# Find-Module -Name *pip*
# Find-Module nx* | Format-Table Version, Name, Description
# Find-Module nx* | Install-Module -Force
# Find-Module -Tag 'Active Directory', 'ActiveDirectory', 'Active', 'Directory', 'AD'
# Get-Command -Name '*Process'
# Get-Module -ListAvailable -All -Verbose
# Get-Module -ListAvailable | where { $_.path -match "System32" }
# Install-Module -Name PowerShellGet -Force -Verbose
# Install-Module PSReadLine -Force -Verbose
# Install-Module PSScriptTools -Force -Verbose
# Install-Module pester -SkipPublisherCheck -Force -Verbose
# Install-Module -Name ActiveDirectoryTools -Force -Verbose
# Update-Module -Verbose
# Get-Module -ListAvailable -All

# ---------------------------------------------------------
# Scripts - PowerShell Commands
# ---------------------------------------------------------
# Find-Script *install*
# Find-Script -Name *pip*
# Install-Script -Name CertificateScanner
# Install-Script -Name Download-AllGalleryModules
# Install-Script -Name Get-ComputerInfo
# Install-Script -Name GettingTLSVersionsFromAllComputers
# Install-Script -Name PSGalleryInfo
# Install-Script -Name PSGalleryModule
# Install-Script -Name set-nsssl

# ---------------------------------------------------------
# Commands - PowerShell Commands
# ---------------------------------------------------------
# Get-Command -Module PowerShellGet | Format-Wide -Column 3
# Get-Command -ParameterName Cimsession
# Get-Command -ParameterName ComputerName

# ---------------------------------------------------------
# Sort / Filter - PowerShell Commands
# ---------------------------------------------------------
# Find-Module -Name *session* -Repository PSGallery | Sort-Object -Property Name | Format-Table -Property Name -HideTableHeaders
# Get-Process | sort -Descending ws | select -First 3
# $servers = Get-ADComputer -Filter * -Properties *
# Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "DHCPEnabled = $true"
# Get-WmiObject -Class Win32_UserAccount -Namespace "root\cimv2" -Filter "LocalAccount='$True'"
# Get-ChildItem -Path C:\ -Filter *.sys -Force
# Get-CimInstance -ClassName Win32_Process -Filter "Name='calculator.exe'"

# Get-ChildItem hklm:\software | Get-Member ps*

# ---------------------------------------------------------
# Active Directory (AD) - PowerShell Commands
# ---------------------------------------------------------
# $ForestInfo = Get-ADForest -Current LocalComputer
# $DomainInfo = Get-ADDomain -Current LocalComputer
# Show-DomainTree
# try {
    # Import-Module ActiveDirectory -ErrorAction Stop
# } catch {
    # Write-Host "Unable to import module ActiveDirectory! Ensure it is available on this system." -BackgroundColor Yellow -ForegroundColor Black
    # Break
# }
# try {
    # Import-Module GroupPolicy -ErrorAction Stop
# } catch {
    # Write-Host "Unable to import module GroupPolicy! Ensure it is available on this system." -BackgroundColor Yellow -ForegroundColor Black
    # Break
# }
# $ForestInfo = Get-ADForest -Current LocalComputer
# $DomainInfo = Get-ADDomain -Current LocalComputer
# $DCs = Get-ADDomainController -Filter {ISReadOnly -eq $True} -ErrorVariable ErrVar -ErrorAction SilentlyContinue | Select-Object $Properties
#
# $SearchBase = $DomainInfo.DistinguishedName
# Add-Content -Path $LogFile -Value "Domain FQDN: $($DomainInfo.DNSRoot)"
# Add-Content -Path $LogFile -Value "Domain NetBIOS: $($DomainInfo.NetBIOSName)"
# Add-Content -Path $LogFile -Value "Script Reference: $($ScriptText[0].Content)"
# Add-Content -Path $LogFile -Value "----------------------------------------------------"
# If ($DomainInfo.DomainSID.GetType().Name -eq 'String'){
    # $DomainSID = $DomainInfo.DomainSID
# } Else {
    # $DomainSID = ($DomainInfo | Select-Object -ExpandProperty DomainSID).Value
# }
# $ChildDomainStatus = foreach ($child in $DomainInfo.ChildDomains){
    # If ((Test-Netconnection $child -Port 389).TcpTestSucceeded){
        # New-Object -TypeName PSObject -Property @{
            # DomainName = $child
            # Online = $True
        # }
    # } Else {
        # New-Object -TypeName PSObject -Property @{
            # DomainName = $child
            # Online = $False
        # }
    # }
# }

# ---------------------------------------------------------
# Computer Info - PowerShell Commands
# ---------------------------------------------------------
# $servers = Get-ADComputer -Filter * -Properties *
# Get-ADComputer -Identity "<HOSTNAME>" -Properties * -Verbose
# Get-ComputerInfo -Property "*version"
# Write-Host $env:COMPUTERNAME
# Get-CimClass -ClassName *bios*
# Get-CimClass -ClassName Win32_Bios
# Get-CimInstance -ClassName Win32_Bios
# Get-CimInstance -ClassName Win32_OperatingSystem
# Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "DHCPEnabled = $true"
# Get-CimInstance -Query "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE DHCPEnabled = $true"
# Get-CimInstance -ClassName Win32_Environment
# Get-Help * -Parameter ComputerName
# Get-Command -ParameterName ComputerName
# Get-ChildItem hklm:\software | Get-Member ps*
# Get-Process | sort -Descending ws | select -First 3
# Get-Process | where Handles -gt 1000

# ---------------------------------------------------------
# User Accounts - PowerShell Commands
# ---------------------------------------------------------
# Get-WmiObject -Class Win32_UserAccount -Namespace "root\cimv2" -Filter "LocalAccount='$True'"

# ---------------------------------------------------------
# Registry - PowerShell Commands
# ---------------------------------------------------------
# cd hklm:\software\microsoft\powershell
# Get-ChildItem -Path Registry::
# Get-ChildItem -Path registry::HKEY_CURRENT_CONFIG\System\CurrentControlSet\SERVICES\TSDDD\

# ---------------------------------------------------------
# Files - PowerShell Commands
# ---------------------------------------------------------
# Get-ChildItem -Path C:\ -Filter *.sys -Force

# ---------------------------------------------------------
# "netstat - PowerShell Commands
# ---------------------------------------------------------
# netstat -n | select -Skip 4 | ConvertFrom-String -PropertyNames Blank, Protocol, LocalAddress, ForeignAddress, State | Select-Object Protocol, LocalAddress, ForeignAddress, State

# ---------------------------------------------------------
# "clipboard" - PowerShell Commands
# ---------------------------------------------------------
# Get-Clipboard

# ---------------------------------------------------------
# "Processes" - PowerShell Commands
# ---------------------------------------------------------
# Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = 'calc.exe'}
# Get-CimInstance -ClassName Win32_Process -Filter "Name='calculator.exe'"

# ---------------------------------------------------------
# "Cimsession" - PowerShell Commands
# ---------------------------------------------------------
# Get-Command -ParameterName Cimsession

# ---------------------------------------------------------
# Services - PowerShell Commands
# ---------------------------------------------------------
# Get-Service -Name BITS


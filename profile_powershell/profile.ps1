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

Update-Help -Force -Verbose

# Get-Help * -Parameter ComputerName
# Get-Command -ParameterName ComputerName


# Get-PSRepository | Format-List

# Computer Info - PowerShell Commands
# Write-Host $env:COMPUTERNAME
# Get-CimClass -ClassName *bios*
# Get-CimClass -ClassName Win32_Bios
# Get-CimInstance -ClassName Win32_Bios
# Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "DHCPEnabled = $true"
# Get-CimInstance -Query "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE DHCPEnabled = $true"

# Get-Module -ListAvailable -All
# Get-Module -All
# Get-Module -ListAvailable | where { $_.path -match "System32" }

# Get-Command -Module PowerShellGet | Format-Wide -Column 3
# Get-Command -ParameterName Cimsession

# Find-Module -Repository PSGallery
# Find-Module -Name *pip*
# Find-Module nx* | Format-Table Version, Name, Description
# Find-Module nx* | Install-Module -Force
# Find-Module -Tag 'Active Directory', 'ActiveDirectory', 'Active', 'Directory', 'AD'

# Find-Script -Name *pip*

# Get-ChildItem hklm:\software | Get-Member ps*

# Get-Process | sort -Descending ws | select -First 3
# Get-Process | where Handles -gt 1000

# Get-CimInstance -ClassName Win32_OperatingSystem


# Registry - PowerShell Commands
# cd hklm:\software\microsoft\powershell
# Get-ChildItem -Path Registry::
# Get-ChildItem -Path registry::HKEY_CURRENT_CONFIG\System\CurrentControlSet\SERVICES\TSDDD\

# Files - PowerShell Commands
# Get-ChildItem -Path C:\ -Filter *.sys -Force

# "netstat" - PowerShell Commands
# netstat -n | select -Skip 4 | ConvertFrom-String -PropertyNames Blank, Protocol, LocalAddress, ForeignAddress, State | Select-Object Protocol, LocalAddress, ForeignAddress, State

# "clipboard" - PowerShell Commands
# Get-Clipboard

# Processes - PowerShell Commands
# Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = 'calc.exe'}
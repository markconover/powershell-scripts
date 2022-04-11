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



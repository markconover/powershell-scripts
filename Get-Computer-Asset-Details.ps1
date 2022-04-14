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
    None

.EXAMPLE
    The following will run and output a CSV file
    .\Get-Computer-Asset-Details.ps1
#>

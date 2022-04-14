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

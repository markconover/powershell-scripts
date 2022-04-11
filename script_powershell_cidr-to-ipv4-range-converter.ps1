#set-executionpolicy unrestricted

$cidrRanges = @(
"10.125.16.0/24",
"10.134.202.0/24",
"10.135.220.128/26")

Function Get-IPV4NetworkStartIP ($strNetwork)
{
	$StrNetworkAddress = ($strNetwork.split("/"))[0]
	$NetworkIP = ([System.Net.IPAddress]$StrNetworkAddress).GetAddressBytes()
	[Array]::Reverse($NetworkIP)
	$NetworkIP = ([System.Net.IPAddress]($NetworkIP -join ".")).Address
	$StartIP = $NetworkIP +1
	
	#Convert To Double
	If (($StartIP.Gettype()).Name -ine "double")
	{
		$StartIP = [Convert]::ToDouble($StartIP)
	}
	$StartIP = [System.Net.IPAddress]$StartIP
	Return $StartIP
}

Function Get-IPV4NetworkEndIP ($strNetwork)
{
	$StrNetworkAddress = ($strNetwork.split("/"))[0]
	[int]$NetworkLength = ($strNetwork.split("/"))[1]
	$IPLength = 32-$NetworkLength
	$NumberOfIPs = ([System.Math]::Pow(2, $IPLength)) -2
	$NetworkIP = ([System.Net.IPAddress]$StrNetworkAddress).GetAddressBytes()
	[Array]::Reverse($NetworkIP)
	$NetworkIP = ([System.Net.IPAddress]($NetworkIP -join ".")).Address
	$EndIP = $NetworkIP + $NumberOfIPs
	
	If (($EndIP.Gettype()).Name -ine "double")
	{
		$EndIP = [Convert]::ToDouble($EndIP)
	}
	$EndIP = [System.Net.IPAddress]$EndIP
	Return $EndIP
}

For ($i=0; $i -lt $cidrRanges.Length; $i++){
	$cidr = $($cidrRanges[$i])
	$StartIP = Get-IPV4NetworkStartIP($cidr)
	$EndIP = Get-IPV4NetworkEndIP($cidr)
	Write-Host "$StartIP - $EndIP"
}

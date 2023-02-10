#
# DNS Zone Information
#
function Get-WmiCount($a) {
	if ($a -eq $Null) {
		$cnt = 0
	} elseif ($a.GetType().Name -eq "ManagementObject") {
		$cnt = 1
	} else {
		$cnt = $a.Length
	}

	$cnt
}

function Output-Zoneinfo($Zone) {
	#$Output = New-Object System.Collections.ArrayList
	$Date = Get-Date -format 'yyyy-MM-ddTHH:mm:sszzz'
    write-host -NoNewline $Date Zone=`"$($Zone.Name)`" Aging=`"$($Zone.Aging)`" AllowUpdate=`"$($Zone.AllowUpdate)`" AutoCreated=`"$($Zone.AutoCreated)`" AvailForScavengeTime=`"$($Zone.AvailForScavengeTime)`" Caption=`"$($Zone.Caption)`" ContainerName=`"$($Zone.ContainerName)`" DataFile=`"$($Zone.DataFile)`" DnsServerName=`"$($Zone.DnsServerName)`" DsIntegrated=`"$($Zone.DsIntegrated)`" ForwarderSlave=`"$($Zone.ForwarderSlave)`" ForwarderTimeout=`"$($Zone.ForwarderTimeout)`" LastSuccessfulSoaCheck=`"$($Zone.LastSuccessfulSoaCheck)`" LastSuccessfulXfr=`"$($Zone.LastSuccessfulXfr)`" NoRefreshInterval=`"$($Zone.NoRefreshInterval)`" Notify=`"$($Zone.Notify)`" Paused=`"$($Zone.Paused)`" RefreshInterval=`"$($Zone.RefreshInterval)`" Reverse=`"$($Zone.Reverse)`" SecureSecondaries=`"$($Zone.SecureSecondaries)`" Shutdown=`"$($Zone.Shutdown)`" Status=`"$($Zone.Status)`" UseWins=`"$($Zone.UseWins)`" ZoneType=`"$($Zone.ZoneType)`"

	# Some information on the zone itself - # record by type and total
	$ZoneName = $Zone.Name

	$SOA  = Get-WmiObject -namespace "root\MicrosoftDNS" -class MicrosoftDNS_SOAType -ComputerName $env:ComputerName -Filter "DomainName = '$ZoneName'"
	$SOAlen = Get-WmiCount($SOA)
	write-host -NoNewline ""SOA=$SOAlen

	$NS   = Get-WmiObject -namespace "root\MicrosoftDNS" -class MicrosoftDNS_NSType -ComputerName $env:ComputerName -Filter "DomainName = '$ZoneName'"
	$NSlen = Get-WmiCount($NS)
	write-host -NoNewline ""NS=$NSlen

	$A    = Get-WmiObject -namespace "root\MicrosoftDNS" -class MicrosoftDNS_AType -ComputerName $env:ComputerName -Filter "DomainName = '$ZoneName'"
	$Alen = Get-WmiCount($A)
	write-host -NoNewline ""A=$Alen

	$AAAA = Get-WmiObject -namespace "root\MicrosoftDNS" -class MicrosoftDNS_AAAAType -ComputerName $env:ComputerName -Filter "DomainName = '$ZoneName'"
	$AAAAlen = Get-WmiCount($AAAA)
	write-host -NoNewline ""AAAA=$AAAAlen

	$CNAME= Get-WmiObject -namespace "root\MicrosoftDNS" -class MicrosoftDNS_CNAMEType -ComputerName $env:ComputerName -Filter "DomainName = '$ZoneName'"
	$CNAMElen = Get-WmiCount($CNAME)
	write-host -NoNewline ""CNAME=$CNAMElen

	$MX   = Get-WmiObject -namespace "root\MicrosoftDNS" -class MicrosoftDNS_MXType -ComputerName $env:ComputerName -Filter "DomainName = '$ZoneName'"
	$MXlen = Get-WmiCount($MX)
	write-host -NoNewline ""MX=$MXlen

	$SRV  = Get-WmiObject -namespace "root\MicrosoftDNS" -class MicrosoftDNS_SRVType -ComputerName $env:ComputerName -Filter "DomainName = '$ZoneName'"
	$SRVlen = Get-WmiCount($SRV)
	write-host -NoNewline ""SRV=$SRVlen

	$HINFO= Get-WmiObject -namespace "root\MicrosoftDNS" -class MicrosoftDNS_HINFOType -ComputerName $env:ComputerName -Filter "DomainName = '$ZoneName'"
	$HINFOlen = Get-WmiCount($HINFO)
	write-host -NoNewline ""HINFO=$HINFOlen

	$TXT  = Get-WmiObject -namespace "root\MicrosoftDNS" -class MicrosoftDNS_TXTType -ComputerName $env:ComputerName -Filter "DomainName = '$ZoneName'"
	$TXTlen = Get-WmiCount($TXT)
	write-host -NoNewline ""TXT=$TXTlen

	$RR  = Get-WmiObject -namespace "root\MicrosoftDNS" -class MicrosoftDNS_ResourceRecord -ComputerName $env:ComputerName -Filter "DomainName = '$ZoneName'"
	$TotalRecords = Get-WmiCount($RR)
	write-host ""TotalRecords=$TotalRecords

}

#
# Main Program
#
$ServerName = $env:ComputerName
$Scope = New-Object Management.ManagementScope("\\$ServerName\root\MicrosoftDNS")
$Path = New-Object Management.ManagementPath("MicrosoftDNS_Zone")
$Options = New-Object Management.ObjectGetOptions($Null, [System.TimeSpan]::MaxValue, $True)

$ZoneClass = New-Object Management.ManagementClass($Scope, $Path, $Options)
$Zones = Get-WMIObject -Computer $ServerName -Namespace "root\MicrosoftDNS" -Class "MicrosoftDNS_Zone"
$OutputEncoding = [Text.Encoding]::UTF8
Foreach ($Zone in $Zones) {
	Output-ZoneInfo($Zone)
}

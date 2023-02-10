#
# Determine and output information about the Site the server is a member of
#

$ServerName = $env:ComputerName
$BSSN = "\\" + $ServerName
$WMI_DOMAIN	 = Get-WmiObject Win32_NTDomain | Where-Object {$_.DomainControllerName -eq $BSSN}
$SiteName = $WMI_DOMAIN.ClientSiteName
$ForestName = [System.DirectoryServices.ActiveDirectory.Forest]::getCurrentForest().Name

$Date = Get-Date -format 'yyyy-MM-ddTHH:mm:sszzz'
$SiteInfoObj = [System.DirectoryServices.ActiveDirectory.Forest]::getCurrentForest().Sites | Where-Object { $_.Name -eq $SiteName }
$ISTG = $SiteInfoObj.IntersiteTopologyGenerator.Name


write-host  $Date Type=`"Site`" ForestName=`"$ForestName`" Site=`"$SiteName`" Location=`"$($SiteInfoObj.Location)`" -NoNewline
$SiteInfoObj.AdjacentSites | Foreach-Object { write-host AdjacentSite=`"$($_.Name)`" -NoNewline }
write-host IntersiteTopologyGenerator=`"$ISTG`" -NoNewline
$SiteInfoObj.SiteLinks | Foreach-Object { write-host "" SiteLink=`"$($_.Name)`" -NoNewline }
$SiteInfoObj.Subnets | Foreach-Object { write-host "" Subnet=`"$($_.Name)`" -nonewline }

write-host #Needed to print a newline for next object

#
# Output Information about Site Links in this site
#
$SiteInfoObj.SiteLinks | Foreach-Object {
    write-host $Date Type=`"SiteLink`" ForestName=`"$ForestName`" Name=`"$($_.Name)`" Cost=$($_.Cost) DataCompressionEnabled=$($_.DataCompressionEnabled) NotificationEnabled=$($_.NotificationEnabled) ReciprocalReplicationEnabled=$($_.ReciprocalReplicationEnabled) TransportType=$($_.TransportType) ReplicationIntervalSecs=$($_.ReplicationInterval.TotalSeconds) -NoNewLine
	foreach ($site in $_.Sites) {
		write-host ""Site=`"$($site.Name)`" -NoNewLine
	}
}
Write-Host  #similar to above

#
# Output Information about Subnets in this site
#

$SiteInfoObj.Subnets | Foreach-Object {
    write-Host $Date Type=`"Subnet`" ForestName=`"$ForestName`" Name=`"$($_.Name)`" Site=`"$SiteName`" Location=`"$($_.Location)`"
}

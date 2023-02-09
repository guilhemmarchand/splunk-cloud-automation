Import-Module ActiveDirectory -ErrorAction SilentlyContinue
#
# Get the Information about this site
#
$ServerName = $env:ComputerName

$DC 	= Get-ADDomainController -Identity $ServerName
$Site	= Get-ADReplicationSite -Identity $DC.Site
$Object = Get-ADObject -Filter * -SearchScope base -Properties * `
		-SearchBase $Site.DistinguishedName

$Location 	= if ($Object.location -eq $null) { "" } else { $Object.location }
$ISTG	  	= Get-ADDomainController -Filter `
			'NTDSSettingsObjectDN -eq $Site.IntersiteTopologyGenerator'
$SiteLinks 	= Get-ADReplicationSiteLink -Filter 'SitesIncluded -eq $Site' -Properties *
$AdjacentSites 	= ($SiteLinks | Select -Expand SitesIncluded | `
			Where-Object { $_ -ne $Site.DistinguishedName } | `
			Sort-Object | Get-Unique | `
			Foreach-Object { Get-ADReplicationSite $_ } )
$Subnets	= Get-ADReplicationSubnet -Filter 'Site -eq $Site'

########################################################################
#
# SITE
#
$SiteInfo = @(
	"Type=`"Site`""
	"ForestName=`"$($DC.Forest)`""
	"Site=`"$($Object.CN)`""
	"Location=`"$Location`""
	"IntersiteTopologyGenerator=`"$($ISTG.HostName)`""
)
$AdjacentSites | %{ $SiteLink += "AdjacentSite=`"$($_.Name)`"" }
$SiteLinks     | %{ $SiteInfo += "SiteLink=`"$($_.Name)`"" }
$Subnets       | %{ $SiteInfo += "Subnet=`"$($_.Name)`"" }
Write-Output ($SiteInfo -join " ")
#
########################################################################
#
# SITELINK
#
$SiteLinks | %{
	# These values are not stored in the object unless you change them
	$cost 		= if ($_.Cost -eq $null) { 100 } else { $_.Cost }
	$options 	= if ($_.options -eq $null) { 0 } else { $_.options }
	$replInterval	= if ($_.replInterval -eq $null) { 180 * 60 } else { $_.replInterval * 60 }
	$notifications	= if ($options -band 0x01) { "True" } else { "False" }
	$reciprocal 	= if ($options -band 0x02) { "True" } else { "False" }
	$compression	= if ($options -band 0x04) { "False" } else { "True" }

	$SiteLink = @(
		"Type=`"SiteLink`""
		"ForestName=`"$($DC.Forest)`""
		"Name=`"$($_.Name)`""
		"Cost=`"$($_.Cost)`""
		"DataCompressionEnabled=$compression"
		"NotificationEnabled=$notifications"
		"ReciprocalReplicationEnabled=$reciprocal"
		"TransportType=$($_.InterSiteTransportProtocol)"
		"ReplicationIntervalSecs=$replInterval"
	)
	Write-Output ($SiteLink -join " ")
}

$Subnets | Foreach-Object {
	$Subnet = @(
		"Type=`"Subnet`""
		"ForestName=`"$($DC.Forest)`""
		"Name=`"$($_.Name)`""
		"Site=`"$($Site.Name)`""
		"Location=`"$($_.Location)`""
	)
	Write-Output ($Subnet -join " ")
}

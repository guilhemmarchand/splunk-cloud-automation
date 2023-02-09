Import-Module ActiveDirectory -ErrorAction SilentlyContinue

Get-ADReplicationPartnerMetaData -Target $env:ComputerName -PartnerType Inbound -Partition * | %{
	$src_host = Get-ADObject -Filter * -SearchBase $_.Partner.Replace("CN=NTDS Settings,","") `
				-SearchScope Base -Properties dNSHostName

	New-Object PSObject -Property @{
		LastAttemptedSync	= $_.LastReplicationAttempt
		LastSuccessfulSync	= $_.LastReplicationSuccess
		type			= "ReplicationEvent"
		usn			= $_.LastChangeUsn
		src_host		= $src_host.dNSHostName
		Result			= $_.LastReplicationResult
		transport		= $_.IntersiteTransportType
		naming_context		= $_.Partition
	}
}

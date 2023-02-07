Import-Module ActiveDirectory -ErrorAction SilentlyContinue

$ServerName = $env:ComputerName

$DomainController = Get-ADDomainController -Identity $ServerName
$Domain 		  = Get-ADDomain -Identity $DomainController.Domain
$Forest			  = Get-ADForest -Identity $DomainController.Forest
$ReplicationSite  = Get-ADReplicationSite -Identity $DomainController.Site
$Computer		  = Get-ADComputer -Identity $ServerName -Properties *
$RootDSE		  = Get-ADRootDSE -Server $ServerName
$RequiredServices = @( "ntfrs", "dfsr", "netlogon", "kdc", "w32time", "ismserv" )

$ISTG 		  = ($DomainController.NTDSSettingsObjectDN -eq $ReplicationSite.InterSiteTopologyGenerator)
$SYSVOL 	  = (Get-SMBShare SYSVOL -ErrorAction SilentlyContinue)
Try {
    $DnsRegister  = [System.Net.Dns]::GetHostByName($DomainController.HostName)
} Catch {
    # The Catch will set $DnsRegister = $null if the GetHostByName fails for some reason
}
$SchemaVersion= Get-ADObject -Filter * -SearchScope Base -Properties objectVersion `
			-SearchBase $RootDSE.schemaNamingContext
$DCWeight	  = (Get-Item "HKLM:System\CurrentControlSet\Services\Netlogon\Parameters").GetValue("LdapSrvWeight", $null)
if (!$DCWeight -or $DCWeight -eq $null -or $DCWeight -eq "") {
	$DCWeight = 100
}
$FSMORoles 	= ($DomainController | Select -Expand OperationMasterRoles | %{ $_.ToString().Replace("Master","") } )

$SvcRunning	= @(Get-Service $RequiredServices | ? Status -eq "Running" | select -expand Name)
$SvcStopped	= @(Get-Service $RequiredServices | ? Status -ne "Running" | select -expand Name)
$ProcsOK	= (($SvcStopped.Count -eq 0) -or ($SvcStopped.Count -eq 1 -and ($SvcStopped[0] -eq "ntfrs" -or $SvcStopped[0] -eq "dfsr")))

New-Object PSObject -Property @{
	Server			= $DomainController.Name
	DomainDNSName	= $DomainController.Domain
	DomainNetBIOSName = $Domain.NetBIOSName
	DomainLevel		= $Domain.DomainMode
	Site			= $DomainController.Site
	ForestName		= $DomainController.Forest
	ForestLevel		= $Forest.ForestMode
	Created			= $Computer.whenCreated
	Changed			= $Computer.whenChanged
	GlobalCatalog	= $DomainController.IsGlobalCatalog
	RODC			= $DomainController.IsReadOnly
	Enabled			= $DomainController.Enabled
	HighestUSN		= $RootDSE.highestCommittedUSN
	SchemaVersion	= $SchemaVersion.objectVersion
	DCWeight		= $DCWeight
	IsIntersiteTopologyGenerator = $ISTG
	OperatingSystem	= $DomainController.OperatingSystem
	ServicePack		= $DomainController.OperatingSystemServicePack
	OSVersion		= $DomainController.OperatingSystemVersion
	FSMORoles		= $FSMORoles -join " "
	ServicesRunning	= $SvcRunning -join ","
	ServicesNotRunning = $SvcStopped -join ","
	ProcsOK			= $ProcsOK
	SYSVOLShare		= ($SYSVOL -ne $null)
	DNSRegister		= ($DnsRegister -ne $null)
}

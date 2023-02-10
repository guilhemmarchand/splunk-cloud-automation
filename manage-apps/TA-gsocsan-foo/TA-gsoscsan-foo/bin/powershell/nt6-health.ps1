#
# Determine the health and statistics of this Active Directory Controller
#
$Output = New-Object System.Collections.ArrayList
$Date = Get-Date -format 'yyyy-MM-ddTHH:mm:sszzz'
[void]$Output.Add($Date)

# Name of Server
$ServerName = $env:ComputerName
[void]$Output.Add("Server=""$ServerName""")
$BSSN = "\\" + $ServerName

# Domain Information

$S_DS_AD_DOM = [System.DirectoryServices.ActiveDirectory.Domain]::getComputerDomain()
$WMI_CS      = (Get-WmiObject Win32_ComputerSystem)
$WMI_DOMAIN	 = Get-WmiObject Win32_NTDomain | Where-Object {$_.DomainControllerName -eq $BSSN}

$DomainDNSName = $WMI_CS.Domain
$DomainNetBIOSName = $WMI_DOMAIN.DomainName
$DomainLevel   = $S_DS_AD_DOM.DomainMode
[void]$Output.Add("DomainDNSName=`"$DomainDNSName`"");
[void]$Output.Add("DomainNetBIOSName=`"$DomainNetBIOSName`"");
[void]$Output.Add("DomainLevel=`"$DomainLevel`"");

# Site Information
$SiteName = $WMI_DOMAIN.ClientSiteName
[void]$Output.Add("Site=`"$SiteName`"");

# Forest Information
$ForestName = $S_DS_AD_DOM.Forest.Name
$ForestLevel = $S_DS_AD_DOM.Forest.ForestMode
[void]$Output.Add("ForestName=`"$ForestName`"");
[void]$Output.Add("ForestLevel=`"$ForestLevel`"");

# Domain Controller Flags
$IsRO = "False"
$IsEnabled = "False"
$IsGC = "False"
$USN = "Unknown"
$MyName = ($env:ComputerName + "." + $DomainDNSName).ToLower()
if ($WMI_DOMAIN.Status -eq "OK") {
	$MyDC = $S_DS_AD_DOM.DomainControllers | Where-Object { $_.Name.ToLower() -eq $MyName.ToLower() }
	if ($MyDC) {
		if ($MyDC.IsGlobalCatalog()) {
			$IsGC = "True"
		}
		$USN = $MyDC.HighestCommittedUsn
		$IsEnabled = "True"

		$entry = $MyDC.getDirectoryEntry()
		[void]$Output.Add("Created=`"$($entry.whenCreated)`"")
		[void]$Output.Add("Changed=`"$($entry.whenChanged)`"")

		$DN = $entry.Path
		$ServerEntry = [ADSI]"$DN"
		$ServerEntry.GetInfoEx(@("msDS-IsRODC"),0)
		$IsRO = $ServerEntry."msDS-IsRODC"
	}
}
[void]$Output.Add("GlobalCatalog=`"$IsGC`"")
[void]$Output.Add("RODC=`"$IsRO`"")
[void]$Output.Add("Enabled=`"$IsEnabled`"")
[void]$Output.Add("HighestUSN=`"$USN`"")

$SchemaInfo = Get-Item "HKLM:System\CurrentControlSet\Services\NTDS\Parameters"
$SchemaVersion = $SchemaInfo.GetValue("Schema Version")
[void]$Output.Add("SchemaVersion=$SchemaVersion")

$NetLogonParams = Get-Item "HKLM:System\CurrentControlSet\Services\Netlogon\Parameters"
$DCWeight = $NetLogonParams.GetValue("LdapSrvWeight", $null)
if (!$DCWeight -or $DCWeight -eq $null -or $DCWeight -eq "") {
	$DCWeight = 100	# This is the default value
}
[void]$Output.Add("DCWeight=$DCWeight")

$SiteInfoObj = [System.DirectoryServices.ActiveDirectory.Forest]::getCurrentForest().Sites | Where-Object { $_.Name -eq $SiteName }

# Is this host a BridgeHead Server?
# Field BridgeheadServer (Collection of DirectoryServer objects - check to see if we are listed and set IsBridgeHeadServer=True/False accordingly)

# Is this host a Intersite Topology Generator
if ($SiteInfoObj.IntersiteTopologyGenerator.Name -and ($SiteInfoObj.IntersiteTopologyGenerator.Name -eq $ServerName -or $SiteInfoObj.IntersiteTopologyGenerator.Name.ToLower() -eq $MyName)) {
	[void]$Output.Add("IsIntersiteTopologyGenerator=`"True`"")
} else {
	[void]$Output.Add("IsIntersiteTopologyGenerator=`"False`"")
}


#
# Windows Version and Build #
#
$WindowsInfo = Get-Item "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$OS = $WindowsInfo.GetValue("ProductName")
$OSSP = $WindowsInfo.GetValue("CSDVersion")
$WinVer = $WindowsInfo.GetValue("CurrentVersion")
$WinBuild = $WindowsInfo.GetValue("CurrentBuildNumber")
$OSVER = "$WinVer ($WinBuild)"

[void]$Output.Add("OperatingSystem=""$OS""")
[void]$Output.Add("ServicePack=""$OSSP""")
[void]$Output.Add("OSVersion=""$OSVER""")

#
# FSMO Roles (Schema, DomainNaming, Infrastructure, RIDMaster, PDC)
#
$aFSMO = @()
if ($MyDC -and $MyDC.Roles) {
	foreach ($role in $MyDC.Roles) {
		switch ($role) {
			"SchemaRole"			{ $aFSMO += "Schema" }
			"NamingRole"			{ $aFSMO += "DomainNaming" }
			"InfrastructureRole"	{ $aFSMO += "Infrastructure" }
			"PdcRole"				{ $aFSMO += "PDCEmulator" }
			"RidRole"				{ $aFSMO += "RIDMaster" }
		}
	}
}
$FSMORoles = [string]::join(' ', $aFSMO)
[void]$Output.Add("FSMORoles=""$FSMORoles""")

#
# Required Processes Running
#		FRS, DFS-R, Net Logon, KDC, W32Time, ISMSERV
#
$RequiredServices = @( "ntfrs", "dfsr", "netlogon", "kdc", "w32time", "ismserv" )
$srvr = @()
$srvnr = @()
foreach ($srv in $RequiredServices) {
	$status = (Get-Service $srv).Status
	if ($status -eq "Running") {
		$srvr += $srv
	} else {
		$srvnr += $srv
	}
}
# Note that the only case that ProcsOK == True is when there is ONE service
# that isn't running - You need one replication services (ntfrs or dfsr) but
# not both
$ProcsOK = "False"
if (($srvnr.Count -eq 0) -or ($srvnr.Count -eq 1 -and ($srvnr[0] -eq "ntfrs" -or $srvnr[0] -eq "dfsr"))) {
	$ProcsOK = "True"
}
$ServicesRunning = [string]::join(',', $srvr)
$ServicesNotRunning = [string]::join(',', $srvnr)
[void]$Output.Add("ServicesRunning=""$ServicesRunning""")
[void]$Output.Add("ServicesNotRunning=""$ServicesNotRunning""")
[void]$Output.Add("ProcsOK=""$ProcsOK""")

#
# Look for Common Problems
#		SYSVOL is shared out
#		DC is registered in DNS
#
$SysvolShare = (Get-WmiObject Win32_Share|Where-Object { $_.Name -eq "SYSVOL" })
if ($SysvolShare) {
	[void]$Output.Add("SYSVOLShare=""True""")
} else {
	[void]$Output.Add("SYSVOLShare=""False""")
}

$DNSEntry = ([System.Net.DNS]::GetHostEntry($ServerName))
if ($DNSEntry) {
	[void]$Output.Add("DNSRegister=""True""")
} else {
	[void]$Output.Add("DNSRegister=""False""")
}

# Output the final string
Write-Host ($output -join " ")

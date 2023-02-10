#
# Determine the health and statistics of this Microsoft DNS Server
#
$Output = New-Object System.Collections.ArrayList
$Date = Get-Date -format 'yyyy-MM-ddTHH:mm:sszzz'
write-host -NoNewline ""$Date

# Name of Server
$ServerName = $env:ComputerName
write-host -NoNewline ""Server=`"$ServerName`"

#
# Windows Version and Build #
#
$WindowsInfo = Get-Item "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$OS = $WindowsInfo.GetValue("ProductName")
$OSSP = $WindowsInfo.GetValue("CSDVersion")
$WinVer = $WindowsInfo.GetValue("CurrentVersion")
$WinBuild = $WindowsInfo.GetValue("CurrentBuildNumber")
$OSVER = "$WinVer ($WinBuild)"

write-host -NoNewline ""OperatingSystem=`"$OS`"
write-host -NoNewline ""ServicePack=`"$OSSP`"
write-host -NoNewline ""OSVersion=`"$OSVER`"

#
# Required Processes Running
#		DNS Dnscache w32time
#
$RequiredServices = @( "DNS", "Dnscache", "w32time" )
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

$ProcsOK = "False"
if ($srvnr.Count -eq 0) {
	$ProcsOK = "True"
}

$ServicesRunning = [string]::join(',', $srvr)
$ServicesNotRunning = [string]::join(',', $srvnr)
write-host -NoNewline ""ServicesRunning=`"$ServicesRunning`" ServicesNotRunning=`"$ServicesNotRunning`" ProcsOK=`"$ProcsOK`"

#
# Settings for this DNS Server
#
$dnsInfo = Get-WmiObject -Namespace "root\MicrosoftDNS" -Class MicrosoftDNS_Server -ComputerName $ServerName

# See http://msdn.microsoft.com/en-us/library/windows/desktop/ms682725(v=vs.85).aspx for details
write-host -NoNewline "" Name=`"$($dnsInfo.Name)`"
write-host -NoNewline "" Version=`"$($dnsInfo.Version)`"
write-host -NoNewline "" LogLevel=`"$($dnsInfo.LogLevel)`"
write-host -NoNewline "" LogFilePath=`"$($dnsInfo.LogFilePath)`"
write-host -NoNewline "" LogFileMaxSize=`"$($dnsInfo.LogFileMaxSize)`"
write-host -NoNewline "" LogIPFilterList=`"$($dnsInfo.LogIPFilterList)`"
write-host -NoNewline "" EventLogLevel=`"$($dnsInfo.EventLogLevel)`"
write-host -NoNewline "" RpcProtocol=`"$($dnsInfo.RpcProtocol)`"
write-host -NoNewline "" NameCheckFlag=`"$NameCheckFlag`"
write-host -NoNewline "" AddressAnswerLimit=`"$($dnsInfo.AddressAnswerLimit)`"
write-host -NoNewline "" RecursionRetry=`"$($dnsInfo.RecursionRetry)`"
write-host -NoNewline "" RecursionTimeout=`"$($dnsInfo.RecursionTimeout)`"
write-host -NoNewline "" DsPollingInterval=`"$($dnsInfo.DsPollingInterval)`"
write-host -NoNewline "" DsTombstoneInteval=`"$($dnsInfo.DsTombstoneInteval)`"
write-host -NoNewline "" MaxCacheTTL=`"$($dnsInfo.MaxCacheTTL)`"
write-host -NoNewline "" MaxNegativeCacheTTL=`"$($dnsInfo.MaxNegativeCacheTTL)`"
write-host -NoNewline "" SendPort=`"$($dnsInfo.SendPort)`"
write-host -NoNewline "" XfrConnectTimeout=`"$($dnsInfo.XfrConnectTimeout)`"
write-host -NoNewline "" BootMethod=`"$($dnsInfo.BootMethod)`"
write-host -NoNewline "" AllowUpdate=`"$($dnsInfo.AllowUpdate)`"
write-host -NoNewline "" UpdateOptions=`"$($dnsInfo.UpdateOptions)`"
write-host -NoNewline "" DsAvailable=`"$($dnsInfo.DsAvailable)`"
write-host -NoNewline "" DisableAutoReverseZones=`"$($dnsInfo.DisableAutoReverseZones)`"
write-host -NoNewline "" AutoCacheUpdate=`"$($dnsInfo.AutoCacheUpdate)`"
write-host -NoNewline "" NoRecursion=`"$($dnsInfo.NoRecursion)`"
write-host -NoNewline "" RoundRobin=`"$($dnsInfo.RoundRobin)`"
write-host -NoNewline "" LocalNetPriority=`"$($dnsInfo.LocalNetPriority)`"
write-host -NoNewline "" StrictFileParsing=`"$($dnsInfo.StrictFileParsing)`"
write-host -NoNewline "" LooseWildcarding=`"$($dnsInfo.LooseWildcarding)`"
write-host -NoNewline "" BindSecondaries=`"$($dnsInfo.BindSecondaries)`"
write-host -NoNewline "" WriteAuthorityNS=`"$($dnsInfo.WriteAuthorityNS)`"
write-host -NoNewline "" ForwardDelegations=`"$($dnsInfo.ForwardDelegations)`"
write-host -NoNewline "" SecureResponses=`"$($dnsInfo.SecureResponses)`"
write-host -NoNewline "" DisjointNets=`"$($dnsInfo.DisjointNets)`"
write-host -NoNewline "" AutoConfigFileZones=`"$($dnsInfo.AutoConfigFileZones)`"
write-host -NoNewline "" ScavengingInterval=`"$($dnsInfo.ScavengingInterval)`"
write-host -NoNewline "" DefaultRefreshInterval=`"$($dnsInfo.DefaultRefreshInterval)`"
write-host -NoNewline "" DefaultNoRefreshInterval=`"$($dnsInfo.DefaultNoRefreshInterval)`"
write-host -NoNewline "" DefaultAgingState=`"$($dnsInfo.DefaultAgingState)`"
write-host -NoNewline "" EDnsCacheTimeout=`"$($dnsInfo.EDnsCacheTimeout)`"
write-host -NoNewline "" EnableEDnsProbes=`"$($dnsInfo.EnableEDnsProbes)`"
write-host -NoNewline "" EnableDnsSec=`"$($dnsInfo.EnableDnsSec)`"
write-host -NoNewline "" ForwardingTimeout=`"$($dnsInfo.ForwardingTimeout)`"
write-host -NoNewline "" IsSlave=`"$($dnsInfo.IsSlave)`"
write-host -NoNewline "" EnableDirectoryPartitions=`"$($dnsInfo.EnableDirectoryPartitions)`"
write-host -NoNewline "" Started=`"$($dnsInfo.Started)`"
write-host -NoNewline "" StartMode=`"$($dnsInfo.StartMode)`"
write-host -NoNewline "" Status=`"$($dnsInfo.Status)`"

foreach ($ip in $dnsInfo.Forwarders) {
	write-host -NoNewline "" Forwarder=`"$ip`"
}
foreach ($ip in $dnsInfo.ServerAddresses) {
	write-host -NoNewline "" ServerAddress=`"$ip`"
}
foreach ($ip in $dnsInfo.ListenAddresses) {
	write-host "" ListenAddress=`"$ip`"
}

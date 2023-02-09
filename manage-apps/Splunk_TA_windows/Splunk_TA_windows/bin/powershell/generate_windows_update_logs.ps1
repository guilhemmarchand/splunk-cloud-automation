## This script generates WindowsUpdate.Log using Get-WindowsUpdateLog in $SplunkHome\var\log\Splunk_TA_windows\WindowsUpdate
## It monitors the WindowsUpdate.log from $SplunkHome\var\log\Splunk_TA_windows\

Set-Variable -Name "LogFolder" -Value "$SplunkHome\var\log\Splunk_TA_windows\WindowsUpdate"
Set-Variable -Name "MonitoredLogFile" -Value "$SplunkHome\var\log\Splunk_TA_windows\WindowsUpdate.log"

if (!(Test-Path -Path $LogFolder )) {
	New-Item -ItemType directory -Path $LogFolder
}

Get-WindowsUpdateLog -LogPath $LogFolder\WindowsUpdate.log

if ([System.IO.File]::Exists("$MonitoredLogFile")) {
	Get-Content "$LogFolder\WindowsUpdate.log" | Set-Content -Path "$MonitoredLogFile"
}
else {
Copy-Item -Path "$LogFolder\WindowsUpdate.log" -Destination "$MonitoredLogFile"
}

exit

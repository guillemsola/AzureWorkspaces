#
# Install WS
#

Param (
	[string] $InstallFolder = "c:\Install"
)

$logFile = Join-Path -Path $InstallFolder -ChildPath "installation.log"

function Write-Log($text) {
	$FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
	"$FormattedDate $text" | Out-File -FilePath $logFile -Append
}

trap {
    Write-Log "Error found executing the script: $_"
	Write-Error "Error found executing the script: $_"
}

Write-Log "Installing..."

Set-Location -Path $InstallFolder

$citrixStoreFrontPath = Join-Path -Path $InstallFolder -ChildPath "CitrixStoreFront-x64.exe"
$wsInstallerExe = Join-Path -Path $InstallFolder -ChildPath "ws10.Workspace.Setup.exe"

$citrixInstalled = Get-WmiObject Win32_Product | Where-Object { $_.Vendor -like "Citrix*" } | Select-Object -ExpandProperty Name
If( ($citrixInstalled -contains "Citrix StoreFront") -and ($citrixInstalled -contains "Citrix Telemetry Service - x64")) {
	Write-Log "Citrix Storefront already installed."
}
Else {
	Write-Log "Installing Citrix Storefront..."
	$res = Start-Process -FilePath $citrixStoreFrontPath -ArgumentList '-silent' -Wait -PassThru
	Write-Log "Citrix installed with code $($res.ExitCode)"
}

$nodeVersion = node -v
Write-Log("Node version: $nodeVersion")

If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ASG CloudRobot Encryption") {
	Write-Log "WS already installed."
}
Else {
	Write-Log "Installing WS."
	$res = Start-Process -FilePath $wsInstallerExe -ArgumentList "/silentmode" -Wait -NoNewWindow -PassThru
	$res | select * | Out-File "C:\install\wsinstall.log"
	Write-Log "WS installed with code $($res.ExitCode)"
}

Write-Log "All done"
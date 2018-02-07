#
# Configuration.ps1
#

$InstallFolder = "C:\Install"
$BinariesLocation = "https://appmirrorbinaries.file.core.windows.net/host-applications"
$NetworkService  = "NT AUTHORITY\NETWORK SERVICE"

configuration Common 
{ 
	param(
		[Parameter(Mandatory)]
		[PSCredential] $AdminCreds
	)

    Import-DscResource -ModuleName PSDesiredStateConfiguration, xSystemSecurity

	LocalConfigurationManager
	{
		RebootNodeIfNeeded = $true
	}

	xIEEsc DisableIEEsc
	{
		IsEnabled = $false
		UserRole = "Administrators"
	}

	Registry DoNotOpenServerManagerAtLogon {
		Ensure = "Present"
		Key = "HKEY_CURRENT_USER\SOFTWARE\Microsoft\ServerManager"
		ValueName = "DoNotOpenServerManagerAtLogon"
		ValueData = "0x1"
		ValueType = "Dword"
		Hex = $true
		Force = $true
		PsDscRunAsCredential = $AdminCreds
	}
}

Configuration PortalFrontEnd 
{
	Import-DscResource -ModuleName PSDesiredStateConfiguration, XNetworking

	WindowsFeatureSet  WorkspaceDependencies {
		Name = @("Web-Server", "Web-Basic-Auth", "Web-Http-Redirect", "Web-Windows-Auth", "Web-App-Dev", "Web-Net-Ext45", "Web-AppInit", "Web-Asp-Net45", "Web-Mgmt-Tools", "Web-Scripting-Tools", "NET-Framework-45-Features", "NET-Framework-Features", "NET-Framework-45-Core", "Web-WebSockets")
		Ensure = "Present"
		IncludeAllSubFeature = $True
	}

	xFirewall QueryEngineCtrl {
		Name = "QueryEngineCtrl"
		Ensure = "Present"
		DisplayName = "Query engine controller"
		Action = "Allow"
		Profile = ("Domain")
		Direction = "Inbound"
		LocalPort = ("8880")
		RemotePort = "Any"
		Protocol = "TCP"
		Description = "Open port for query engine"
		Enabled = "True"
	}

	xFirewall QueryEngineCtrlAgent {
		Name = "QueryEngineCtrlAgent"
		Ensure = "Present"
		DisplayName = "Query engine controller agent"
		Action = "Allow"
		Profile = ("Domain")
		Direction = "Inbound"
		LocalPort = ("8081", "8082")
		RemotePort = "Any"
		Protocol = "TCP"
		Description = "Open ports for query agent"
		Enabled = "True"
		DependsOn = "[xFirewall]QueryEngineCtrl"
	}
}

Configuration PortalBackend
{
	param(
		[Parameter(Mandatory)]
		[PSCredential] $AdminCreds
	)

	Import-DscResource -ModuleName PSDesiredStateConfiguration, xSmbShare

	WindowsFeatureSet  WorkspaceDependencies {
		Name = @("NET-Framework-Features", "NET-Framework-45-Core", "RSAT-AD-PowerShell", "RSAT-ADLDS")
		Ensure = "Present"
		IncludeAllSubFeature = $True
	}

	File RobotHomeDir {
        Type = 'Directory'
        DestinationPath = 'C:\RobotHome'
        Ensure = "Present"
    }

	xSmbShare RobotHomeDirShare
	{
		Ensure = "Present"
		Name   = "RobotHome"
		Path = "C:\RobotHome" 
		FullAccess = $AdminCreds.UserName
		Description = "Workspace Robot home folder"
		DependsOn = "[File]RobotHomeDir"
	}

	File TSHomeDir {
        Type = 'Directory'
        DestinationPath = 'C:\RobotTS'
        Ensure = "Present"
    }

	xSmbShare TSHomeDirShare
	{
		Ensure = "Present"
		Name   = "RobotTS"
		Path = "C:\RobotTS" 
		FullAccess = $AdminCreds.UserName
		Description = "Workspace Robot TS folder"
		DependsOn = "[File]TSHomeDir"
	}
}

Configuration DevTools
{
	Import-DscResource -ModuleName cChoco

	cChocoInstaller installChoco
	{
		InstallDir = "c:\choco"
	}
	
	cChocoPackageInstallerSet Tools
	{
		Name = @(
			"GoogleChrome"
			"notepadplusplus.install"
			"putty"
		)
		DependsOn = "[cChocoInstaller]installChoco"
		Ensure = "Present"
	}
}

Configuration AddRootCA
{
	param(
		[Parameter(Mandatory)]
		[string] $artifactsLocation,
		[Parameter(Mandatory)]
		[string] $artifactsLocationSasToken
	)

	Import-DscResource -ModuleName xPSDesiredStateConfiguration, xCertificate

	$rootCA = Join-Path -Path $InstallFolder -ChildPath "rootCA.crt"
	
	xRemoteFile CACert {
		Uri = "$artifactsLocation/rootCA.crt$artifactsLocationSasToken"
		DestinationPath = $rootCA
	}

	xCertificateImport CARoot
    {
        Thumbprint = '313EB774FDF2BD9B98BD89C496057B4025C47576'
        Location   = 'LocalMachine'
        Store      = 'Root'
        Path       = $rootCA
		DependsOn = "[xRemoteFile]CACert"
    }
}

Configuration ReplaceJsonFile
{
	param(
		[string] $WsJsonUri,
		[PSCredential] $AdminCreds,
		[String] $IdpUrl,
		[string] $BinariesVersion
	)

	Import-DscResource -ModuleName PSDesiredStateConfiguration, xPSDesiredStateConfiguration, FileContentDSC

	$wsjson = Join-Path -Path $InstallFolder -ChildPath "WSMISettings.json"
	$wsinstaller = Join-Path -Path $InstallFolder -ChildPath "Workspace-$BinariesVersion.zip"

	xRemoteFile ConfigJson {
		Uri = $WsJsonUri
		DestinationPath = $wsjson
	}
	
	ReplaceText replaceFQDN {
		Path   = $wsjson
        Search = '%IdpUrl%'
        Type   = 'Text'
        Text   = $IdpUrl
		DependsOn = "[xRemoteFile]ConfigJson"
	}

	ReplaceText replacePassword {
		Path   = $wsjson
        Search = '%password%'
        Type   = 'Text'
        Text   = $AdminCreds.GetNetworkCredential().Password
		DependsOn = "[ReplaceText]replaceFQDN"
	}

	ReplaceText replaceUser {
		Path   = $wsjson
        Search = '%user%'
        Type   = 'Text'
        Text   = $AdminCreds.UserName.Split('@')[0]
		DependsOn = "[ReplaceText]replacePassword"
	}
		
	ReplaceText replaceHostname {
		Path   = $wsjson
        Search = '%hostname%'
        Type   = 'Text'
        Text   = $env:COMPUTERNAME
		DependsOn = "[ReplaceText]replaceUser"
	}

	xRemoteFile Workspace {
		Uri = "$BinariesLocation/Artifactory/Workspace-$BinariesVersion.zip$binariesLocationSasToken"
		DestinationPath = $wsinstaller
	}

	Archive UnzipWorkspace {
		Destination = $InstallFolder
		Path = $wsinstaller
		Force = $True
		DependsOn = "[xRemoteFile]Workspace"
	}
}

Configuration WSFront
{
	param(
		[Parameter(Mandatory)]
		[string] $artifactsLocation,
		[Parameter(Mandatory)]
		[string] $artifactsLocationSasToken,
		[Parameter(Mandatory)]
		[string] $binariesLocationSasToken,
		[Parameter(Mandatory)]
		[string] $IdpUrl,
		[Parameter(Mandatory)]
		[string] $BinariesVersion,
		[Parameter(Mandatory)]
		[PSCredential] $AdminCreds,
		[string] $SplitPortalAndProvisioning

	)

	Import-DscResource -ModuleName PSDesiredStateConfiguration, xPSDesiredStateConfiguration, cChoco, xCertificate
	if ($SplitPortalAndProvisioning -eq "No") {
		$configFile = "Compact"
	}
	$configArtifact = "$artifactsLocation/wsfront/WSMISettings$configFile.json$artifactsLocationSasToken"
	
	$iisCert = Join-Path -Path $InstallFolder -ChildPath "ws.local.pfx"
	$citrixStorefrontExe = "CitrixStoreFront-x64.exe"
	$citrixStoreFrontPath = Join-Path -Path $InstallFolder -ChildPath $citrixStorefrontExe

	Node localhost
	{
		LocalConfigurationManager {
			RebootNodeIfNeeded = $true
		}

		ReplaceJsonFile ReplaceConfiguration {
			WsJsonUri = $configArtifact
			AdminCreds = $AdminCreds
			IdpUrl = $IdpUrl
			BinariesVersion = $BinariesVersion
		}

		xRemoteFile CitrixStorefront {
			Uri = "$BinariesLocation/prerequisites/$citrixStorefrontExe$binariesLocationSasToken"
			DestinationPath = $citrixStoreFrontPath
		}

		AddRootCa NestedRootCA {
			artifactsLocation = $artifactsLocation
			artifactsLocationSasToken = $artifactsLocationSasToken
		}

		if ($SplitPortalAndProvisioning -eq "No") {
			PortalBackend RobotDependencies {
				AdminCreds = $AdminCreds
			}
		}

		Common NestedCommon {
			AdminCreds = $AdminCreds
		}

		PortalFrontEnd FrontendDependencies {}

		DevTools NestedDevTools {}

		cChocoPackageInstaller vcredist2013
		{
			Name = "vcredist2013"
			Ensure = "Present"
			DependsOn   = "[DevTools]NestedDevTools"
		}

		cChocoPackageInstaller nodejs
		{
			Name = "nodejs-lts"
			Ensure = "Present"
			DependsOn   = "[cChocoPackageInstaller]vcredist2013"
		}

		xRemoteFile IISCertFile {
			Uri = "$artifactsLocation/ws.local.pfx$artifactsLocationSasToken"
			DestinationPath = $iisCert
		}

		xPfxImport IISCert
		{
			Thumbprint = "C41F7E2B6971DC66BA86722038AD660CA64D177E"
			Path       = $iisCert
			Location   = 'LocalMachine'
			Store      = 'WebHosting'
			#Credential = New-Object -TypeName pscredential -ArgumentList $NetworkService, (new-object System.Security.SecureString)
			DependsOn  = '[xRemoteFile]IISCertFile'
		}

		# Required to make nodejs path be in environment vars
		Script ForceReboot
		{
			TestScript = {
				return (Test-Path HKLM:\SOFTWARE\AzureDSCProvisioning\RebootKey)
			}
			SetScript = {
				New-Item -Path HKLM:\SOFTWARE\AzureDSCProvisioning\RebootKey -Force
				 $global:DSCMachineStatus = 1 

			}
			GetScript = { return @{result = 'result'}}
			DependsOn = @("[PortalFrontEnd]FrontendDependencies", "[cChocoPackageInstaller]nodejs")
		}    
		
		Script InstallCitrixStoreFront
		{
			SetScript = 
			{
				Set-Location -Path $using:InstallFolder

				$env:SEE_MASK_NOZONECHECKS = 1

				$res = Start-Process -FilePath $using:citrixStoreFrontPath -ArgumentList '-silent' -Wait -PassThru
				$res | select * | Out-File "C:\install\citrixinstall.log"

				if($res.ExitCode -gt 0) {
					throw "Error installing Citrix Storefront, exit code $($res.ExitCode)."
				}
			}
			TestScript = 
			{
				$installed = Get-WmiObject Win32_Product | Where-Object { $_.Vendor -like "Citrix*" } | Select-Object -ExpandProperty Name

				($installed -contains "Citrix StoreFront") -and ($installed -contains "Citrix Telemetry Service - x64")
			}
			GetScript = 
			{
				$version = Get-WmiObject Win32_Product | Where-Object { $_.Name -like "Citrix StoreFront" } | Select-Object -ExpandProperty Version

				return @{ Result = "$version" }
			}
			DependsOn = @("[xRemoteFile]CitrixStorefront", "[PortalFrontEnd]FrontendDependencies")
			PsDscRunAsCredential = $AdminCreds
		}

		Script InstallWorkspaces
		{
			SetScript = 
			{
				Set-Location -Path $using:InstallFolder
				$wsInstallerExe = Join-Path -Path $using:InstallFolder -ChildPath "ws10.Workspace.Setup.exe"

				$res = Start-Process -FilePath $wsInstallerExe -ArgumentList "/silentmode" -Wait -NoNewWindow -PassThru

				$res | select * | Out-File "C:\install\wsinstall.log"

				if($res.ExitCode -gt 0) {
					throw "Error installing Workspaces, exit code $($res.ExitCode)."
				}
			}
			TestScript = 
			{
				If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ASG CloudRobot Encryption") {
					$installed = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ASG CloudRobot Encryption' -ErrorAction SilentlyContinue
					($installed.DisplayName -contains "ASG CloudRobot Encryption")
				}
				Else {
					$False
				}
			}
			GetScript = 
			{
				$version = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ASG CloudRobot Encryption').Version

				return @{ Result = "$version" }
			}
			DependsOn = @("[ReplaceJsonFile]ReplaceConfiguration", "[Script]InstallCitrixStoreFront", "[cChocoPackageInstaller]nodejs")
			PsDscRunAsCredential = $AdminCreds
		}
	}
}

Configuration WSBack
{
	param(
		[Parameter(Mandatory)]
		[string] $artifactsLocation,
		[Parameter(Mandatory)]
		[string] $artifactsLocationSasToken,
		[Parameter(Mandatory)]
		[string] $binariesLocationSasToken,
		[Parameter(Mandatory)]
		[string] $BinariesVersion,
		[Parameter(Mandatory)]
		[PSCredential] $AdminCreds
	)

	Import-DscResource -ModuleName PSDesiredStateConfiguration, xPSDesiredStateConfiguration

	Node localhost
	{
		LocalConfigurationManager {
			RebootNodeIfNeeded = $true
		}

		ReplaceJsonFile ReplaceConfiguration {
			WsJsonUri = "$artifactsLocation/wsback/WSMISettings.json$artifactsLocationSasToken"
			AdminCreds = $AdminCreds
			BinariesVersion = $BinariesVersion
		}

		AddRootCa NestedRootCA {
			artifactsLocation = $artifactsLocation
			artifactsLocationSasToken = $artifactsLocationSasToken
		}

		PortalBackend RobotDependencies {
			AdminCreds = $AdminCreds
		}

		Script InstallWorkspaces
		{
			SetScript = 
			{
				Set-Location -Path $using:InstallFolder
				$wsInstallerExe = Join-Path -Path $using:InstallFolder -ChildPath "ws10.Workspace.Setup.exe"

				$res = Start-Process -FilePath $wsInstallerExe -ArgumentList "/silentmode" -Wait -NoNewWindow -PassThru

				$res | select * | Out-File "C:\install\wsinstall.log"

				if($res.ExitCode -gt 0) {
					throw "Error installing Workspaces, exit code $($res.ExitCode)."
				}
			}
			TestScript = 
			{
				If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ASG CloudRobot Encryption") {
					$installed = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ASG CloudRobot Encryption' -ErrorAction SilentlyContinue
					($installed.DisplayName -contains "ASG CloudRobot Encryption")
				}
				Else {
					$False
				}
			}
			GetScript = 
			{
				$version = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ASG CloudRobot Encryption').Version

				return @{ Result = "$version" }
			}
			DependsOn = @("[ReplaceJsonFile]ReplaceConfiguration", "[PortalBackend]RobotDependencies")
			PsDscRunAsCredential = $AdminCreds

		}

		# TODO If multiple front reference all QE in backend

		Common NestedCommon {
			AdminCreds = $AdminCreds
		}

		DevTools NestedDevTools {}
	}
}

Configuration WSSQL
{
	param(
		[Parameter(Mandatory)]
		[string] $artifactsLocation,
		[Parameter(Mandatory)]
		[string] $artifactsLocationSasToken,
		[Parameter(Mandatory)]
		[string] $TcpPort,
		[Parameter(Mandatory)]
		[PSCredential] $SqlCredential,
		[Parameter(Mandatory)]
		[PSCredential] $AdminCreds,
		[string] $SQLServerSKU
	)
	Import-DscResource -ModuleName PSDesiredStateConfiguration, xPSDesiredStateConfiguration, xSqlServer

	$getScript = Join-Path -Path $InstallFolder -ChildPath "Get-Workspace.sql"
	$setScript = Join-Path -Path $InstallFolder -ChildPath "Set-Workspace.sql"
	$testScript = Join-Path -Path $InstallFolder -ChildPath "Test-Workspace.sql"

	If($SQLSercerSKU -eq "Express") {
		$instanceName = "SQLExpress"
	}
	Else {
		$instanceName = "MSSQLSERVER"
	}

	Node localhost
	{
		xSQLServerNetwork ChangeTcpIpOnDefaultInstance
		{
			InstanceName = $instanceName
			ProtocolName = "Tcp"
			IsEnabled = $true
			TcpDynamicPort = $false
			TcpPort = $TcpPort
			RestartService = $true
		}
		
		<#xRemoteFile GetSqlScript{
			Uri = "$artifactsLocation/SQL/Get-Workspace.sql$artifactsLocationSasToken"
			DestinationPath = $getScript
			DependsOn = "[xSQLServerNetwork]ChangeTcpIpOnDefaultInstance"
		}

		xRemoteFile SetSqlScript{
			Uri = "$artifactsLocation/SQL/Set-Workspace.sql$artifactsLocationSasToken"
			DestinationPath = $setScript
			DependsOn = "[xRemoteFile]GetSqlScript"
		}

		xRemoteFile TestSqlScript{
			Uri = "$artifactsLocation/SQL/Test-Workspace.sql$artifactsLocationSasToken"
			DestinationPath = $testScript
			DependsOn = "[xRemoteFile]SetSqlScript"
		}

		xSQLServerScript CreateDatabase
        {
            ServerInstance = 'sql.ws.local'
            Credential     = $SqlCredential
            SetFilePath    = $setScript
            TestFilePath   = $testScript
            GetFilePath    = $getScript
            Variable       = @("FilePath=C:\temp\log\AuditFiles")
			DependsOn = "[xRemoteFile]TestSqlScript"
        }#>

		Common NestedCommon {
			AdminCreds = $AdminCreds
		}
	}
}

Configuration WSLBack
{
	param(
		[Parameter(Mandatory)]
		[string] $artifactsLocation,
		[Parameter(Mandatory)]
		[string] $artifactsLocationSasToken
	)

	Import-DscResource -ModuleName PSDesiredStateConfiguration, xPSDesiredStateConfiguration

	Node localhost
	{
		WindowsFeature WebServer {
            Ensure = "Present"
            Name   = "Web-Server"
			#IncludeAllSubFeature = $True
        }

		WindowsFeature IISMgmtConsole {
			Ensure = "Present"
			Name = "web-mgmt-tools"
			IncludeAllSubFeature = $True
			DependsOn = "[WindowsFeature]WebServer"
		}

		WindowsFeature WebASP {
			Ensure = "Present"
			Name = "Web-ASP-Net45"
			DependsOn = "[WindowsFeature]IISMgmtConsole"
		}

		AddRootCa NestedRootCA {
			artifactsLocation = $artifactsLocation
			artifactsLocationSasToken = $artifactsLocationSasToken
		}

		#Common NestedCommon {
		#	AdminCreds = $AdminCreds
		#}

		DevTools NestedDevTools {}
	}
}

Configuration WSLFront
{
	param(
		[Parameter(Mandatory)]
		[string] $artifactsLocation,
		[Parameter(Mandatory)]
		[string] $artifactsLocationSasToken
	)

	Import-DscResource -ModuleName PSDesiredStateConfiguration, xPSDesiredStateConfiguration, cChoco, xCertificate, xSystemSecurity, XNetworking

	$logFolder = "C:\Apache24\logs"

	Node localhost
	{
		WindowsFeature WslDependencies {
			Ensure = "Present"
			Name = "web-mgmt-tools"
			IncludeAllSubFeature = $True
		}

		#Common NestedCommon {
		#	AdminCreds = $AdminCreds
		#}

		AddRootCa NestedRootCA {
			artifactsLocation = $artifactsLocation
			artifactsLocationSasToken = $artifactsLocationSasToken
		}

		xFirewall ApacheWebPort {
			Name = "apacheweb"
			Ensure = "Present"
			DisplayName = "Apache https WSL web port"
			Action = "Allow"
			Profile = ("Public")
			Direction = "Inbound"
			LocalPort = ("443")
			Protocol = "TCP"
			Description = "Open port for enabling WSL external connectivity"
			Enabled = "True"
		}
		
		xFirewall ApacheIntPort {
			Name = "apacheint"
			Ensure = "Present"
			DisplayName = "Apache https WSL internal port"
			Action = "Allow"
			Profile = ("Public")
			Direction = "Inbound"
			LocalPort = ("3345")
			Protocol = "TCP"
			Description = "Open port for enabling internal WSL API"
			Enabled = "True"
		}

		DevTools NestedDevTools {}

		cChocoPackageInstaller Apache
		{
			Name = "apache-httpd"
			Params = "'/installLocation:C:\'"
			Ensure = "Present"
			DependsOn   = "[DevTools]NestedDevTools"
		}

		# TODO fix install dir not really applied as desired
		cChocoPackageInstaller PHP
		{
			Name = "php"
			Params = '"/ThreadSafe /InstallDir:C:\PHP"'
			DependsOn = "[cChocoPackageInstaller]Apache"
			Ensure = "Present"
		}

		xFileSystemAccessRule FullControlExample
        {
            Path = $logFolder
            Identity = $NetworkService
            Rights = @("FullControl")
			DependsOn = "[cChocoPackageInstaller]PHP"
        }

		Service ApacheOwner
		{
			Name = "Apache"
			BuiltInAccount = "NetworkService"
			DependsOn = "[xFileSystemAccessRule]FullControlExample"
		}

		File htintdocs
		{
			Ensure = "Present"
			Type = "Directory"
			DestinationPath = "C:\apache24\htintdocs"
			DependsOn = "[Service]ApacheOwner"
		}

		# https://stackoverflow.com/questions/29044864/managing-common-configuration-files-with-powershell-dsc
		# C:\Apache24\conf\httpd.conf : Listen 8080 -> Listen 80
		# uncomment : socache_shmcb_module, ssl_module, rewrite_module, headers_module, proxy_module and proxy_http_module
		# uncomment : Include conf/extra/httpd-ssl.conf
		# add : Include conf/extra/http-int-ssl.conf

		# LOGON PAGES
		# change : c:\Apache24\conf\extra\httpd-ssl.conf
		# change : -> Listen wsl-gsa.northeurope.cloudapp.azure.com https
		# change : -> <VirtualHost wsl-gsa.northeurope.cloudapp.azure.com:443>
		# more security with rewrite rules
		# point SSLCertificateFile and SSLCertificateKeyFile to own certificate
		# change all .log files to c:/log
		
		#File httpdintssl
		#{
		#	Ensure = "Present"
		#	Type = "File"
		#	SourcePath = "c:\Apache24\conf\extra\httpd-ssl.conf"
		#	DestinationPath = "c:\Apache24\conf\extra\httpd-int-ssl.conf"
		#	DependsOn = "[File]htintdocs"
		#}

		# change public ip to internal ip
		# change : DocumentRoot "${SRVROOT}/htintdocs"
		# add certificates for internal net

		# config php

		<# After last loadmodule

			LoadModule php7_module "c:/tools/php71/php7apache2_4.dll"
			AddType application/x-httpd-php .php 
			# configure the path to php.ini 
			PHPIniDir "C:/tools/php"
		#>

		# Uncompress FrontEnd

		# Include in httpd.conf : conf/extra/httpd-vsl.conf
		# edit conf/extra/httpd-vsl.conf, set wsfront and wslback FQDN

		# Add FEService directory in http-ssl.conf
	}
}

	Configuration JMeter {
		Import-DscResource -ModuleName PSDesiredStateConfiguration, xPSDesiredStateConfiguration, cChoco

		Node localhost {
			#Common NestedCommon {}

			DevTools NestedDevTools {}

			cChocoPackageInstallerSet Apps
			{
				Name = @(
					"jdk8"
					"7zip.install"
				)
				Ensure = "Present"
			}
		}
	}
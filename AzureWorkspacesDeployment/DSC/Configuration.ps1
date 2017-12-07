#
# Configuration.ps1
#

$InstallFolder = "C:\Install"
$BinariesLocation = "https://appmirrorbinaries.file.core.windows.net/host-applications"
$BinariesVersion = "master"
$NetworkService  = "NT AUTHORITY\NETWORK SERVICE"

$confData = @{
    AllNodes = @(
        @{
            NodeName = 'localhost'
            PSDscAllowPlainTextPassword = $true
        }
    )
}

configuration Common 
{ 
    Import-DscResource -ModuleName PSDesiredStateConfiguration

	LocalConfigurationManager
	{
		RebootNodeIfNeeded = $true
	}

	<#Service ModulesInstaller {
		Name = "TrustedInstaller"
		DisplayName = "Windows Modules Installer"
		StartupType = "Manual"
	}

	Service WindowsUpdate {
		DisplayName = "Windows Update"
		Name = "wuauserv"
		StartupType = "Disabled"
		State = "Stopped"
		DependsOn = "[Service]ModulesInstaller"
	}

	# https://msdn.microsoft.com/en-us/library/dd939844(v=ws.10).aspx
	Registry WindowsUpdate {
		Ensure = "Present"
		Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows"
		ValueName = "WindowsUpdate"
	}

	Registry WindowsUpdateAU {
		Ensure = "Present"
		Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
		ValueName = "AU"
		DependsOn = "[Registry]WindowsUpdate"
	}

	Registry NoAutoUpdate {
		Ensure = "Present"
		Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
		ValueName = "NoAutoUpdate"
		ValueData = 1
		DependsOn = "[Registry]WindowsUpdateAU"
	}#>

	# http://techibee.com/sysadmins/disable-server-manager-startup-from-user-login-using-registry-and-group-policies/2076
	Registry DoNotOpenServerManagerAtLogon {
		Ensure = "Present"
		Key = "HKLM:\SOFTWARE\Microsoft\ServerManager"
		ValueName = "DoNotOpenServerManagerAtLogon"
		ValueData = 1
	}
}

Configuration FrontEnd 
{
	Import-DscResource -ModuleName PSDesiredStateConfiguration, XNetworking

	xFirewall QueryEngineCtrl {
		Name = "QueryEngineCtrl"
		Ensure = "Present"
		DisplayName = "Query engine controller"
		Action = "Allow"
		Profile = ("Domain")
		Direction = "Inbound"
		LocalPort = ("8880")
		RemotePort = ("8880")
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
		RemotePort = ("8081", "8082")
		Protocol = "TCP"
		Description = "Open ports for query agent"
		Enabled = "True"
		DependsOn = "[xFirewall]QueryEngineCtrl"
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

Configuration WSFront
{
	param(
		[Parameter(Mandatory)]
		[string] $artifactsLocation,
		[Parameter(Mandatory)]
		[string] $artifactsLocationSasToken,
		[Parameter(Mandatory)]
		[string] $binariesLocationSasToken
	)

	Import-DscResource -ModuleName PSDesiredStateConfiguration, xPSDesiredStateConfiguration, cChoco, xCertificate
	$wsjson = Join-Path -Path $InstallFolder -ChildPath "WSMISettings.json"
	$iisCert = Join-Path -Path $InstallFolder -ChildPath "ws.local.pfx"
	$wsinstaller = Join-Path -Path $InstallFolder -ChildPath "Workspace-$BinariesVersion.zip"
	$citrixStorefrontExe = "CitrixStoreFront-x64.exe"
	$citrixStoreFrontPath = Join-Path -Path $InstallFolder -ChildPath $citrixStorefrontExe

	#DependensOn = '[WindowsFeature]WslDependencies'

	Node localhost
	{
		xRemoteFile ConfigJson {
			Uri = "$artifactsLocation/wsfront/WSMISettings.json$artifactsLocationSasToken"
			DestinationPath = $wsjson
		}

		xRemoteFile Workspace {
			Uri = "$BinariesLocation/Artifactory/Workspace-$BinariesVersion.zip$binariesLocationSasToken"
			DestinationPath = $wsinstaller
		}

		xRemoteFile CitrixStorefront {
			Uri = "$BinariesLocation/prerequisites/$citrixStorefrontExe$binariesLocationSasToken"
			DestinationPath = $citrixStoreFrontPath
		}

		Archive UnzipWorkspace {
			Destination = $InstallFolder
			Path = $wsinstaller
			Force = $True
			DependsOn = "[xRemoteFile]Workspace"
		}

		AddRootCa NestedRootCA {
			artifactsLocation = $artifactsLocation
			artifactsLocationSasToken = $artifactsLocationSasToken
		}

		WindowsFeatureSet  WorkspaceDependencies {
			Name = @("Web-Server","Web-App-Dev", "NET-Framework-Features", "NET-Framework-45-Core", "Web-WebSockets")
			Ensure = "Present"
			IncludeAllSubFeature = $True
		}

		Common NestedCommon {}

		FrontEnd NestedFrontend {}

		DevTools NestedDevTools {}

		cChocoPackageInstaller vcredist2013
		{
			Name = "vcredist2013"
			Ensure = "Present"
			DependsOn   = "[DevTools]NestedDevTools"
		}

		cChocoPackageInstaller nodejs
		{
			Name = "nodejs.install"
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

		
		Script InstallCitrixStoreFront
		{
			SetScript = 
			{
				$res = Start-Process -FilePath $using:citrixStoreFrontPath -ArgumentList '-silent' -Wait -ErrorAction Stop -PassThru

				if($res.ExitCode -gt 0) {
					throw "Error installing Citrix Storefront"
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
			DependsOn = "[xRemoteFile]CitrixStorefront"
		}

		$wsInstallerExe = Join-Path -Path $InstallFolder -ChildPath "ws10.Workspace.Setup.exe"
		
		Script InstallWorkspaces
		{
			SetScript = 
			{
				$res = Start-Process -FilePath $using:wsInstallerExe -ArgumentList "/silentmode" -Wait -NoNewWindow -PassThru

				if($res.ExitCode -gt 0) {
					throw "Error installing Citrix Storefront"
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
			DependsOn = @("[Archive]UnzipWorkspace", "[WindowsFeatureSet]WorkspaceDependencies", "[Script]InstallCitrixStoreFront", "[cChocoPackageInstaller]nodejs")
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
		[string] $binariesLocationSasToken
	)

	Import-DscResource -ModuleName PSDesiredStateConfiguration, xPSDesiredStateConfiguration

	$wsinstaller = Join-Path -Path $InstallFolder -ChildPath "Workspace-$BinariesVersion.zip"

	Node localhost
	{
		xRemoteFile ConfigJson {
			Uri = "$artifactsLocation/wsback/WSMISettings.json$artifactsLocationSasToken"
			DestinationPath = $rootCA = Join-Path -Path $InstallFolder -ChildPath "WSMISettings.json"
		}

		WindowsFeatureSet  WorkspaceDependencies {
			Name = @("NET-Framework-Features", "NET-Framework-45-Core")
			Ensure = "Present"
			IncludeAllSubFeature = $True
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

		AddRootCa NestedRootCA {
			artifactsLocation = $artifactsLocation
			artifactsLocationSasToken = $artifactsLocationSasToken
		}

		$wsInstallerExe = Join-Path -Path $InstallFolder -ChildPath "ws10.Workspace.Setup.exe"

		Script InstallWorkspaces
		{
			SetScript = 
			{
				$res = Start-Process -FilePath $using:wsInstallerExe -ArgumentList "/silentmode" -Wait -NoNewWindow -PassThru

				if($res.ExitCode -gt 0) {
					throw "Error installing Citrix Storefront"
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
			DependsOn = @("[Archive]UnzipWorkspace", "[WindowsFeatureSet]WorkspaceDependencies")
		}

		Common NestedCommon {}

		DevTools NestedDevTools {}
	}
}

Configuration WSSQL
{
	param(
		[Parameter(Mandatory)]
		[string] $TcpPort
	)
	Import-DscResource -ModuleName PSDesiredStateConfiguration, xSqlServer

	Node localhost
	{
		xSQLServerNetwork ChangeTcpIpOnDefaultInstance
		{
			InstanceName = "MSSQLSERVER"
			ProtocolName = "Tcp"
			IsEnabled = $true
			TcpDynamicPorts = ""
			TcpPort = $TcpPort
			RestartService = $true
		}

		Common NestedCommon {}
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

		Common NestedCommon {}

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

		Common NestedCommon {}

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
			Common NestedCommon {}

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
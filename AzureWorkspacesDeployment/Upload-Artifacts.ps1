#
# Upload_Artifacts.ps1
#

Param(
	[string] $Branch = "master",
	[string[]] $Components =  @("Workspace", "WSL", "AppDelivery" )
)

function DownloadFromArtifactory($component, $revision)
{
	$output = @{}

    $wc = New-Object System.Net.WebClient
    # Artifactory Read User
    $wc.Credentials = (New-Object System.Net.NetworkCredential "dhw_read",(ConvertTo-SecureString -AsPlainText -Force -String "DHWread_!"))
    $url = "https://bin-eu.asg.com/artifactory/DHW-Dev/Workspaces/$component/$revision-SNAPSHOT/$component-$revision-SNAPSHOT.zip"
    # Get latest snapshot buildid
    $latestSnapshotName = $wc.DownloadString("https://bin-eu.asg.com/artifactory/api/search/latestVersion?g=Workspaces&a=$component&v=$revision-SNAPSHOT")
    $artifactInfo = $wc.DownloadString("https://bin-eu.asg.com/artifactory/api/storage//DHW-Dev/Workspaces/$component/master-SNAPSHOT/$component-$latestSnapshotName.zip?properties=build.number") | ConvertFrom-Json
    $output.buildId = $artifactInfo.properties.'build.number'
	
    Write-Host "Detected artifact $latestSnapshotName from build $($output.buildId) for $component"
	$output.file = (New-TemporaryFile).FullName

    Write-Host "Donwloading $url to $($output.file)"
    try {
        $t = Measure-Command { $wc.DownloadFile($url, $output.file) }
        Write-Host "Download took $($t.TotalSeconds) seconds"
        $wc.Dispose()
    }
    catch {
        throw "Error getting artifact $($_.Exception.Message)"
    }

	return $output
}

$ctx = New-AzureStorageContext -StorageAccountName appmirrorbinaries -StorageAccountKey (Get-AzureRmStorageAccountKey -ResourceGroupName AppMirror_Scallability_Tests -Name appmirrorbinaries)[0].Value

foreach($component in $Components ) {
	$artifact = DownloadFromArtifactory $component $Branch
	Write-Output "Upload $component $branch Id $($artifact.buildId) -> Artifactory/$component-$Branch.zip"
	Set-AzureStorageFileContent -ShareName host-applications -Source $artifact.file -Path "Artifactory/$component-$Branch.zip" -Context $ctx -Force
}

 #Get-AzureStorageShare -Name host-applications -Context $ctx | New-AzureStorageShareSASToken -Permission "r" -Context $ctx -ExpiryTime (Get-Date).AddDays(30)

 Write-Output "Current Azure content"
 Get-AzureStorageFile -ShareName host-applications -Context $ctx -Path Artifactory | Get-AzureStorageFile
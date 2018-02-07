<#
This script is intended to decrypt the config files for the WS provisioning services.
#>

$files = @(
"C:\Program Files\ASG Workspaces\ASG CloudRobot BUS Adapter\WfeBusAdapter.exe",
"C:\Program Files\ASG Workspaces\ASG CloudRobot Repository API\RepositoryWindowsServices.exe",
"C:\Program Files\ASG Workspaces\ASG CloudRobot Workflow Engine\CloudRobot.WorkflowEngine.Service.exe",
"C:\Program Files\ASG Workspaces\ASG CloudRobot Scheduler\Scheduler.Service.exe"
)

foreach ($file in $files) {
    $exec = """C:\Program Files\ASG Workspaces\ASG CloudRobot Encryption\ConfigSectionCrypter.exe"" --mode=Decrypt ""--app=$($file)""  --section=connectionStrings"
    Write-Output $exec
    cmd.exe /c $exec
    #Start-Process -FilePath "C:\Program Files\ASG Workspaces\ASG CloudRobot Encryption\ConfigSectionCrypter.exe" -ArgumentList "--mode=Decrypt ""--app=$file"" connectionStrings" -Wait -NoNewWindow
}
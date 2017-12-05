# https://technet.microsoft.com/de-de/library/ee617253.aspx

Import-Module ActiveDirectory
$userName = "testsp4"
$password = "Asg2017!" | ConvertTo-SecureString -AsPlainText -Force
[array]$a = 1..2

foreach ($i in $a)
{
	Write-Host "Creating $userName$i"
	#With Roaming Profile:
	#New-ADUser -Name TestuserAM$i -GivenName TestuserAM$i -Surname TestuserAM$i -Path "OU=Test,DC=AppMirror,DC=local" -AccountPassword $Password -HomeDrive "H:" -HomeDirectory "\\filer01.appmirror.local\Home\Testuser$i" -ProfilePath "\\filder01.appmirror.local\profile\Testuser$i" -ChangePasswordAtLogon $False -Enabled $True
	
	#Without Roaming Profile:
	New-ADUser -Name $userName$i -GivenName "$userName$i" -Surname "$userName$i" -UserPrincipalName "$userName$i@ws.local" -Path "OU=TestSP4,DC=ws,DC=local" -AccountPassword $Password -ChangePasswordAtLogon $False -Enabled $True -EmailAddress "$userName$i@ws.local"
}
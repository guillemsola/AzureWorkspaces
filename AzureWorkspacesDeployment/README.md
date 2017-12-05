# Create a new Windows VM and create a new AD Forest, Domain and DC

This template will deploy a new VM (along with a new VNet, Storage Account and Load Balancer) and will configure it as a Domain Controller and create a new forest and domain.

Click the button below to deploy

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FAzure%2Fazure-quickstart-templates%2Fmaster%2Factive-directory-new-domain%2Fazuredeploy.json" target="_blank">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>
<a href="https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FAzure%2Fazure-quickstart-templates%2Fmaster%2Factive-directory-new-domain%2Fazuredeploy.json" target="_blank">
    <img src="http://azuredeploy.net/AzureGov.png"/>
</a>
<a href="http://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com%2FAzure%2Fazure-quickstart-templates%2Fmaster%2Factive-directory-new-domain%2Fazuredeploy.json" target="_blank">
    <img src="http://armviz.io/visualizebutton.png"/>
</a>

## DSC With secured parameters

Reference in case this scenario is needed

```json
        {
          "type": "extensions",
          "name": "DSCConfiguration",
          "apiVersion": "2015-06-15",
          "tags": {
            "displayName": "DSC Configuration"
          },
          "location": "[resourceGroup().location]",
          "dependsOn": [
            "[variables('WSFrontVMName')]",
            "[concat('Microsoft.Compute/virtualMachines/', variables('WSFrontVMName'), '/extensions/joindomain')]"
          ],
          "properties": {
            "publisher": "Microsoft.Powershell",
            "type": "DSC",
            "typeHandlerVersion": "2.19",
            "autoUpgradeMinorVersion": true,
            "settings": {
              "configuration": {
                "url": "[concat(parameters('_artifactsLocation'), '/Configuration.zip')]",
                "script": "Configuration.ps1",
                "function": "WSFront"
              },
              "configurationArguments": {
                "domainName": "[parameters('domainName')]"
              },
			  "configurationData": {
				"url": "[concat(parameters('_artifactsLocation'), '/Configuration.psd1')]"
			  },
            },
            "protectedSettings": {
              "configurationUrlSasToken": "[parameters('_artifactsLocationSasToken')]",
			  "configurationDataUrlSasToken": "[parameters('_artifactsLocationSasToken')]",
              "configurationArguments": {
                "AdminCreds": {
                  "UserName": "[parameters('adminUsername')]",
                  "Password": "[parameters('adminPassword')]"
                }
              }
            }
          }
        }
```

To receive those values in the PS configuration script

```powershell

Configuration JoinDomain
{
	param 
    ( 
        [Parameter(Mandatory)]
        [String]$domainName,

        [Parameter(Mandatory)]
        [PSCredential]$adminCreds
    ) 
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration

    $domainCreds = New-Object System.Management.Automation.PSCredential ("$domainName\$($adminCreds.UserName)", $adminCreds.Password)
}
```
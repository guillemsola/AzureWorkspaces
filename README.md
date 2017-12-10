# AzureWorkspaces

Having a functional Workspaces Portal is just one click from you!

[![Deploy to Azure](http://azuredeploy.net/deploybutton.png)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fguillemsola%2FAzureWorkspaces%2Fmaster%2FAzureWorkspacesDeployment%2Fazuredeploy.json)

## Summary

This is an Azure Marketplace ready Muti-VM ARM template. It will deploy a self-conatined solution with a dedicated Domain Controller, SQL Server with Development License Database, Linux machine for the RabbitMQ and two Windows Server 2016 to host the Workspaces Portal as well as the provisioning Services.

## Deployment

Click the "Deploy to Azure" button and fill the required values once logged in the Azure portal. Those are the parameters that need to be filled.

- Admin user name: The root WS user name for the first login. It will be used to as the name of the administrator account of the new VMs and domain. 
- Admin password: The password for the administrator account of the new VM and domain.
- Domain name: The FQDN of the Active Directory Domain to be created. Notice that currently **value is limited to ws.local**
- DNS prefix: The DNS prefix for the public IP address used for the WS Portal website and server __http://**dnsprefix**.westeurope.cloudapp.azure.com/Workspace__. The full DNS name has to be unique for each Azure region.
- Artifacts location: The location of resources, such as templates and DSC modules, that the template depends on. Let it to the github project to use defaults.
- Artifacts location SAS token: Auto-generated token to access template resources. Notice that github does not require it but deployment template yes. Leave it to ?foo in this case.
- Binaries location SAS token: Token to access ASG installer binaries that has been given to you. Beware that token has a date of expiry.
- VM Size: The default size applied for virtual machines.

## Technical details

Resource will create an Active Directory machine with a local domain. A domain user wil be created to administer all the machines and connect to the portal.

RabbitMQ will be created in a dedicated Ubuntu 16.04 machine.

A SQL Server with development license machine will be created to host the various databases. Notice that the aim of this template is to test Workspaces in Azure and no intended for production deployments.

Workspace Portal will be deployed in a Windows 2016 server.

Provisioning Services will be deployed in a dedicated Windows Server 2016 machine.

All the dependencies will be satisfied at deployment time using Microsoft Desired State Configuration technology.

A network security group will be created to harden all the infrastructure. Outside access is only granted to portal machine through the dedicated Azure dynamic DNS.

Web Secure Logon deployment is not provided with this template as well as HTML5 Remote Apps.
# AzureKeyVaultPasswordRepo PowerShell Module
##Description
This repository contains the source code of the AzureKeyVaultPasswordRepo PowerShell module. AzureKeyVaultPasswordRepo PS module provides a PowerShell console based menu driven interface for users to manage password-based credentials in an Azure Key Vault.

##Install Instruction
###Install from PowerShell Gallery
Install-module AzureKeyVaultPasswordRepo

###Manually Install
Download this module from github, and place the AzureKeyVaultPasswordRepo module folder to 'C:\Program Files\WindowsPowerShell\Modules'

###Download from PowerShell Gallery
Find-Module AzureKeyVaultPasswordRepo | Save-Module -Force -Path 'C:\Temp'

##PowerShell functions
###Invoke-AzureKeyVaultPasswordRepository
Launch Azure Key Vault Password Repository

Use Get-Help Invoke-AzureKeyVaultPasswordRepository -Full to access the help file for this function.

####Aliases
ipr
Start-PasswordRepo

Use Get-Help New-AzureTableEntity -Full to access the help file for this function.

##Additional information:

###PowerShell Gallery:
https://www.powershellgallery.com/packages/AzureTableEntity

###Sample code on GitHub Gist:
https://gist.github.com/tyconsulting/1ff706181d8e476528c86b8f7ac8af23
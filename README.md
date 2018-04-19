# AzureKeyVaultPasswordRepo PowerShell Module

## Description

This repository contains the source code of the AzureKeyVaultPasswordRepo PowerShell module.

The AzureKeyVaultPasswordRepo PS module provides a PowerShell console based, menu driven interface for users to manage password-based credentials in an Azure Key Vault.

## Install Instructions

### Installing from PowerShell Gallery

To instal the AzureKeyVaultPasswordRepo module from the PowerShell gallery, run the following command in a PowerShell environment (you may need to temporarily reduce your execution policies - click [here](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-6) for guidacne on how to do that)

    Install-module AzureKeyVaultPasswordRepo

### Manual Installation

Download this module from github, and place the AzureKeyVaultPasswordRepo module folder to `C:\Program Files\WindowsPowerShell\Modules`

### Download from PowerShell Gallery

In order to download the AzureKeyVaultPasswordRepo module from the PowerShell gallery without installing it, run the following command in a PowerShell environment:

    Find-Module AzureKeyVaultPasswordRepo | Save-Module -Force -Path 'C:\Temp'

## PowerShell functions

### Invoke-AzureKeyVaultPasswordRepository

Launch Azure Key Vault Password Repository

Use `Get-Help Invoke-AzureKeyVaultPasswordRepository -Full` to access the help file for this function.

#### Aliases

- ipr
- Start-PasswordRepo

## Additional information:

### PowerShell Gallery

Additional information can be found at the PowerShell gallery page for the AzureKeyVaultPasswordRepo module; which can be found [here](https://www.powershellgallery.com/packages/AzureKeyVaultPasswordRepo).

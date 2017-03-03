Function New-Passowrd
{
  [OutputType([System.Security.SecureString])]
  [CmdletBinding()]
  PARAM (
    [Parameter(Mandatory = $true)][int]$Length,
    [Parameter(Mandatory = $true)][int]$NumberOfSpecialCharacters
  )
  Add-Type -AssemblyName System.Web
  $PwString = [Web.Security.Membership]::GeneratePassword($Length,$NumberOfSpecialCharacters)
  $secString = New-Object System.Security.SecureString
  For ($i = 0; $i -lt $PwString.length; $i++)
  {
    $char = $PwString.Substring($i, 1)
    $secString.AppendChar($char)
  }
  $secString
}
Function Get-ExistingCred
{
  [OutputType([System.Collections.ArrayList])]
  [CmdletBinding()]
  PARAM (
    [Parameter(Mandatory = $false)][string]$SearchString = $null
  )
  #Get existing secrets from key vault
  If ($PSBoundParameters.ContainsKey('SearchString'))
  {
    $ExistingSecrets = Get-AzureKeyVaultSecret -VaultName $Global:KeyVaultName|
    Where-Object -FilterScript {
      $_.Tags.ContainsKey('CredName')
    } |
    Where-Object -FilterScript {
      $_.Tags['CredName'] -imatch $SearchString
    }
  }
  else 
  {
    $ExistingSecrets = Get-AzureKeyVaultSecret -VaultName $Global:KeyVaultName
  }
  
  #Get credential names
  $ExistingCredNames = $ExistingSecrets |
  ForEach-Object -Process {
    $_.tags['CredName']
  } |
  Get-Unique
  #Get credential user names
  $arrExistingCreds = New-Object -TypeName System.Collections.ArrayList
  FOreach ($item in $ExistingCredNames)
  {
    $UserNameSecret = $ExistingSecrets | Where-Object -FilterScript {
      $_.Tags['CredName'] -eq $item -and $_.Tags['Type'] -eq 'UserName'
    }
    $PasswordSecret = $ExistingSecrets | Where-Object -FilterScript {
      $_.Tags['CredName'] -eq $item -and $_.Tags['Type'] -eq 'Password'
    }
    $UserName = (Get-AzureKeyVaultSecret -VaultName $Global:KeyVaultName -Name $UserNameSecret.Name).SecretValueText
    $objExistingCred = New-Object -TypeName psobject -Property @{
      CredName           = $item
      UserName           = $UserName
      UserNameSecretName = $UserNameSecret.Name
      PasswordSecretName = $PasswordSecret.Name
    }
    [void]$arrExistingCreds.Add($objExistingCred)
  }
  ,$arrExistingCreds
}
Function New-KeyVaultCred
{
  $NewCredName = $null
  $NewCredUserName = $null
  Do
  {
    $NewCredName = Read-Host -Prompt 'Give your new credential a name (only contain alphanumeric characters and dash)'
  }
  while ($NewCredName.Length -eq 0 -or $NewCredName -notmatch '^[0-9a-zA-Z-]+$')
  Do
  {
    $NewCredUserName = Read-Host -Prompt 'Enter user name'
  }
  while ($NewCredUserName.Length -eq 0)
  $NewCredPassword = Read-Host -Prompt "Enter new password or hit enter to generate a random password with $Global:RandomPasswordLength character in length with $Global:RandomPasswordSpecialCharactersCount special characters" -AsSecureString
  $UserNameSecretName = "$NewCredName`-UserName"
  $PasswordSecretName = "$NewCredName`-Password"
  
  #preparing for the tags
  $UTags = @{
    CredName = "$NewCredName"
    Type     = 'UserName'
  }
  $PTags = @{
    CredName = "$NewCredName"
    Type     = 'Password'
  }
        
  #Create secrets
  Write-Output -InputObject 'Creating Credential in key vault. please wait...'
  #user name 
  $NewCredUserNameSecString = New-Object System.Security.SecureString
  For ($i = 0; $i -lt $NewCredUserName.length; $i++)
  {
    $char = $NewCredUserName.Substring($i, 1)
    $NewCredUserNameSecString.AppendChar($char)
  }
  $NewUserSecret = Set-AzureKeyVaultSecret -VaultName $Global:KeyVaultName -Name $UserNameSecretName -SecretValue $NewCredUserNameSecString -Tag $UTags -ErrorVariable errCreateNewUserName
  #password secret
  $bNewCopyPassworToClipboard = $false
  If ($NewCredPassword.length -eq 0)
  {
    Write-Output -InputObject 'Password not specified. Generating a new password...'
    $NewCredPassword = New-Passowrd -Length $Global:RandomPasswordLength -NumberOfSpecialCharacters $Global:RandomPasswordSpecialCharactersCount
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewCredPassword)
    $NewCredPasswordClearText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    $bNewCopyPassworToClipboard = $true
  }
  $NewPasswordSecret = Set-AzureKeyVaultSecret -VaultName $Global:KeyVaultName -Name $PasswordSecretName -SecretValue $NewCredPassword -Tag $PTags -ErrorVariable errCreateNewPassword
  If ($errCreateNewUserName.Count -eq 0 -and $errCreateNewPassword.Count -eq 0)
  {
    Write-Host -Object 'Credential successfully created.' -ForegroundColor Green
    if ($bNewCopyPassworToClipboard -eq $true)
    {
      $NewCredPasswordClearText | clip.exe
      Write-Host -Object 'Password copied to clipboard.' -ForegroundColor Green
      Write-output ""
    }
  }
  Write-Output -InputObject ''
}

Function Get-KeyVaultCred
{
  [CmdletBinding()]
  PARAM (
    [Parameter(Mandatory = $false)][switch]$Search
  )
  If ($Search)
  {
    Write-Host -Object 'Search credential' -ForegroundColor Yellow
    Do
    {
      $SearchString = Read-Host -Prompt 'Enter search string (only contain alphanumeric characters and dash)'
    }
    while ($SearchString.Length -eq 0 -or $SearchString -notmatch '^[0-9a-zA-Z-]+$')
    Write-Output -InputObject ''
    $ExistingCreds = Get-ExistingCred -SearchString $SearchString
  }
  else 
  {
    $ExistingCreds = Get-ExistingCred
  }
  
  If ($ExistingCreds.count -gt 0)
  {
    Write-Output -InputObject "Number of existing credential(s) found in Azure Key Vault: $($ExistingCreds.count)"
    Write-Host -Object 'Select credential:' -ForegroundColor DarkGray
    $i = 0
    Write-Host -Object " $i. Go Back" -ForegroundColor DarkGray
    Foreach ($item in $ExistingCreds)
    {
      $i++
      Write-Host -Object " $i. $($item.CredName) `($($item.UserName)`)" -ForegroundColor Yellow
    }
    Do 
    {
      [int]$ans = Read-Host -Prompt "Enter selection (0 - $i)"
      if ($ans -gt 0 -and $ans -le $i)
      {
        Write-Output -InputObject ''
        #retrieve the cred
        $SelectedCred = $ExistingCreds[$ans-1]
        
        Do 
        {
          Write-Host -Object "Selected credential name: $($SelectedCred.CredName)" -ForegroundColor DarkGray
          Write-Host -Object '   0. Go Back' -ForegroundColor DarkGray
          Write-Host -Object '   1. Copy User Name to clipboard' -ForegroundColor Yellow
          Write-Host -Object '   2. Copy Password to clipboard' -ForegroundColor Yellow
          Write-Host -Object '   3. Update Credential' -ForegroundColor Yellow
          Write-Host -Object '   4. Delete Credential' -ForegroundColor Yellow
          Do 
          {
            [int]$GetCredOption = Read-Host -Prompt 'Enter selection (0 - 4)'
          }
          Until ($GetCredOption -ge 0 -and $GetCredOption -le 4)
          Write-Output -InputObject ''
          If ($GetCredOption -eq 1) #Copy username to clipboard
          {
            $ExistingCredUserName = (Get-AzureKeyVaultSecret -VaultName $Global:KeyVaultName -Name $SelectedCred.UserNameSecretName).SecretValueText
            $ExistingCredUserName | clip.exe
            Write-Host -Object 'User Name copied to clipboard.' -ForegroundColor Green
            Write-output ""
            Write-Output -InputObject ''
          }
          elseif ($GetCredOption -eq 2) #Copy password to clipboard
          {
            $ExistingCredPassword = (Get-AzureKeyVaultSecret -VaultName $Global:KeyVaultName -Name $SelectedCred.PasswordSecretName).SecretValueText
            $ExistingCredPassword | clip.exe
            Write-Host -Object 'Password copied to clipboard.' -ForegroundColor Green
            Write-output ""
          }
          elseif ($GetCredOption -eq 3) #Update
          {
            $UpdatedUserName = Read-Host -Prompt 'Enter new user name or hit enter to keep the existing user name'
            $UpdatedPassword = Read-Host -Prompt "Enter new password or hit enter to generate a random password with $Global:RandomPasswordLength character in length with $Global:RandomPasswordSpecialCharactersCount special characters" -AsSecureString
            $bEditCopyPassworToClipboard = $false
            If ($UpdatedPassword.length -eq 0)
            {
              Write-Output -InputObject 'Password not specified. Generating a new password...'
              $UpdatedPassword = New-Passowrd -Length $Global:RandomPasswordLength -NumberOfSpecialCharacters $Global:RandomPasswordSpecialCharactersCount
              $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($UpdatedPassword)
              $UpdatedPasswordClearText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
              $bEditCopyPassworToClipboard = $true
            }

            Write-Output -InputObject 'Updating Credential in key vault. please wait...'
            If ($UpdatedUserName.Length -gt 0)
            {
              #Upate the user name secret
               $UpdatedUserNameSecString = New-Object System.Security.SecureString
              For ($i = 0; $i -lt $UpdatedUserName.length; $i++)
              {
                $char = $UpdatedUserName.Substring($i, 1)
                $UpdatedUserNameSecString.AppendChar($char)
              }
              $ExistingUserNameSecret = Get-AzureKeyVaultSecret -VaultName $Global:KeyVaultName -Name $SelectedCred.UserNameSecretName
              $UpdateUserNameSecret = Set-AzureKeyVaultSecret -VaultName $Global:KeyVaultName -Name $ExistingUserNameSecret.Name -SecretValue $UpdatedUserNameSecString -Tag $($ExistingUserNameSecret.Attributes.Tags) -ErrorVariable errUpdateUserName
            }
            #Update the password secret
            $ExistingPasswordSecret = Get-AzureKeyVaultSecret -VaultName $Global:KeyVaultName -Name $SelectedCred.PasswordSecretName
            $UpdatePasswordSecret = Set-AzureKeyVaultSecret -VaultName $Global:KeyVaultName -Name $ExistingPasswordSecret.Name -SecretValue $UpdatedPassword -Tag $($ExistingPasswordSecret.Attributes.Tags) -ErrorVariable errUpdatePassword
            If ($errUpdateUserName.Count -eq 0 -and $errUpdatePassword.Count -eq 0)
            {
              Write-Host -Object 'Credential successfully updated.' -ForegroundColor Green
              if ($bEditCopyPassworToClipboard -eq $true)
              {
                $UpdatedPasswordClearText | clip.exe
                Write-Host -Object 'Password copied to clipboard.' -ForegroundColor Green
                Write-output ""
              }
            }
            Write-Output -InputObject ''
          }
          elseif ($GetCredOption -eq 4) #delete
          {
            #Confirm
            $DeleteConfirmationTitle = 'Confirming Credential Deletion'
            $DeleteConfirmationMessage = "Are you sure you want to delete credential '$($SelectedCred.CredName)'?"
            $yes = New-Object -TypeName System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes', 'Delete.'
            $no = New-Object -TypeName System.Management.Automation.Host.ChoiceDescription -ArgumentList '&No', 'Keep.'
            $DeleteConfirmOptions = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
            $DeleteConfirmed = $host.ui.PromptForChoice($DeleteConfirmationTitle, $DeleteConfirmationMessage, $DeleteConfirmOptions, 0) 
            If ($DeleteConfirmed -eq 0)
            {
              #Yes selected
              #Remove the user name secret
              $DeleteUserNameSecret = Remove-AzureKeyVaultSecret -VaultName $Global:KeyVaultName -Name $SelectedCred.UserNameSecretName -Force -Confirm:$false  -ErrorVariable errDeleteUserName
              #Remove the password secret
              $DeletePasswordSecret = Remove-AzureKeyVaultSecret -VaultName $Global:KeyVaultName -Name $SelectedCred.PasswordSecretName -Force -Confirm:$false  -ErrorVariable errDeletePassword
              If ($errDeleteUserName.Count -eq 0 -and $errDeletePassword.Count -eq 0)
              {
                Write-Host -Object 'Credential successfully deleted.' -ForegroundColor Green
                $ExistingCreds.Remove($SelectedCred)
                #Go back to the parent menu
                $GetCredOption = 0
              }
              Write-Output -InputObject ''
            }
          }
        }
        Until ($GetCredOption -eq 0)
      }
    }
    while ($ans -lt 0 -or $ans -gt $i)
    Write-Output -InputObject ''
  }
  else 
  {
    Write-Host -Object 'No credentials are found in the Azure Key Vault.' -ForegroundColor Red
  }
  Write-Output -InputObject ''
}

Function Save-KeyVaultRepoProfile
{
  #confirm
  Write-Output -InputObject 'By Saving the selected Azure subscription and Key Vault in registry, you will no need to select them again.'
  $SaveProfileConfirmationTitle = 'Save Profile'
  $SaveProfileConfirmationMessage = 'Are you sure you want to save selected Azure subscription Id and key vault name in your profile?'
  $yes = New-Object -TypeName System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes', 'Save.'
  $no = New-Object -TypeName System.Management.Automation.Host.ChoiceDescription -ArgumentList '&No', "Don't Save."
  $SaveProfileConfirmOptions = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
  $SaveProfileConfirmed = $host.ui.PromptForChoice($SaveProfileConfirmationTitle, $SaveProfileConfirmationMessage, $SaveProfileConfirmOptions, 0) 
  If ($SaveProfileConfirmed -eq 0)
  {
    #Yes selected
    $context = Get-AzureRmContext 
    #Create a new regkey
    $NewRegKey = New-Item -Path $Global:SettingRegPath -Name $context.account.id -Force
    $ProfilePath = Join-Path -Path $Global:SettingRegPath -ChildPath $context.account.id
    #Save Azure Subscription Id
    $AzureSubIdRegValue = New-ItemProperty -Path $ProfilePath -Name AzureSubscriptionId -Value $context.Subscription.SubscriptionId -PropertyType 'String' -Force
    $AzureKeyVaultNameRegValue = New-ItemProperty -Path $ProfilePath -Name AzureKeyVaultName -Value $Global:KeyVaultName -PropertyType 'String' -Force
    Write-Host -Object 'Profile saved.' -ForegroundColor Green
    Write-Output -InputObject ''
  }
}
Function Get-KeyVaultRepoProfile
{
  $context = Get-AzureRmContext
  $RegKeyPath = Join-Path -Path $Global:SettingRegPath -ChildPath $context.Account.Id
  If (Test-Path $RegKeyPath)
  {
    Try 
    {
      $regvalues = Get-ItemProperty -Path $RegKeyPath -ErrorAction SilentlyContinue
      $AzureSubId = $regvalues.AzureSubscriptionId
      $KeyVaultName = $regvalues.AzureKeyVaultName
    }
    catch 
    {
      $AzureSubId = $null
      $KeyVaultName = $null
    }
  }

  If ($AzureSubId.Length -gt 0 -and $KeyVaultName -gt 0)
  {
    $objProperty = @{
      'AzureSubId' = $AzureSubId
      'KeyVaultName' = $KeyVaultName
    }
    $objProfile = New-Object -TypeName psobject -Property $objProperty
    $objProfile
  }
  else 
  {
    $null
  }
}

Function Remove-KeyVaultRepoProfile
{
  $context = Get-AzureRmContext
  $RegKeyPath = Join-Path -Path $Global:SettingRegPath -ChildPath $context.Account.Id
  If (Test-Path $RegKeyPath)
  {
    #delete the registry 
    #confirm
    Write-Output -InputObject 'By Deleting the Key Vault Password Repository Profile from registry, you will need to manually select Azure Subscription and key vault when you use it next time.'
    $DeleteProfileConfirmationTitle = 'Delete Profile'
    $DeleteProfileConfirmationMessage = 'Are you sure you want to delete your profile?'
    $yes = New-Object -TypeName System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes', 'Delete.'
    $no = New-Object -TypeName System.Management.Automation.Host.ChoiceDescription -ArgumentList '&No', "Don't Delete."
    $DeleteProfileConfirmOptions = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $DeleteProfileConfirmed = $host.ui.PromptForChoice($DeleteProfileConfirmationTitle, $DeleteProfileConfirmationMessage, $DeleteProfileConfirmOptions, 0) 
    If ($DeleteProfileConfirmed -eq 0)
    {
      #Yes selected
      $DeleteKey = Remove-Item -Path $RegKeyPath -Recurse -Force -ErrorVariable errDeleteProfile
      If ($errDeleteProfile.Count -eq 0)
      {
        Write-Host -Object 'Profile Deleted.' -ForegroundColor Green
        Write-Output -InputObject ''
      }
      else 
      {
        Write-Error -Message 'Failed to delete the profile.'
      }
    }
  }
  else 
  {
    Write-Host -Object "No profile exists for the current user Id '$($context.Account.Id)'." -ForegroundColor Red
  }
}

Function Add-KeyVaultFullAccessPolicy
{
  
  Do
  {
    $AADSearchString = Read-Host -Prompt 'Enter a search string for the Azure AD user to search Azure Active Directory (i.e. name)'
    $AADUsers = Get-AzureRmADUser -SearchString $AADSearchString
    If ($AADUsers.count -eq 0)
    {
      Write-Host -Object 'No Azure AD users found that matches the search string. Please enter another search string' -ForegroundColor Red
    }
  }
  until ($AADUsers.count -gt 0)
  for ($i = 1;$i -le $AADUsers.count; $i++) 
  {
    Write-Host -Object "$i. $($AADUsers[$i-1].DisplayName) `| UPN: $($AADUsers[$i-1].UserPrincipalName) `| Object Id: $($AADUsers[$i-1].Id.ToString())" -ForegroundColor Yellow
  }
  Write-Host -Object 'Select the User Accountccount' -ForegroundColor Yellow
  [int]$ans = Read-Host -Prompt 'Enter selection'
  $VaultAdmin = $AADUsers[$ans-1]
  $VaultAdminObjectId = $VaultAdmin.Id.ToString()
  Write-Output -InputObject "Configuring Key Vault Access Policy for '$($VaultAdmin.UserPrincipalName)'."
  Set-AzureRmKeyVaultAccessPolicy -VaultName $Global:KeyVaultName -ObjectId $VaultAdminObjectId -PermissionsToKeys all -PermissionsToSecrets all -ErrorAction errAddAccess
  If ($errAddAccess.Count -eq 0)
  {
    Write-Host -Object 'Key Vault access granted.' -ForegroundColor Green
    Write-Output -InputObject ''
  }
  else 
  {
    Write-Error -Message 'Failed to grant access to the Key Vault.'
    Write-Output -InputObject ''
  }
}

Function Remove-KeyVaultFullAccessPolicy
{
  #Get keyvault
  $KeyVault = Get-AzureRmKeyVault -VaultName $Global:KeyVaultName
  #Get Access policies
  $AccessPolicies = $KeyVault.AccessPolicies
  Write-Host -Object 'Select Account to Remove:' -ForegroundColor DarkGray
  $i = 0
  Write-Host -Object " $i. Go Back" -ForegroundColor DarkGray
  Foreach ($item in $AccessPolicies)
  {
    $i++
    Write-Host -Object " $i. $($item.DisplayName) `(Object Id: $($item.ObjectId)`)" -ForegroundColor Yellow
  }
   Do 
    {
      [int]$ans = Read-Host -Prompt "Enter selection (0 - $i)"
      if ($ans -gt 0 -and $ans -le $i)
      {
        $AccessPolicyToRemove = $AccessPolicies[$i-1]
        #Confirm
        Write-Output -InputObject 'By removing the access to Key Vault, the selected user will no longer have access to the credentials saved in this key vault.'
        $DeleteAccessConfirmationTitle = 'Remove Access'
        $DeleteAccessConfirmationMessage = "Are you sure you want to remove Key Vault access for '$($item.DisplayName)'?"
        $yes = New-Object -TypeName System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes', 'Remove.'
        $no = New-Object -TypeName System.Management.Automation.Host.ChoiceDescription -ArgumentList '&No', "Don't Remove."
        $DeleteAccessConfirmOptions = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
        $DeleteAccessConfirmed = $host.ui.PromptForChoice($DeleteAccessConfirmationTitle, $DeleteAccessConfirmationMessage, $DeleteAccessConfirmOptions, 0) 
        If ($DeleteAccessConfirmed -eq 0)
        {
          #Yes selected
          Write-Output "Removing Key Vault access for '$($AccessPolicyToRemove.DisplayName)'"
          $RemoveJob = Remove-AzureRmKeyVaultAccessPolicy -VaultName $Global:KeyVaultName -ObjectId $AccessPolicyToRemove.ObjectId -ErrorVariable errRemoveAccess
          If ($errRemoveAccess.Count -eq 0)
          {
            Write-Host -Object 'Key Vault access removed.' -ForegroundColor Green
            Write-Output -InputObject ''
          }
          else 
          {
            Write-Error -Message 'Failed to remove access to the Key Vault.'
            Write-Output -InputObject ''
          }
        } else {
          Write-Output "Key Vault access removal cancelled for '$($AccessPolicyToRemove.DisplayName)'."
          Write-Output -InputObject ''
        }
      }
    }
    while ($ans -lt 0 -or $ans -gt $i)
}

# .EXTERNALHELP AzureKeyVaultPasswordRepo.psm1-Help.xml
Function Invoke-AzureKeyVaultPasswordRepository
{
  Clear-Host
  #region variables
  $IdentifyingTagName = 'Purpose'
  $IdentifyingTagValue = 'PersonalPasswordRepo'
  $Global:RandomPasswordLength = 20
  $Global:RandomPasswordSpecialCharactersCount = 3
  $TopMenuTitleLine1 = 'Azure Key Vault Personal Password Repository'
  $TopMenuTitleLine2 = '============================================'

  $Global:SettingRegPath = 'HKCU:\Software\TYConsulting\AzureKeyVaultPasswordRepo\Profiles'
  #endregion

  #region retrieve Azure resources
  #Logging in to Azure
  Write-Output -InputObject 'Checking for existing Azure login session.'
  Do
  {
    Try
    {
      $context = Get-AzureRmContext
      $CurrentAccount = $context.Account.Id
      If ($CurrentAccount -ne $null)
      {
        $AzureContextTitle = 'Existing Azure Credential'
        $ExistingAccountMessage = "You are currently logged in to Azure using account $CurrentAccount. Do you want to keep using this account?"
        $yes = New-Object -TypeName System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes', 'Keep using this Id.'
        $no = New-Object -TypeName System.Management.Automation.Host.ChoiceDescription -ArgumentList '&No', 'Login to Azure using another Id.'
        $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

        $UserSelected = $host.ui.PromptForChoice($AzureContextTitle, $ExistingAccountMessage, $options, 0) 
        If ($UserSelected -eq 1)
        {
          Write-Output -InputObject 'Login to Auzre'
          $null = Add-AzureRmAccount
          $context = Get-AzureRmContext
          $CurrentAccount = $context.Account.Id
        }
      }
      else 
      {
        Write-Host -Object 'You are currently not logged in to Azure. Please login.' -ForegroundColor Red
        $null = Add-AzureRmAccount
        $context = Get-AzureRmContext
        $CurrentAccount = $context.Account.Id
      }
    }
    Catch 
    {
      Write-Host -Object 'You are currently not logged in to Azure. Please login.' -ForegroundColor Red
      $null = Add-AzureRmAccount
      $context = Get-AzureRmContext
      $CurrentAccount = $context.Account.Id
    }
  }
  Until ($CurrentAccount -gt 0)
  $CurrentSubName = $context.Subscription.SubscriptionName
  $CurrentSubId = $context.Subscription.SubscriptionId

  #Check for existing profile
  Write-Output -InputObject 'Looking for existing profile'
  $ExistingProfile = Get-KeyVaultRepoProfile
  If ($ExistingProfile)
  {
    Write-Output -InputObject "Existing Profile is found for user '$($context.Account.Id)'. Loading profile..."
    if ($CurrentSubId -ine $ExistingProfile.AzureSubId)
    {
      Write-Output "Setting Azure Subscription '$($ExistingProfile.AzureSubId)' to the context."
      $null = Set-AzureRmContext -SubscriptionId $ExistingProfile.AzureSubId
    }
    Write-Output "Connecting to key vault '$($ExistingProfile.KeyVaultName)'"
    $KeyVault = Get-AzureRmKeyVault -VaultName $ExistingProfile.KeyVaultName
    $Global:KeyVaultName = $KeyVault.VaultName
  }
  else 
  {
    Write-Host -Object "No Profile is found for user '$($context.Account.Id)'" -ForegroundColor Red
    #Select Azure subscription
    If ($CurrentSubName -ne $null)
    {
      $SelectSubTitle = 'Select Azure Subscription'
      $SelectSubMessage = "Currently the Azure subscription '$CurrentSubName (Id: $CurrentSubId)' is selected. Do you want to use this subscription?"
      $yes = New-Object -TypeName System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes', 'Use the current subscription.'
      $no = New-Object -TypeName System.Management.Automation.Host.ChoiceDescription -ArgumentList '&No', 'Select another subscription.'
      $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

      $UserSelected = $host.ui.PromptForChoice($SelectSubTitle, $SelectSubMessage, $options, 0)
    }
    If($UserSelected -eq 1)
    {
      Write-Output -InputObject 'Getting Azure subscriptions...'
      $subscriptions = Get-AzureRmSubscription -WarningAction SilentlyContinue
      if ($subscriptions.count -gt 0)
      {
        Write-Host -Object 'Select Azure Subscription of which the Azure Key Vault is located' -ForegroundColor DarkGray

        $menu = @{}
        for ($i = 1;$i -le $subscriptions.count; $i++) 
        {
          Write-Host -Object "$i. $($subscriptions[$i-1].SubscriptionName)" -ForegroundColor Yellow
          $menu.Add($i,($subscriptions[$i-1].SubscriptionId))
        }
        Do 
        {
          [int]$ans = Read-Host -Prompt "Enter selection (1 - $($i -1))"
        }
        while ($ans -le 0 -or $ans -gt $($i -1))
        Write-Output -InputObject ''
        $subscriptionID = $menu.Item($ans)
        $null = Set-AzureRmContext -SubscriptionId $subscriptionID
      }
      else 
      {
        Write-Error -Message 'No Azure Subscription found. Unable to continue!'
        Exit -1
      }
    }
    $context = Get-AzureRmContext
    $subscriptionID = $context.Subscription.SubscriptionId
    #Check for existing key vault configured for AaaS solutions
    $ExistingKeyVaults = Get-AzureRmKeyVault |
    Where-Object -FilterScript {
      $_.Tags.ContainsKey($IdentifyingTagName)
    } |
    Where-Object -FilterScript {
      $_.Tags["$IdentifyingTagName"] -eq $IdentifyingTagValue
    }
    Write-Output -InputObject ''
    if ($ExistingKeyVaults.count -eq 0)
    {
      Write-Host -Object 'No existing AaaS key vault detected. select 0 to create a new key vault.' -ForegroundColor Red
    }
    else
    {
      Write-Host -Object 'Select a Key Vault' -ForegroundColor DarkGray
    }
    Write-Host -Object '0. [Create New Key Vault]' -ForegroundColor DarkGray
    $i = 0
    Foreach ($KV in $ExistingKeyVaults)
    {
      $i++
      Write-Host -Object "$i. $($KV.VaultName)" -ForegroundColor Yellow
    }
    Do 
    {
      [int]$KVAnswer = Read-Host -Prompt "Enter selection (0 - $i)"
    }
    while ($KVAnswer -lt 0 -or $KVAnswer -gt $i)
    Write-Output -InputObject ''
    If ($KVAnswer -eq 0)
    {
      #Create new key vault
      $AzureLocations = Get-AzureRmLocation
      $ExistingResourceGroups = @()
      #get resource groups
      Foreach ($item in Get-AzureRmResourceGroup)
      {
        $RGLoc = $AzureLocations | Where-Object -FilterScript {
          $item.Location -eq $_.Location
        }
        if ($RGLoc.Providers -contains 'Microsoft.KeyVault')
        {
          $ExistingResourceGroups += $item
        }
      }

      Write-Host -Object 'Select a resource group' -ForegroundColor DarkGray
      Write-Host -Object '0. [Create New Resource Group]' -ForegroundColor DarkGray
      $i = 0
      Foreach ($RG in $ExistingResourceGroups)
      {
        $i++
        Write-Host -Object "$i. $($RG.ResourceGroupName)"  -ForegroundColor Yellow
      }
      Do 
      {
        [int]$RGAnswer = Read-Host -Prompt "Enter selection (1 - $i)"
      }
      while ($RGAnswer -lt 0 -or $RGAnswer -gt $i)
      Write-Output -InputObject ''

      if ($RGAnswer -eq 0)
      {
        #Create a new resource group
        #resource group name
        Do
        {
          $ResourceGroupName = Read-Host -Prompt 'Enter the name for the new Resource Group (only include alphanumeric characters, periods, underscores, hyphens and parenthesis and cannot end in a period.)'
        }
        while ($ResourceGroupName.Length -eq 0 -or $ResourceGroupName -notmatch '^[-\w\._\(\)]+$')
        #location
        $AvailableLocations = $AzureLocations |
        Where-Object -FilterScript {
          $_.Providers -contains 'Microsoft.Resources' -and $_.Providers -contains 'Microsoft.KeyVault'
        } |
        Sort-Object -Property DisplayName
        Write-Host -Object 'Select Azure Region:' -ForegroundColor DarkGray
        $i = 0
        foreach ($loc in $AvailableLocations)
        {
          $i++
          Write-Host -Object "$i. $($loc.DisplayName)" -ForegroundColor Yellow
        }
        Do 
        {
          [int]$ans = Read-Host -Prompt "Enter selection (1 - $i)"
        }
        while ($ans -le 0 -or $ans -gt $i)
        Write-Output -InputObject ''
        $Location = $AvailableLocations[$ans-1]
        $strLocation = $Location.Location
        Write-Output -InputObject "Creating new Resource Group '$ResourceGroupName' in Azure region '$($Location.DisplayName)'."
        $NewRG = New-AzureRmResourceGroup -Name $ResourceGroupName -Location $strLocation
        If ($NewRG.ProvisioningState -eq 'Succeeded')
        {
          Write-Host -Object "Resource group '$ResourceGroupName' successfully created." -ForegroundColor Green
        }
        else 
        {
          Write-Host -Object "Resource Group creation failed. provisioning state: '$($NewRG.ProvisioningState)'." -ForegroundColor Red
        }
        Write-Output -InputObject ''
      }
      else 
      {
        #choose existing Resource Group
        $ResourceGroupName = $ExistingResourceGroups[$RGAnswer -1].ResourceGroupName
        $strLocation = $ExistingResourceGroups[$RGAnswer -1].Location
        Write-Output -InputObject ''
      }

      #Create Key Vault
      #Key Vault name
      Do
      {
        $Global:KeyVaultName = Read-Host -Prompt 'Enter the name for the new Key Vault (only include alphanumeric characters and dashes and cannot start with a number.)'
      }
      while ($Global:KeyVaultName.Length -eq 0 -or $Global:KeyVaultName -notmatch '^[a-zA-Z0-9-]{3,24}$')
      Write-Output -InputObject 'Creating Azure Key Vault'
      $KeyVault = New-AzureRmKeyVault -VaultName $Global:KeyVaultName -ResourceGroupName $ResourceGroupName -Location $strLocation -EnabledForDeployment -EnabledForTemplateDeployment -EnabledForDiskEncryption -Sku Standard -Tag @{
        $IdentifyingTagName = $IdentifyingTagValue
      } -Confirm:$false
      $Global:KeyVaultName = $KeyVault.VaultName

      #Give someone access to the key vault
      Write-Output -InputObject 'Assigning Azure Key Vault permission to an Azure AD user. Searching Azure AD to get the AD user.'
      Add-KeyVaultFullAccessPolicy
    }
    else 
    {
      $KeyVault = $ExistingKeyVaults[$KVAnswer-1]
      $Global:KeyVaultName = $KeyVault.VaultName
    }
  }

  #endregion

  #region manage key vault secrets
  Clear-Host
  Do
  {
    Write-Host -Object $TopMenuTitleLine1 -ForegroundColor Cyan
    Write-Host -Object $TopMenuTitleLine2 -ForegroundColor Cyan
    Write-Host -Object "  Selected Key Vault: '$Global:KeyVaultName'" -ForegroundColor Cyan
    Write-Host -Object "Select what you'd like to do:" -ForegroundColor DarkGray
    Write-Host -Object '0. Exit' -ForegroundColor DarkGray
    Write-Host -Object '1. Create new credential' -ForegroundColor Yellow
    Write-Host -Object '2. Choose existing credentials from the list' -ForegroundColor Yellow
    Write-Host -Object '3. Search existing credentials' -ForegroundColor Yellow
    Write-Host -Object '4. Save Azure subscription and Key Vault selection in Key Vault Password Repository profile' -ForegroundColor Yellow
    Write-Host -Object '5. Delete Key Vault Password Repository profile' -ForegroundColor Yellow
    Write-Host -Object '6. Grant Key Vault Access' -ForegroundColor Yellow
    Write-Host -Object '7. Remove Key Vault Access' -ForegroundColor Yellow
  
    Do 
    {
      [int]$option = Read-Host -Prompt 'Enter selection (0 - 7)'
    }
    while ($option -lt 0 -or $option -gt 7)
    Write-Output -InputObject ''
    SWITCH ($option)
    {
      1 
      {
        #Create new
        New-KeyVaultCred
        Write-Output -InputObject ''
      }
      2 
      {
        #list existing
        Get-KeyVaultCred
      }
      3 
      {
        #search existing
        Get-KeyVaultCred -Search
      }
      4 
      {
        #Save profile
        Save-KeyVaultRepoProfile
      }
      5 
      {
        #Delete profile
        Remove-KeyVaultRepoProfile
      }
      6
      {
        #Grant access
        Add-KeyVaultFullAccessPolicy
      }
      7
      {
        #Grant access
        Remove-KeyVaultFullAccessPolicy
      }
      0 
      {
        Write-Output -InputObject 'See you next time!'
      }
    }
  }
  Until ($option -eq 0)
}

New-Alias -Name ipr -Value Invoke-AzureKeyVaultPasswordRepository
New-Alias -Name Start-PasswordRepo -Value Invoke-AzureKeyVaultPasswordRepository
Export-ModuleMember -Alias * -Function *

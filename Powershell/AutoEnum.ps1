$AccessToken = ''
$GraphAccessToken = ''
$KeyVaultAccessToken = ''
$StorageAccountAccessToken = ''
$AccountId = 'ThomasLWright@oilcorporation.onmicrosoft.com'

# Connect to ARM
Connect-AzAccount -AccessToken $ARMAccessToken -GraphAccessToken $GraphAccessToken -KeyVaultAccessToken $KeyVaultAccessToken -AccountId $AccountId

# Connect to Graph
Connect-MgGraph -AccessToken ($GraphAccessToken | ConvertTo-SecureString -Force -AsPlainText)

# Enumerate roles and group membership
$users = Get-MgUser -All
$userCurrent = $users | where { $_.UserPrincipalName -eq $AccountId }

Write-Host "Directory Roles:`n-----------------------------"
$directoryRoles = Get-MgDirectoryRole
foreach ($role in $directoryRoles) {
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id
    if ($members.Id -contains $userCurrent.Id) {
        Write-Host " - $($role.DisplayName)"
    }
}

Write-Host "Application Role Assignments:`n-----------------------------"
$appRoles = Get-MgUserAppRoleAssignment -UserId $userCurrent.Id
foreach ($appRole in $appRoles) {
    Write-Host " - $($appRole.ResourceDisplayName): AppRoleId $($appRole.AppRoleId)"
}

Write-Host "Group Memberships:`n-----------------------------"
$groups = Get-MgUserMemberOf -UserId $userCurrent.Id
foreach ($group in $groups) {
    Write-Host " - $($group.AdditionalProperties.displayName)"
}

# Enumerate Azure RBAC roles
Write-Host "RBAC roles:`n-----------------------------"
$rolesRbac = Get-AzRoleAssignment
$rolesRbac | FL

# Enumerate applications
Write-Host "Applications:`n-----------------------------"
$applications = Get-MgApplication
$resultsApplications = @()
foreach ($application in $applications) {
	$keyCredentials = @()
	foreach ($keyCredential in $application.KeyCredentials) {
		if ($keyCredential.Type -eq 'AsymmetricX509Cert') {
			$keyCredentials += [PSCustomObject]@{
				Id = $keyCredential.KeyId
				Name = $keyCredential.DisplayName
				Thumprint = [System.Convert]::ToBase64String($keyCredential.CustomKeyIdentifier)
				Type = $keyCredential.Type
			}
		}
		else {
				$keyCredentials += [PSCustomObject]@{
				Id = $keyCredential.KeyId
				Name = $keyCredential.DisplayName
				KeyIdentifier = $keyCredential.CustomKeyIdentifier
				Type = $keyCredential.Type
			}
		}
	}    

	$passwordCredentials = @()
	foreach ($passwordCredential in $application.PasswordCredentials) {
		$passwordCredentials += [PSCustomObject]@{
			Id = $keyCredential.KeyId
			Name = $keyCredential.DisplayName
			Hint = $keyCredential.Hint
			SecretText = $keyCredential.SecretText
		}
	}

	$resultsApplications += [PSCustomObject]@{
		name = $application.DisplayName
		appId = $application.AppId
		keyCredentialsLen = $keyCredentials.Length
		keyCredentials = $keyCredentials
		passwordCredentialsLen = $passwordCredentials.Length
		passwordCredentials = $passwordCredentials
	}
}
$resultsApplications | Format-List

# Enumerate resources
$resources = Get-AzResource
$resources | Format-List

# Enumerate Vaults
Write-Host "Vaults:`n-----------------------------"
$resultsVault = @()
$vaults = Get-AzKeyVault
foreach ($vault in $vaults) {
	$roles = Get-AzRoleAssignment -Scope $vault.ResourceId
	foreach ($role in $roles) {
		$roleDefinition = Get-AzRoleDefinition -Id $role.RoleDefinitionId

		$resultsVault += [PSCustomObject]@{
			vaultName = $vault.VaultName
			vaultResourceId = $vault.ResourceID
			roleDefinitionName = $role.RoleDefinitionName
			roleDataActions = $roleDefinition.DataActions
		}
	}
}
$resultsVault | Format-List
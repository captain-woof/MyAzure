function Perform-MyAzAutoEnum {
	param(
		[string]$ARMAccessToken = '',
		[string]$GraphAccessToken = '',
		[string]$KeyVaultAccessToken = '',
		[string]$StorageAccountAccessToken = '',
		[string]$AccountId = ''
	)

	# Connect to ARM
	if ($ARMAccessToken) {
		$ARMConnectParams = @{
		    AccessToken = $ARMAccessToken
		    AccountId   = $AccountId
		}
		if ($GraphToken) {
		    $connectParams.Add('GraphAccessToken', $GraphAccessToken)
		}
		if ($KeyVaultAccessToken) {
		    $connectParams.Add('KeyVaultAccessToken', $KeyVaultAccessToken)
		}
		if ($StorageAccountAccessToken) {
		    $connectParams.Add('StorageAccountAccessToken', $StorageAccountAccessToken)
		}

		Connect-AzAccount @ARMConnectParams
	}
	
	# Connect to Graph
	if ($GraphAccessToken) {
		Connect-MgGraph -AccessToken ($GraphAccessToken | ConvertTo-SecureString -Force -AsPlainText)
	}

	############
	# GRAPH ENUM
	############
	if ($GraphAccessToken) {
		Write-Host "GRAPH ENUMERATION:`n-----------------------------------------------------`n----------------------------------------------------------------"

		# Enumerate context
		Write-Host "Graph context:`n-----------------------------------------------------"
		Get-MgContext | FL

		# Enumerate users
		$users = Get-MgUser -All
		$userCurrent = $users | where { $_.UserPrincipalName -eq $AccountId }

		# Enumerate group membership
		Write-Host "Group Memberships of current user:`n-----------------------------------------------------"
		$groups = Get-MgUserMemberOf -UserId $userCurrent.Id
		foreach ($group in $groups) {
		    Write-Host " - $($group.AdditionalProperties.displayName)"
		}

		# Enumerate roles
		Write-Host "Enumerating directory roles`n-----------------------------------------------------"
		$roles = Get-MyAzDirectoryRoleAssignment
		$roles | FL

		# Enumerate AUs
		Write-Host "Administrative Units (AUs):`n-----------------------------------------------------"
		$aus = Get-MyAzDirectoryAdministrativeUnits
		$aus | FL
		
		# Enumerate applications
		Write-Host "Applications:`n-----------------------------------------------------"
		$applications = Get-MyAzApplications
		$applications | FL

		# Owned principals
		Write-Host "Owned principals:`n-----------------------------------------------------"
		Get-MyAzOwnedPricipals -PrincipalId $userCurrent.Id

		# Authentication methods
		Write-Host "Authentication methods:`n-----------------------------------------------------"
		$authMethods = Get-MyAzAuthenticationMethods
		$authMethods | FL

		# Conditional Access Policies
		Write-Host "Conditional Access Policies:`n-----------------------------------------------------"
		$conditionalAccessPolicies = Get-MyAzConditionalAccessPolicies
		$conditionalAccessPolicies | FL

		# Cross-Tenant Access Policy
		Write-Host "Cross-tenant Access Policy:`n-----------------------------------------------------"
		$crossTenantAccessPolicy = Get-MyAzCrossTenantAccessPolicy
		$crossTenantAccessPolicy | FL

		# Outlook emails
		Write-Host "My Outlook emails:`n-----------------------------------------------------"
		$emailsOutlook = Get-MyAzOutlookEmails

		# Chats
		Write-Host "My Teams chats:`n-----------------------------------------------------"
		$teamsChats = Get-MyAzTeamsChats
		$teamsChats | FL
	}


	##########
	# ARM ENUM
	##########
	if ($ARMAccessToken) {
		Write-Host "ARM ENUMERATION:`n-----------------------------------------------------`n----------------------------------------------------------------"

		# Enumerate context
		Write-Host "ARM context:`n-----------------------------------------------------"
		Get-AzContext | FL

		# Enumerate resources
		Write-Host "Resources:`n-----------------------------------------------------"
		$resources = Get-AzResource
		$resources | Format-List

		# Enumerate current permissions over resources
		Write-Host "Permissions over resources:`n-----------------------------------------------------"
		foreach ($resource in $resources) {
			$perms = Get-MyAzPermissionOverResource -ResourceUri $resource.Id -ARMAccessToken $ARMAccessToken
			
			Write-Host "`t$($resource.Id)"
			$perms | FL
		}
		
		# Enumerate Azure RBAC roles
		Write-Host "RBAC Roles:`n-----------------------------------------------------"
		$rolesRbac = Get-MyAzRolesRbac
		$rolesRbac | FL

		# Enumerate Vaults
		Write-Host "Vaults:`n-----------------------------------------------------"
		$vaults = Get-MyAzKeyVault
		$vaults | FL

		# Enumerate Logic Apps
		Write-Host "Logic Apps:`n-----------------------------------------------------"
		$logicApps = Get-MyAzLogicApps
		$logicApps | FL

		# Enumerate function apps
		Write-Host "Function apps:`n-----------------------------------------------------"
		$functionApps = Get-AzFunctionApp
		$functionApps | FL

		# Enumerate Storage Accounts
		Write-Host "Storage Accounts:`n-----------------------------------------------------"
		$storageAccounts = Get-MyAzStorageAccount # prints data by itself

		# Enumerate Lighthouse
		Write-Host "Lighthouse:`n-----------------------------------------------------"
		$managedServicesAssignment = Get-AzManagedServicesAssignment -ExpandRegistrationDefinition
		$managedServicesAssignment | FL

		# Enumerate VMs
		Write-Host "VMs:`n-----------------------------------------------------"
		$vms = Get-MyAzVMs
		$vms | FL

		# Enumerate Automation accounts
		Write-Host "Automation accounts:`n-----------------------------------------------------"
		Get-MyAzAutomationAccount # prints data by itself

		# Web apps
		Write-Host "Web Apps:`n-----------------------------------------------------"
		Get-AzWebApp | FL
	}
}
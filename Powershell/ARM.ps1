function Get-MyAzPermissionOverResource {
    param(
        [string]$ResourceUri,
        [string]$ARMAccessToken
    )
    $URI = "https://management.azure.com$($ResourceUri)/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
    $RequestParams = @{
        Method = 'GET'
        Uri = $URI
        Headers = @{
            'Authorization' = "Bearer $($ARMAccessToken)"
        }
    }
    $Permissions = (Invoke-RestMethod @RequestParams).value
    return $Permissions
}

function Get-MyAzRolesRbac {
    $rolesRbac = Get-AzRoleAssignment
	$rolesRbacProcessed = @()
	foreach ($role in $rolesRbac) {
		$roleDefinition = Get-AzRoleDefinition -Id $role.RoleDefinitionId
		$rolesRbacProcessed += [PSCustomObject]@{
			Id = $role.ObjectId
			Scope = $role.Scope
			DisplayName = $role.DisplayName
			Description = $role.Description
			Condition = $role.Condition
			RoleAssignmentId = $role.RoleAssignmentId
			RoleAssignmentName = $role.RoleAssignmentName
			RoleDefinitionId = $roleDefinition.Id
			RoleDefinitionName = $roleDefinition.Name
			RoleDefinitionIsCustom = $roleDefinition.IsCustom
			RoleDefinitionDescription = $roleDefinition.Description
			RoleDefinitionActions = $roleDefinition.Actions
			RoleDefinitionNotActions = $roleDefinition.NotActions
			RoleDefintionDataActions = $roleDefinition.DataActions		
			RoleDefinitionNotDataActions = $roleDefinition.NotDataActions
			RoleDefinitionAssignableScopes = $roleDefinition.AssignableScopes
			RoleDefinitionCondition = $roleDefinition.Condition
			RoleDefinitionConditionVersion = $roleDefinition.ConditionVersion
		}
	}
	return $rolesRbacProcessed
}
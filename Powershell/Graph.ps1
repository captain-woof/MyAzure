function Get-MyAzPrincipalFromId {
    param(
    [Parameter(Mandatory=$true)]
    [string]$PrincipalId
)

    try {
        $user = Get-MgUser -UserId $PrincipalId -ErrorAction Stop
        return $user
    } catch {}

    try {
        $group = Get-MgGroup -GroupId $PrincipalId -ErrorAction Stop
        return $group
    } catch {}

    try {
        $sp = Get-MgServicePrincipal -ServicePrincipalId $PrincipalId -ErrorAction Stop
        return $sp
    } catch {}

    try {
        $app = Get-MgApplication -ApplicationId $PrincipalId -ErrorAction Stop
        return $app
    } catch {}
}

function Get-MyAzDirectoryRoleAssignment {
    $roles = Get-MgRoleManagementDirectoryRoleAssignment
    $rolesProcessed = @()
    $roles | ForEach-Object {
        $roleDef = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $_.RoleDefinitionId

        $principal = Get-MyAzPrincipalFromId -PrincipalId $_.PrincipalId

        $rolesProcessed += [PSCustomObject]@{
            PrincipalName = $principal.DisplayName
            PrincipalId = $_.PrincipalId
            RoleDisplayName = $roleDef.DisplayName
            RoleDescription = $roleDef.Description
            RoleId = $roleDef.Id
            DirectoryScopeId = $_.DirectoryScopeId
            Condition = $_.Condition
            ConditionRoleDef = $roleDef.RolePermissions.Condition
            AppId = $principal.AppId
            AllowedResourceActions = $roleDef.RolePermissions.AllowedResourceActions
            ExcludedResourceActions = $roleDef.RolePermissions.ExcludedResourceActions
        }
    }
    return $rolesProcessed
}
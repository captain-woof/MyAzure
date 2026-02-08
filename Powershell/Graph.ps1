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

function Get-MyAzDirectoryAdministrativeUnits {
    $aus = Get-MgDirectoryAdministrativeUnit
    $ausResult = @()
    foreach ($au in $aus) {
        $members = Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $au.Id -All
        $membersResult = @()

        foreach ($member in $members) {
            $membersResult += [PSCustomObject]@{
                Id = $member.Id
                Name = $member.AdditionalProperties.DisplayName
                userPrincipalName = $member.AdditionalProperties.userPrincipalName
                AppId = $member.AdditionalProperties.appId
            }
        }

        $ausResult += [PSCustomObject]@{
            Id = $au.Id
            Name = $au.DisplayName
            Description = $au.Description
            Members = $membersResult
        }
    }
}

function Set-MyAzUserPassword {
    param(
        [string]$NewPassword,
        [string]$UserId
    )
    $passwordProfile = @{
        forceChangePasswordNextSignIn = $false
        password = $NewPassword
    }
    $res = Update-MgUser -UserId $UserId -PasswordProfile $passwordProfile
    return $res
}

function Add-MyAzApplicationSecret {
    param(
        [string]$ServicePrincipalId
    )
    $passwordCred = @{
        displayName = 'Added by Azure Service Bus - DO NOT DELETE'
        endDateTime = (Get-Date).AddMonths(6)
    }
    $res = Add-MgApplicationPassword -ApplicationId $ServicePrincipalId -PasswordCredential $passwordCred
    return $res
}

function Get-MyAzApplications {
    $apps = Get-MgApplication -All
    $sps = Get-MgServicePrincipal -All

    $res = @()
    foreach ($app in $apps) {
        $sp = $sps | where {$_.AppId -eq $app.AppId}

        $ApplicationKeyCredentials = @()
	    foreach ($keyCredential in $app.KeyCredentials) {
	    	if ($keyCredential.Type -eq 'AsymmetricX509Cert') {
	    		$ApplicationKeyCredentials += [PSCustomObject]@{
	    			Id = $keyCredential.KeyId
	    			Name = $keyCredential.DisplayName
	    			Thumbprint = [System.Convert]::ToBase64String($keyCredential.CustomKeyIdentifier)
	    			Type = $keyCredential.Type
	    		}
	    	}
	    	else {
	    			$ApplicationKeyCredentials += [PSCustomObject]@{
	    			Id = $keyCredential.KeyId
	    			Name = $keyCredential.DisplayName
	    			KeyIdentifier = $keyCredential.CustomKeyIdentifier
	    			Type = $keyCredential.Type
	    		}
	    	}
	    }
	    $ApplicationPasswordCredentials = @()
	    foreach ($passwordCredential in $app.PasswordCredentials) {
	    	$ApplicationPasswordCredentials += [PSCustomObject]@{
	    		Id = $passwordCredential.KeyId
	    		Name = $passwordCredential.DisplayName
	    		Hint = $passwordCredential.Hint
	    		SecretText = $passwordCredential.SecretText
	    	}
	    }

        $ServicePrincipalKeyCredentials = @()
	    foreach ($keyCredential in $sp.KeyCredentials) {
	    	if ($keyCredential.Type -eq 'AsymmetricX509Cert') {
	    		$ServicePrincipalKeyCredentials += [PSCustomObject]@{
	    			Id = $keyCredential.KeyId
	    			Name = $keyCredential.DisplayName
	    			Thumbprint = [System.Convert]::ToBase64String($keyCredential.CustomKeyIdentifier)
	    			Type = $keyCredential.Type
	    		}
	    	}
	    	else {
	    			$ServicePrincipalKeyCredentials += [PSCustomObject]@{
	    			Id = $keyCredential.KeyId
	    			Name = $keyCredential.DisplayName
	    			KeyIdentifier = $keyCredential.CustomKeyIdentifier
	    			Type = $keyCredential.Type
	    		}
	    	}
	    }
	    $ServicePrincipalPasswordCredentials = @()
	    foreach ($passwordCredential in $sp.PasswordCredentials) {
	    	$ServicePrincipalPasswordCredentials += [PSCustomObject]@{
	    		Id = $passwordCredential.KeyId
	    		Name = $passwordCredential.DisplayName
	    		Hint = $passwordCredential.Hint
	    		SecretText = $passwordCredential.SecretText
	    	}
	    }

        $res += [PSCustomObject]@{
            AppId = $app.AppId
            AppObjectId = $app.Id
            AppDisplayName = $app.DisplayName
            AppRequiredResourceAccess = $app.RequiredResourceAccess
            AppKeyCredentials = $ApplicationKeyCredentials
            AppPasswordCredentials = $ApplicationPasswordCredentials
            AppTags = $app.Tags
            ServicePrincipalId = $sp.Id
            ServicePrincipalKeyCredentials = $ServicePrincipalKeyCredentials
            ServicePrincipalPasswordCredentials = $ServicePrincipalPasswordCredentials
            ServicePrincipalDisplayName = $sp.DisplayName
            ServicePrincipalTags = $sp.Tags
        }
    }

    return $res
}

function Get-MyAzOwnedPricipals {
    param(
        [string]$PrincipalId
    )
    try {
        Get-MgUserOwnedObject -All -UsedId $PrincipalId -EA Stop | select Id, @{Name='displayName';Expression={$_.AdditionalProperties.displayName}},@{Name='ObjectType';Expression={$_.AdditionalProperties.'@odata.type'}} | fl
    } catch {}

    try {
        Get-MgServicePrincipalOwnedObject -All -ServicePrincipalId $PrincipalId -EA Stop | select Id, @{Name='displayName';Expression={$_.AdditionalProperties.displayName}},@{Name='ObjectType';Expression={$_.AdditionalProperties.'@odata.type'}} | fl
    } catch {}
}

function Get-MyAzConditionalAccessPolicies {
    # Retrieve all conditional access policies
    $policies = Get-MgIdentityConditionalAccessPolicy

    $results = foreach ($policy in $policies) {
        # Flatten conditions
        $conditions = $policy.Conditions
        $users = $conditions.Users
        $applications = $conditions.Applications
        $locations = $conditions.Locations
        $platforms = $conditions.Platforms
        $clientApps = $conditions.ClientApplications
        $devices = $conditions.Devices

        # Flatten grant controls
        $grantControls = $policy.GrantControls
        $sessionControls = $policy.SessionControls

        # Build custom object
        [PSCustomObject]@{
            Id                   = $policy.Id
            DisplayName          = $policy.DisplayName
            State                = $policy.State
            CreatedDateTime      = $policy.CreatedDateTime
            ModifiedDateTime     = $policy.ModifiedDateTime

            # User assignments
            IncludeUsers         = $users.IncludeUsers -join ", "
            ExcludeUsers         = $users.ExcludeUsers -join ", "
            IncludeGroups        = $users.IncludeGroups -join ", "
            ExcludeGroups        = $users.ExcludeGroups -join ", "
            IncludeRoles         = $users.IncludeRoles -join ", "
            ExcludeRoles         = $users.ExcludeRoles -join ", "

            # Application assignments
            IncludeApplications  = $applications.IncludeApplications -join ", "
            ExcludeApplications  = $applications.ExcludeApplications -join ", "

            # Locations
            IncludeLocations     = $locations.IncludeLocations -join ", "
            ExcludeLocations     = $locations.ExcludeLocations -join ", "

            # Platforms
            IncludePlatforms     = $platforms.IncludePlatforms -join ", "
            ExcludePlatforms     = $platforms.ExcludePlatforms -join ", "

            # Client apps
            IncludeClientApps    = $clientApps.IncludeClientApplications -join ", "
            ExcludeClientApps    = $clientApps.ExcludeClientApplications -join ", "

            # Device states
            IncludeDeviceStates  = $devices.IncludeDeviceStates -join ", "
            ExcludeDeviceStates  = $devices.ExcludeDeviceStates -join ", "

            # Grant controls
            BuiltInControls      = $grantControls.BuiltInControls -join ", "
            CustomAuthenticationFactors = $grantControls.CustomAuthenticationFactors -join ", "
            Operator             = $grantControls.Operator
            TermsOfUse           = $grantControls.TermsOfUse -join ", "

            # Session controls
            ApplicationEnforcedRestrictions = $sessionControls.ApplicationEnforcedRestrictions.IsEnabled
            CloudAppSecurity                = $sessionControls.CloudAppSecurity.IsEnabled
            CloudAppSecurityMode            = $sessionControls.CloudAppSecurity.CloudAppSecurityType
            SignInFrequencyIsEnabled        = $sessionControls.SignInFrequency.IsEnabled
            SignInFrequencyValue            = $sessionControls.SignInFrequency.Value
            SignInFrequencyType             = $sessionControls.SignInFrequency.Type
            PersistentBrowserIsEnabled      = $sessionControls.PersistentBrowser.IsEnabled
            PersistentBrowserMode           = $sessionControls.PersistentBrowser.Mode
        }
    }

    return $results
}

function Perform-MyAzDeviceCodeFlow {
    param(
        [string]$AppId
        [string]$TenantID
    )
    # Prepare device code and user code

    # Keep polling for successful authentication
}
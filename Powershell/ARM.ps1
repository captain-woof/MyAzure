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
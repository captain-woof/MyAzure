function Perform-MyAzDeviceCodeAuthFlow2 {
    param(
        [string]$ClientID,
        [string]$Scope = "https://management.azure.com/.default",
        [string]$TenantID = "common"
    )

    # Generate device code
    $body = @{
        "client_id" = $ClientID
        "scope" = $Scope  
    }
 
    Write-Host "Generating device code`n- ClientId: $($ClientID)`n- Scope: $($Scope)"
    try {
        $authResponse = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/$($TenantID)/oauth2/v2.0/devicecode" -Body $body -ErrorAction Stop
    }
    catch {
        return $null
    }

    $userCode = $authResponse.user_code
    $deviceCode = $authResponse.device_code
    $verificationUrl = $authResponse.verification_uri
    $interval = $authResponse.interval
    $expiresIn = $authResponse.expires_in

    Write-Host "Device code: $($deviceCode)`nUser code: $($userCode)`nVerification URL: $($verificationUrl)`nExpires in: $($expiresIn) seconds"

    # Keep polling for successful authentication
    $body=@{
        "client_id" = $ClientID
        "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
        "device_code" = $deviceCode
    }
    while ($true) {
        try {
            Write-Host "Sleeping for $($interval) seconds..."
            Start-Sleep -Seconds $interval

            Write-Host "Polling for successful authentication..." 
            $tokensResponse = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/$($TenantID)/oauth2/v2.0/token" -Body $body -ErrorAction Stop

            return $tokensResponse
        } catch {
        }
    }
}

function Refresh-MyAzTokenForResource2 {
    param(
        [string]$TenantId = "common",
        [string]$ClientId,
        [string]$ClientSecret = $null,   # Only if using confidential client
        [string]$RefreshToken,
        [string]$Scope = "https://graph.microsoft.com/.default offline_access openid profile"  # Example: Microsoft Graph
    )    
    # Token endpoint (v2.0)
    $tokenEndpoint = "https://login.microsoftonline.com/$($TenantId)/oauth2/v2.0/token"

    # Request body
    if ($ClientSecret -eq $null) {
        $body = @{
            grant_type    = "refresh_token"
            client_id     = $ClientId
            refresh_token = $RefreshToken
            scope         = $Scope
        }
    } else {
        $body = @{
            grant_type    = "refresh_token"
            client_id     = $ClientId
            client_secret = $ClientSecret
            refresh_token = $RefreshToken
            scope         = $Scope
        }
    }
    
    # Request new access token
    $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri $tokenEndpoint -Body $body

    return $response
}

function Perform-MyAzDeviceCodeAuthFlow {
    param(
        [string]$ClientID,
        [string]$Resource = "https://management.azure.com",
        [string]$TenantID = "common"
    )

    # Generate device code
    $body = @{
        "client_id" = $ClientID
        "resource" = $Resource
    }
 
    Write-Host "Generating device code`n- ClientId: $($ClientID)`n- Resource: $($Resource)"
    try {
        $authResponse = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/$($TenantID)/oauth2/devicecode" -Body $body -ErrorAction Stop
    }
    catch {
        return $null
    }

    $userCode = $authResponse.user_code
    $deviceCode = $authResponse.device_code
    $verificationUrl = $authResponse.verification_url
    $interval = $authResponse.interval
    $expiresIn = $authResponse.expires_in

    Write-Host "Device code: $($deviceCode)`nUser code: $($userCode)`nVerification URL: $($verificationUrl)`nExpires in: $($expiresIn) seconds"

    # Keep polling for successful authentication
    $body=@{
        "client_id" = $ClientID
        "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
        "code" = $deviceCode
        "resource" = $Resource
    }
    while ($true) {
        try {
            Write-Host "Sleeping for $($interval) seconds..."
            Start-Sleep -Seconds $interval

            Write-Host "Polling for successful authentication..." 
            $tokensResponse = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/$($TenantID)/oauth2/token" -Body $body -ErrorAction Stop

            return $tokensResponse
        } catch {
        }
    }
}

function Refresh-MyAzTokenForResource {
    param(
        [string]$TenantId = "common",
        [string]$ClientId,
        [string]$ClientSecret = $null,   # Only if using confidential client
        [string]$RefreshToken,
        [string]$Resource = "https://graph.microsoft.com"  # Example: Microsoft Graph
    )    
    # Token endpoint
    $tokenEndpoint = "https://login.microsoftonline.com/$($TenantId)/oauth2/token"

    # Request body
    if ($ClientSecret -eq $null) {
        $body = @{
            grant_type    = "refresh_token"
            client_id     = $ClientId
            refresh_token = $RefreshToken
            resource      = $Resource
        }
    } else {
        $body = @{
            grant_type    = "refresh_token"
            client_id     = $ClientId
            client_secret = $ClientSecret
            refresh_token = $RefreshToken
            resource      = $Resource
        }
    }
    
    # Request new access token
    $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri $tokenEndpoint -Body $body

    return $response
}

function Generate-MyAzTapForUser {
    param(
        [string]$UserId
    )
    $properties = @{}
    $properties.isUsableOnce = $True
    $properties.startDateTime = (Get-Date)
    $propertiesJSON = $properties | ConvertTo-Json
    
    return New-MgUserAuthenticationTemporaryAccessPassMethod -UserId $UserId -BodyParameter $propertiesJSON
}
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

function Get-MyAzAccessTokenFromLocalCertificate {
    param(
        [string]$CertificatePath,
        [string]$TenantID='common',
        [string]$AppId,
        [string]$Scope='https://graph.microsoft.com/.default'
    )

    # Load certificate
    $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $CertificatePath

    $audience = "https://login.microsoftonline.com/$($TenantID)/oauth2/token"

    # Create a base64 hash of the certificate. The Base64 encoded string must by urlencoded
    $CertificateBase64Hash =
    [System.Convert]::ToBase64String($certificate.GetCertHash())
    $CertificateBase64Hash = $CertificateBase64Hash -replace '\+','-' -replace '/','_' -replace '='

    # JWT request should be valid for max 2 minutes.
    $StartDate = (Get-Date "1970-01-01T00:00:00Z").ToUniversalTime()
    $JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds
    $JWTExpiration = [math]::Round($JWTExpirationTimeSpan,0)

    # Create a NotBefore timestamp.
    $NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
    $NotBefore = [math]::Round($NotBeforeExpirationTimeSpan,0)

    # Create JWT header
    $jwtHeader = @{
    'alg' = "RS256" # Use RSA encryption and SHA256 as hashing algorithm
    'typ' = "JWT" # We want a JWT
    'x5t' = $CertificateBase64Hash # Webencoded Base64 of the hash of our certificate
    }

    # Create the payload
    $jwtPayLoad = @{
        'aud' = $audience # Points to oauth token request endpoint for your tenant
        'exp' = $JWTExpiration # Expiration of JWT request
        'iss' = $AppId # The AppID for which we request a token for
        'jti' = [guid]::NewGuid() # Random GUID
        'nbf' = $NotBefore # This should not be used before this timestamp
        'sub' = $AppId # Subject
    }

    # Convert header and payload to json and to base64
    $jwtHeaderBytes = [System.Text.Encoding]::UTF8.GetBytes(($jwtHeader | ConvertTo-Json))
    $jwtPayloadBytes = [System.Text.Encoding]::UTF8.GetBytes(($jwtPayLoad | ConvertTo-Json))
    $b64JwtHeader = [System.Convert]::ToBase64String($jwtHeaderBytes)
    $b64JwtPayload = [System.Convert]::ToBase64String($jwtPayloadBytes)

    # Concat header and payload to create an unsigned JWT

    $unsignedJwt = $b64JwtHeader + "." + $b64JwtPayload
    $unsignedJwtBytes = [System.Text.Encoding]::UTF8.GetBytes($unsignedJwt)

    # Configure RSA padding and hashing algorithm, load private key of certificate and use it to sign the unsigned JWT
    $privateKey = ([System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate))
    $padding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
    $hashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256
    $signedData = $privateKey.SignData($unsignedJwtBytes, $hashAlgorithm, $padding)

    # Create a signed JWT by adding the signature to the unsigned JWT
    $signature = [Convert]::ToBase64String($signedData) -replace '\+','-' -replace '/','_' -replace '='
    $signedJWT = $unsignedJwt + "." + $signature

    # Request an access token using the signed JWT
    $uri = "https://login.microsoftonline.com/$($TenantID)/oauth2/v2.0/token"
    $headers = @{'Content-Type' = 'application/x-www-form-urlencoded'}
    $response = Invoke-RestMethod -Uri $uri -UseBasicParsing -Method POST -Headers $headers -Body ([ordered]@{
        'client_id' = $AppId
        'client_assertion' = $signedJWT
        'client_assertion_type' = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        'scope' = $Scope
        'grant_type' = 'client_credentials'
    })
    return $response.access_token
}

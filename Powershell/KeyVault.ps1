function Get-MyAzCertThumbprintBase64 {
    param(
        [string]$ThumbprintHexString
    )

    # Convert hex string to byte array
    $bytes = for ($i = 0; $i -lt $ThumbprintHexString.Length; $i += 2) {
        [Convert]::ToByte($ThumbprintHexString.Substring($i, 2), 16)
    }

    # Convert byte array to Base64
    $base64 = [Convert]::ToBase64String($bytes)

    # Replace Base64 characters to URL-safe variant if needed
    $base64Url = $base64.TrimEnd('=') -replace '\+','-' -replace '/','_'

    return $base64Url
}

function Get-MyAzSignedJWT {
    param(
            [string]$TenantID,
            [string]$ApplicationId,
            [string]$KeyVaultAccessToken,
            [string]$ResourceScopeUri,
            $Certificate
        )
    $audience = "https://login.microsoftonline.com/$($TenantID)/oauth2/token"
    
    # JWT request should be valid for max 2 minutes.
    $StartDate             = (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime()
    $JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds
    $JWTExpiration         = [math]::Round($JWTExpirationTimeSpan,0)
    
    # Create a NotBefore timestamp. 
    $NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
    $NotBefore                   = [math]::Round($NotBeforeExpirationTimeSpan,0)
    
    # Create JWT header
    $x5t = Get-MyAzCertThumbprintBase64 -ThumbprintHexString $Certificate.Thumbprint
    $jwtHeader = @{
        'alg' = "RS256"              # Use RSA encryption and SHA256 as hashing algorithm
        'typ' = "JWT"                # We want a JWT
        'x5t' = $x5t  # The pubkey hash we received from Azure Key Vault
    }
    
    # Create the payload
    $jwtPayLoad = @{
        'aud' = $audience           # Points to oauth token request endpoint for your tenant
        'exp' = $JWTExpiration      # Expiration of JWT request
        'iss' = $ApplicationId    # The AppID for which we request a token for
        'jti' = [guid]::NewGuid()   # Random GUID
        'nbf' = $NotBefore          # This should not be used before this timestamp
        'sub' = $ApplicationId    # Subject
    }
    
    # Convert header and payload to json and to base64
    $jwtHeaderBytes  = [System.Text.Encoding]::UTF8.GetBytes(($jwtHeader | ConvertTo-Json))
    $jwtPayloadBytes = [System.Text.Encoding]::UTF8.GetBytes(($jwtPayLoad | ConvertTo-Json))
    $b64JwtHeader    = [System.Convert]::ToBase64String($jwtHeaderBytes)
    $b64JwtPayload   = [System.Convert]::ToBase64String($jwtPayloadBytes)
    
    # Concat header and payload to create an unsigned JWT and compute a Sha256 hash
    $unsignedJwt      = $b64JwtHeader + "." + $b64JwtPayload
    $unsignedJwtBytes = [System.Text.Encoding]::UTF8.GetBytes($unsignedJwt)
    $hasher           = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
    $jwtSha256Hash    = $hasher.ComputeHash($unsignedJwtBytes)
    $jwtSha256HashB64 = [Convert]::ToBase64String($jwtSha256Hash) -replace '\+','-' -replace '/','_' -replace '='
    
    # Sign the sha256 of the unsigned JWT using the certificate in Azure Key Vault
    $uri      = "$($Certificate.KeyId)/sign?api-version=7.3"
    $headers  = @{
        'Authorization' = "Bearer $($KeyVaultAccessToken)"
        'Content-Type' = 'application/json'
    }
    $response = Invoke-RestMethod -Uri $uri -UseBasicParsing -Method POST -Headers $headers -Body (([ordered] @{
        'alg'   = 'RS256'
        'value' = $jwtSha256HashB64
    }) | ConvertTo-Json)
    $signature = $response.value
    
    # Concat the signature to the unsigned JWT
    $signedJWT = $unsignedJwt + "." + $signature
    
    return $signedJWT
}

function Get-MyAzAccessTokenFromKeyVaultCertificate {
    param(
        [string]$TenantID,
        [string]$VaultName,
        [string]$CertificateName,
        [string]$KeyVaultAccessToken,
        [string]$ApplicationId,
        [string]$ResourceScopeUri
    )

    # Get certificate details
    $cert = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertificateName
    Write-Host "Certificate found:"
    Write-Host $cert

    # Get signed JWT
    $SignedJWT = Get-MyAzSignedJWT -TenantID $TenantID -ApplicationId $ApplicationId -KeyVaultAccessToken $KeyVaultAccessToken -Certificate $cert -ResourceScopeUri $ResourceScopeUri
    Write-Host "Signed JWT obtained:"
    Write-Host $SignedJWT

    # Request access token
    $uri = "https://login.microsoftonline.com/$($TenantID)/oauth2/v2.0/token"
    $headers  = @{'Content-Type' = 'application/x-www-form-urlencoded'}
    $response = Invoke-RestMethod -Uri $uri -UseBasicParsing -Method POST -Headers $headers -Body ([ordered]@{
        'client_id'             = $ApplicationId
        'client_assertion'      = $SignedJWT
        'client_assertion_type' = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        'scope'                 = $ResourceScopeUri
        'grant_type'            = 'client_credentials'
    })

    Write-Host "Access token:"
    Write-Host $response.access_token

    return $response.access_token
}

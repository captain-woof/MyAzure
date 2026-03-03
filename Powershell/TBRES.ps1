function Decrypt-MyAzTBRESBlob {
    param(
        [string]$FilepathBlob,
        [byte[]]$EncryptedBytes
    )
    Add-Type -AssemblyName System.Security    

    if ($EncryptedBytes -eq $null) {
        $EncryptedBytes = [IO.File]::ReadAllBytes($FilepathBlob)
    }    

    try {
        return [System.Security.Cryptography.ProtectedData]::Unprotect(
            $EncryptedBytes,
            $null, 
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
    } catch {
        try {
            return [System.Security.Cryptography.ProtectedData]::Unprotect(
                $EncryptedBytes,
                $null, 
                [System.Security.Cryptography.DataProtectionScope]::LocalMachine
            )
        }
        catch {
            Write-Host "Failed to decrypt"
        }
    }
}

function Get-MyAzTBRESEncryptedContent {
    param(
        [string]$FilepathTBRES,
        [string]$FilepathOutputBlob,
        [boolean]$PerformDecryption = $false
    )
    $jsonText = Get-Content -Path $FilepathTBRES -Raw -Encoding Unicode

    $pattern = '(?s)"ResponseBytes".*?"Value"\s*:\s*"([^"]*)"'
    if ($jsonText -match $pattern) {
        # Get base64 data from TBRES json
        $blobEncBytes = [Convert]::FromBase64String($matches[1])

        # Create full path for output if input is not full path
        if ($FilepathOutputBlob[0] -eq ".") {
            $FilepathOutputBlob = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilepathOutputBlob)
        }

        # Perform direct decryption if requested
        if ($PerformDecryption -eq $true) {
            $decryptedBytes = Decrypt-MyAzTBRESBlob -EncryptedBytes $blobEncBytes
            [IO.File]::WriteAllBytes($FilepathOutputBlob, $decryptedBytes)
        }
        # Else write encrypted contents
        else {
            [IO.File]::WriteAllBytes($FilepathOutputBlob, $blobEncBytes)
        }
    }
}

function Get-MyAzTBRESEncryptedContentAll {
    param(
        [string]$DirectoryPath,
        [boolean]$PerformDecryption = $false
    )
    # Get output suffix
    if ($PerformDecryption -eq $true) {
        $outputFileSuffix = "-dec.data"
    }
    else {
        $outputFileSuffix = "-enc.blob"
    }

    # Perform operation
    $files = Get-ChildItem -Force -Filter '*.tbres' -Path $DirectoryPath
    foreach ($file in $files) {
        Get-MyAzTBRESEncryptedContent -PerformDecryption $PerformDecryption  -FilepathTBRES $file.FullName -FilepathOutputBlob $("$($file.Directory.FullName)\$($file.BaseName)$($outputFileSuffix)")
    }
}

function Get-MyAzStorageAccount {
    param(
        [string]$Name,
        [string]$StorageAccountAccessToken
    )
    # Get all storage accounts
    $storageAccounts = Get-AzStorageAccount

    # Further enumerate each storage account
    foreach ($storageAccount in $storageAccounts) {
        # Check for Blob
        Write-Host "Blob containers:"
        try {
            $Params = @{
                "URI"     = "https://$($storageAccount.StorageAccountName).blob.core.windows.net/?comp=list"
                "Method"  = "GET"
                "Headers" = @{
                "Content-Type"  = "application/json"
                "Authorization" = "Bearer $StorageAccountAccessToken"
                "x-ms-version" = "2017-11-09"
                "accept-encoding" = "gzip, deflate"
                }
            }
            $Result = Invoke-RestMethod @Params -UseBasicParsing
        
            # Strip BOM characters if present
            $clean = $Result -replace '^[\uFEFF\u00EF\u00BB\u00BF]+',''
            # Parse as XML
            [xml]$xml = $clean
    
            # Navigate to the container name
            foreach ($Container in $xml.EnumerationResults.Containers.ChildNodes) {
                Write-Host $(" - $($Container.Name)")
            }
        } catch {

        }
        
        # Check for File Shares
        Write-Host "`nFile Shares:"
        try {
            $shares = Get-AzStorageShare -Context $storageAccount.Context
            if ($shares) {
                $shares | ForEach-Object { Write-Host " - $($_.Name)" }
            } else {
            }
        } catch {
        }

        # Check for Queues
        Write-Host "`nQueues:"
        try {
            $queues = Get-AzStorageQueue -Context $storageAccount.Context
            if ($queues) {
                $queues | ForEach-Object { Write-Host " - $($_.Name)" }
            } else {
            }
        } catch {
        }

        # Check for Tables
        Write-Host "`nTables:"
        try {
            $tables = Get-AzStorageTable -Context $storageAccount.Context
            if ($tables) {
                $tables | ForEach-Object { Write-Host " - $($_.Name)" }
            } else {
            }
        } catch {
        }
    }
}

function Get-MyAzStorageAccountContainerFiles {
    param(
        [string]$StorageAccountName,
        [string]$ContainerName,
        [string]$StorageAccountAccessToken
    )

    $Params = @{
        "URI"     = "https://$($StorageAccountName).blob.core.windows.net/$($ContainerName)?restype=container&comp=list"
        "Method"  = "GET"
        "Headers" = @{
        "Content-Type"  = "application/json"
        "Authorization" = "Bearer $StorageAccountAccessToken"
        "x-ms-version" = "2017-11-09"
        "accept-encoding" = "gzip, deflate"
        }
    }

    $XML = Invoke-RestMethod @Params -UseBasicParsing
    #Remove BOM characters and list Blob names
    $XML.TrimStart([char]0xEF,[char]0xBB,[char]0xBF) | Select-Xml -XPath "//Name" | foreach {$_.node.InnerXML}
}

function Get-MyAzStorageAccountContainerFileDownload {
    param(
        [string]$StorageAccountName,
        [string]$ContainerName,
        [string]$StorageAccountAccessToken,
        [string]$Filename
    )

    $Params = @{
        "URI"     = "https://$($StorageAccountName).blob.core.windows.net/$($ContainerName)/$($Filename)"
        "Method"  = "GET"
        "Headers" = @{
        "Content-Type"  = "application/json"
        "Authorization" = "Bearer $StorageAccountAccessToken"
        "x-ms-version" = "2017-11-09"
        "accept-encoding" = "gzip, deflate"
        }
    }

    return Invoke-RestMethod @Params -UseBasicParsing
}

function Set-MyAzStorageAccountContainerFileTag {
    param(
        [string]$StorageAccountName,
        [string]$ContainerName,
        [string]$StorageAccountAccessToken,
        [string]$Filename,
        [string]$TagKey,
        [string]$TagValue
    )

    $Params = @{
        "URI"     = "https://$($StorageAccountName).blob.core.windows.net/$($ContainerName)/$($Filename)?comp=tags"
        "Method"  = "PUT"
        "Headers" = @{
            "Content-Type"  = "application/xml; charset=UTF-8"
            "Authorization" = "Bearer $StorageAccountAccessToken"
            "x-ms-version" = "2020-04-08"   
        }
    }

    $Body = @"
<?xml version="1.0" encoding="utf-8"?>  
<Tags>  
    <TagSet>  
        <Tag>  
            <Key>$($TagKey)</Key>  
            <Value>$($TagValue)</Value>  
        </Tag>    
    </TagSet>  
</Tags> 
"@ 

    Invoke-RestMethod @Params -UseBasicParsing -Body $Body
}
function New-MyAzIntuneScript {
    param(
        [string]$GraphAccessToken,
        [string]$DisplayName,
        [string]$Description,
        [string]$ScriptPath,
        [string]$RunAsLocalUser = "system",
        [string]$FileName
    )

    $script = [Convert]::ToBase64String([IO.File]::ReadAllBytes($ScriptPath))

    $body = @{
        "@odata.type"           = "#microsoft.graph.deviceManagementScript"
        "displayName"           = $DisplayName
        "description"           = $Description
        "scriptContent"         = $script
        "runAsAccount"          = "system"
        "enforceSignatureCheck" = $false
        "fileName"              = $FileName
        "runAs32Bit"            = $false
        "roleScopeTagIds"       = @()
    }

    $jsonBody = $body | ConvertTo-Json -Depth 5
    $headers = @{
        "Authorization" = "Bearer $GraphAccessToken"
        "Content-Type"  = "application/json"
    }

    $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts"
    $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri $uri -Headers $headers -Body $jsonBody

    return $response
}

function Assign-MyAzIntuneScriptToAllUsersAndDevices {
    param(
        [string]$GraphAccessToken,
        [string]$ScriptId
    )
    $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/$ScriptId/assign"
    $headers = @{
        "Authorization" = "Bearer $GraphAccessToken"
        "Content-Type"  = "application/json"
    }
    $body = @{
        deviceManagementScriptAssignments = @(
            @{
                target = @{
                    "@odata.type" = "#microsoft.graph.allLicensedUsersAssignmentTarget"
                }
            },
            @{
                target = @{
                    "@odata.type" = "#microsoft.graph.allDevicesAssignmentTarget"
                }
            }
        )
    } | ConvertTo-Json -Depth 5
    $response = Invoke-RestMethod -UseBasicParsing -Method POST -Uri $uri -Headers $headers -Body $body

    return $response
}
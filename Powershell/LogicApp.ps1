function Get-MyAzLogicApps {
    $result = @()

    $logicApps = Get-AzLogicApp

    foreach ($logicApp in $logicApps) {
        $definition = $logicApp.Definition.ToString() | ConvertFrom-Json

        # Get triggers
        $triggers = @()
        foreach ($trigger in $definition.triggers) {
            $triggerName = $trigger.PSObject.Properties.Name
            $triggerResourceGroup = ""

            if ($logicApp.Id -match "resourceGroups/([^/]+)") {
                $triggerResourceGroup = $matches[1]
            }

            $triggerCallbackUrl = Get-AzLogicAppTriggerCallbackUrl -ResourceGroupName $triggerResourceGroup -Name $logicApp.Name -TriggerName $triggerName

            $triggers += [PSCustomObject]@{
                Name = $triggerName
                Callbackurl = $triggerCallbackUrl
            }
        }

        # Make final object
        $result += [PSCustomObject]@{
            Id = $logicApp.Id
            Name = $logicApp.Name
            AccessEndpoint = $logicApp.AccessEndpoint
            ResponseActions = $definition.actions
            ResponseTriggers = $triggers
        }
    }

    return $result
}
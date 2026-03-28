function Get-MyAzAutomationAccount {
    <#
    .SYNOPSIS
        Enumerates Azure Automation Accounts, reads Runbook contents, and fetches Job outputs.
    .DESCRIPTION
        This script discovers all Automation Accounts in the current Azure context.
        For each account, it lists the runbooks, exports their scripts to a temporary folder,
        prints the script contents to the console, and then cleans up. 
        It also enumerates the jobs for each account and retrieves their output streams.
    #>

    [CmdletBinding()]
    param (
        [int]$MaxJobsToRetrieve = 20 # Limits the number of jobs per account to prevent overwhelming the console
    )

    try {
        $automationAccounts = Get-AzAutomationAccount -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to retrieve Automation Accounts. Ensure you have the necessary permissions."
        return
    }

    if ($automationAccounts.Count -eq 0) {
        Write-Host "No Automation Accounts found in the current subscription."
        return
    }

    # 3. Iterate through each Automation Account
    foreach ($account in $automationAccounts) {
        $rgName = $account.ResourceGroupName
        $aaName = $account.AutomationAccountName

        Write-Host "-------------------------------------------------------------------" -ForegroundColor Green
        Write-Host " AUTOMATION ACCOUNT: $aaName " -ForegroundColor White -BackgroundColor DarkGreen
        Write-Host " RESOURCE GROUP:     $rgName " -ForegroundColor Green
        Write-Host "-------------------------------------------------------------------" -ForegroundColor Green

        # ==========================================
        # ENUMERATE RUNBOOKS & CONTENT
        # ==========================================
        Write-Host "`n[*] Enumerating Runbooks..." -ForegroundColor Yellow
        $runbooks = Get-AzAutomationRunbook -ResourceGroupName $rgName -AutomationAccountName $aaName

        if ($runbooks.Count -eq 0) {
            Write-Host "    No Runbooks found in $aaName." -ForegroundColor DarkGray
        }

        foreach ($runbook in $runbooks) {
            Write-Host "`n    [+] Runbook Name: $($runbook.Name) (Type: $($runbook.RunbookType))" -ForegroundColor Cyan

            # Create a temporary directory to export the runbook
            $tempDir = Join-Path $env:TEMP (New-Guid).ToString()
            New-Item -ItemType Directory -Path $tempDir -ErrorAction SilentlyContinue | Out-Null

            try {
                # Exporting the runbook to the temp directory
                Export-AzAutomationRunbook -ResourceGroupName $rgName -AutomationAccountName $aaName -Name $runbook.Name -OutputFolder $tempDir -Force -ErrorAction Stop | Out-Null

                # Read the exported file
                $exportedFile = Get-ChildItem -Path $tempDir -File | Select-Object -First 1
                if ($exportedFile) {
                    $content = Get-Content -Path $exportedFile.FullName -Raw
                    Write-Host "        --- Runbook Content Start ---" -ForegroundColor DarkGray
                    Write-Host $content -ForegroundColor White
                    Write-Host "        --- Runbook Content End ---" -ForegroundColor DarkGray
                } else {
                    Write-Host "        [!] Could not read exported runbook file (might be empty or unpublished)." -ForegroundColor Red
                }
            }
            catch {
                Write-Host "        [!] Failed to read runbook content: $($_.Exception.Message)" -ForegroundColor Red
            }
            finally {
                # Clean up the temporary directory
                if (Test-Path $tempDir) {
                    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }

        # ==========================================
        # ENUMERATE JOBS & OUTPUTS
        # ==========================================
        Write-Host "`n[*] Enumerating Recent Jobs (Limit: $MaxJobsToRetrieve)..." -ForegroundColor Yellow

        # Get jobs, sorted by start time descending to get the most recent ones
        $jobs = Get-AzAutomationJob -ResourceGroupName $rgName -AutomationAccountName $aaName | 
                Sort-Object StartTime -Descending | 
                Select-Object -First $MaxJobsToRetrieve

        if ($jobs.Count -eq 0) {
            Write-Host "    No Jobs found in $aaName." -ForegroundColor DarkGray
        }

        foreach ($job in $jobs) {
            Write-Host "`n[+] Job ID: $($job.JobId)" -ForegroundColor Magenta
            Write-Host "        Runbook: $($job.RunbookName)" -ForegroundColor DarkGray
            Write-Host "        Status:  $($job.Status)" -ForegroundColor DarkGray
            Write-Host "        Started: $($job.StartTime)" -ForegroundColor DarkGray

            try {
                # Retrieve Job Output Streams (Output, Error, Warning, Any)
                $jobOutputs = Get-AzAutomationJobOutput -Id $job.JobId -ResourceGroupName $rgName -AutomationAccountName $aaName -Stream Any -ErrorAction Stop

                if ($jobOutputs) {
                    Write-Host "        --- Job Output Start ---" -ForegroundColor DarkGray
                    foreach ($output in $jobOutputs) {
                        # Format output based on the stream type (Error vs Standard Output)
                        if ($output.Type -match "Error|Exception") {
                            Write-Host "        [$($output.Type)] $($output.Summary)" -ForegroundColor Red
                        }
                        elseif ($output.Type -match "Warning") {
                            Write-Host "[$($output.Type)] $($output.Summary)" -ForegroundColor DarkYellow
                        }
                        else {
                            Write-Host "        [$($output.Type)] $($output.Summary)" -ForegroundColor White
                        }
                    }
                    Write-Host "        --- Job Output End ---" -ForegroundColor DarkGray
                }
                else {
                    Write-Host "        [No output logged for this job]" -ForegroundColor DarkGray
                }
            }
            catch {
                Write-Host "        [!] Failed to read job output: $($_.Exception.Message)" -ForegroundColor Red
            }
        }

        Write-Host "`n"
    }

}
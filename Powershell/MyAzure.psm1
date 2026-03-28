# 1. Find all .ps1 files in the same directory as this module file.
# (Remove "-Recurse" if you don't want it to search inside sub-folders)
$scriptFiles = Get-ChildItem -Path $PSScriptRoot -Filter "*.ps1" -Recurse

# 2. Loop through each file and dot-source it into the module's scope
foreach ($file in $scriptFiles) {
    try {
        . $file.FullName
    } catch {
        Write-Warning "Failed to load $($file.Name): $_"
    }
}

# 3. Export all the functions so they become available to the user
Export-ModuleMember -Function *
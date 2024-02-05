# Dynamically determine module name
$directorySeparator = [System.IO.Path]::DirectorySeparatorChar
$moduleName = $PSScriptRoot.Split($directorySeparator)[-1]

# Pull current module manifest and test it
$moduleManifest = $PSScriptRoot + $directorySeparator + $moduleName + '.psd1'
$publicFunctionsPath = $PSScriptRoot + $directorySeparator + 'Public'
$privateFunctionsPath = $PSScriptRoot + $directorySeparator + 'Private'
$currentManifest = Test-ModuleManifest $moduleManifest

# Function to recursively get all PS1 files in a directory and its subdirectories
function Get-AllPS1Files {
    param (
        [string]$path
    )

    Get-ChildItem -Path $path -Recurse -Filter '*.ps1' | Where-Object { -Not $_.PSIsContainer }
}

# Discover all .ps1 in private and public directories, dot sourcing (importing) them
$aliases = @()

$publicFunctions = Get-AllPS1Files -path $publicFunctionsPath
$privateFunctions = Get-AllPS1Files -path $privateFunctionsPath

$publicFunctions | ForEach-Object { . $_.FullName }
$privateFunctions | ForEach-Object { . $_.FullName }

# Loop over each public function to import any required aliases as module members
$publicFunctions | ForEach-Object {
    # Export all of the public functions from this module

    # The command has already been sourced above. Query any defined aliases.
    $alias = Get-Alias -Definition $_.BaseName -ErrorAction SilentlyContinue
    if ($alias) {
        $aliases += $alias
        Export-ModuleMember -Function $_.BaseName -Alias $alias
    }
    else {
        Export-ModuleMember -Function $_.BaseName
    }
}
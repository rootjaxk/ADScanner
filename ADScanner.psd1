@{
# Version number of this module.
ModuleVersion = '1.0'

# ID used to uniquely identify this module
GUID = 'd81cb58a-cc81-415f-bb1c-97d0ee9ebb73'

# Author of this module
Author = 'Jack Gooday'

# Copyright statement for this module
Copyright = '(c) 2024. All rights reserved.'

# Description of the functionality provided by this module
# Description = 'Active Directory vulnerability scanner with intelligent reporting capability'

# Minimum version of the Windows PowerShell engine required by this module
# PowerShellVersion = '5.0'


# Modules that must be imported into the global environment prior to importing this module
RootModule = 'ADScanner.psm1'
RequiredModules = @(
    #@{
    #    ModuleName    = 'ActiveDirectory'
    #    ModuleVersion = '1.0.0.0'
    #    Guid          = '43c15630-959c-49e4-a977-758c5cc93408'
    #}
)    #none needed as Invoke-ADScanner will install them if not installed 


# Only export public function to keep all internal working 'hidden' from end user. 
FunctionsToExport = @('Invoke-ADScanner')

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @()

# Variables to export from this module
VariablesToExport = @()

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        # Tags = @()

        # A URL to the license for this module.
        # LicenseUri = ''

        # A URL to the main website for this project.
        # ProjectUri = ''

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        # ReleaseNotes = ''

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''
}

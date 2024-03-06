function Find-SensitiveInfo {
    <#
    .SYNOPSIS
    Searches for sensitive information in sysvol and netlogon folders. This includes credentials and misconfigured logon script permissions.
    Also finds insecure ACLs on scripts in sysvol and netlogon folders.

    Inspired by https://github.com/techspence/ScriptSentry 
  
    .PARAMETER Domain
    The domain to run against, in case of a multi-domain environment
  
    .EXAMPLE 
    Find-SensitiveInfo -Domain test.local
  
    #>
   
    #Add mandatory domain parameter
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [String]
        $Domain
    )
  
    Write-Host '[*] Finding sensitive info...' -ForegroundColor Yellow

    #define SYSVOL and NETLOGON scripts
    $SysvolScripts = "\\$Domain\sysvol\$Domain\scripts"

    #find suspicious scripts
    $ExtensionList = '.bat|.vbs|.ps1|.cmd|.txt|.ps1|.psm1|.psd1|.conf|.config|.cfg|.xml'
    $LogonScripts = try { 
        Get-ChildItem -Path $SysvolScripts -Recurse | Where-Object { $_.Extension -match $ExtensionList } 
    } 
    #catch errors
    catch {}

    #Initialise issues
    $PlaintextCredIssue = [pscustomobject]@{
        Technique  = (to_red "[HIGH]") + " plaintext credentials found readable by low privileged user"
        Score      = 30
        File       = ""
        Credential = ""
        Issue      = "Hardcoded plaintext credentials found in SYSVOL. These can be used by any authenticated user and any account utilising them should be considered compromised."
    }
    
    #find hardcoded creds or secrets in scripts
    foreach ($script in $LogonScripts) {
        $Credentials = Get-Content -Path $script.FullName -ErrorAction SilentlyContinue | Select-String -Pattern "/user:", "-AsPlainText", "passw", "admin", "key", "secret" -AllMatches
        if ($Credentials) {
            $Credentials | ForEach-Object {
                if ($PlaintextCredIssue.File -eq '') {
                    $PlaintextCredIssue.File += $script.FullName
                    $PlaintextCredIssue.Credential += $_
                }
                else {
                    $PlaintextCredIssue.File += "`r`n$($script.FullName)"
                    $PlaintextCredIssue.Credential += "`r`n$($_)"
                }
            }
        }
    }

    #If issue output them
    if ($PlaintextCredIssue.File) {
        $PlaintextCredIssue
    }
}


function Find-SensitiveInfo {
    <#
    .SYNOPSIS
    Searches for sensitive information in sysvol and netlogon folders. This includes credentials and misconfigured logon script permissions.

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
        File      = ""
        Credential = ""
        Issue      = "Hardcoded plaintext credentials found in SYSVOL. These can be used by any authenticated user and any account utilising them should be considered compromised."
    }
    $ModifiablelogonIssue = [pscustomobject]@{
        Technique = (to_red "[HIGH]") + " modifiable logon script - see baby2 for example exploitation"
        File      = ""
        User      = ""
        Rights    = ""
        Issue     = "Low privileged user has write privileges to a logon script. A malcious actor could replace this script with a malicious one and run it on linked workstations"
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
    
    #finds insecure ACLs on scripts
    $SafeUsers = "NT AUTHORITY\\SYSTEM|Administrator|NT SERVICE\\TrustedInstaller|Domain Admins|Server Operators|Enterprise Admins|Administrators|CREATOR OWNER"
    $UnsafeRights = "FullControl|Modify|Write"
    foreach ($script in $LogonScripts) {
        Write-Host "Checking $($script.FullName) for unsafe permissions..." -ForegroundColor Yellow
        #Get ACL for each script
        $ACL = (Get-Acl $script.FullName).Access
        foreach ($entry in $ACL) {
            if ($entry.FileSystemRights -match $UnsafeRights -and $entry.AccessControlType -eq "Allow" -and $entry.IdentityReference -notmatch $SafeUsers) {
                if ($ModifiablelogonIssue.File -eq '') {
                    $ModifiablelogonIssue.File = $script.FullName
                    $ModifiablelogonIssue.User = $entry.IdentityReference.Value
                    $ModifiablelogonIssue.Rights = $entry.FileSystemRights
                }
                else {
                    $ModifiablelogonIssue.File += "`r`n$($script.FullName)"
                    $ModifiablelogonIssue.User += "`r`n$($entry.IdentityReference.Value)"
                    $ModifiablelogonIssue.Rights += "`r`n$($entry.FileSystemRights)"
                }
            }
        }
    } 

    #If issue output them
    if ($PlaintextCredIssue.File) {
        $PlaintextCredIssue
    }
    if ($ModifiablelogonIssue.File) {
        $ModifiablelogonIssue
    }
}


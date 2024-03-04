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

    #find hardcoded creds or secrets in scripts
    foreach ($script in $LogonScripts) {
        $Credentials = Get-Content -Path $script.FullName -ErrorAction SilentlyContinue | Select-String -Pattern "/user:", "-AsPlainText", "passw", "admin", "key", "secret" -AllMatches
        if ($Credentials) {
            $Credentials | ForEach-Object {
                $Issue = [pscustomobject]@{
                    Technique  = (to_red "[HIGH]") + " plaintext credentials found readable by low privileged user"
                    File       = $script.FullName
                    Credential = $_
                    Issue      = "Plaintext credentials found in $($script.FullName)"
                    
                }
                $Issue
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
                $Issue = [pscustomobject] @{
                    Technique = (to_red "[HIGH]") + " modifiable logon script - see baby2 for example exploitation"
                    File      = $script.FullName
                    User      = $entry.IdentityReference.Value
                    Rights    = $entry.FileSystemRights
                    Issue     = "$($entry.IdentityReference.Value) has $($entry.FileSystemRights) over $($script.FullName)"
                }
                $Issue
            }
        }
    } 
}


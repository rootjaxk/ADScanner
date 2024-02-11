function Find-ESC5 {
  <#
  .SYNOPSIS
  Finds ESC5 (explanation of the vulnerability here). Vulnerable PKI Object Access Control. ESC5 relates to vulnerable PKI objects such as the CA object in AD, or any object within
  CN=Public Key Services,CN=Services,CN=Configuration,DC=test,DC=local.

  If a user has unsafe privileges over the CA object, they can compromise the tier 0 asset and perform a golden certificate attack. 

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-ESC5 -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Finding ESC5...' -ForegroundColor Yellow

  #Unsafe privileges over CA
  $DangerousRights = 'GenericAll|WriteOwner|WriteDacl|WriteProperty'

  #Safe user rights over CA
  $PrivilegedUsers = '-500$|-512$|-519$|-544$|-18$|-517$|-516$|-9$|-526$|-527$|S-1-5-10'
  
  #Dynamically retrieve CA hostname (e.g. CA.test.local)
  $CAhostname = (Find-ADCS -domain $domain).dnshostname
 
  #Do ACL check against CA computer object
  $CAComputername = ($CAhostname -split '\.')[0]
  $CAdistinguishedname = (Get-ADComputer -Identity $CAComputername).distinguishedname
  $CAacl = Get-Acl -Path "AD:$CAdistinguishedname"
   
  #Parse the security descriptor over the CA object
  $CAacl | ForEach-Object {
    foreach ($ace in $CAacl.access) {
    $Principal = New-Object System.Security.Principal.NTAccount($ace.IdentityReference)
    if ($Principal -match '^(S-1|O:)') {
        $SID = $Principal
    } else {
        $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
    }
   # if any low-privileged users have dangerous rights over the CA object, ESC5
   if (($ace.ActiveDirectoryRights -match $DangerousRights) -and ($SID -notmatch $PrivilegedUsers)){
      $Issue = [pscustomobject]@{
        Forest                = $Domain
        Name                  = $CAComputername
        DistinguishedName     = $CAdistinguishedname
        IdentityReference     = $ace.IdentityReference
        ActiveDirectoryRights = $ace.ActiveDirectoryRights
        Issue                 = "$($ace.IdentityReference) has $($ace.ActiveDirectoryRights) rights over this CA object"
        Technique             = 'ESC5'
      }
      $Issue
      }
    }
  }
}
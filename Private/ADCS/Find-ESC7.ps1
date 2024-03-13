function Find-ESC7 {
  <#
  .SYNOPSIS
  Searches ADCS for misconfigured certificate authorites vulnerable to ESC7. 
  ESC7 relates to when a user has the Manage CA or Manage Certificates access right on a CA, they can issue failed certificate requests. 
  The SubCA certificate template is vulnerable to ESC1, but only administrators can enroll in the template. 
  A user can request to enroll in the SubCA - which will be denied - but then issued by the manager afterwards escalating through ESC1.

  Module requires PSPKI module as to retrieve ManageCA rights requires RSAT-ADCS

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-ESC7 -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $true)]
    [String]
    $Domain
  )

  Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Finding ESC7..." -ForegroundColor Yellow

  #Safe user rights over CA
  $PrivilegedUsers = '-500$|-512$|-519$|-544$|-18$|-517$|-516$|-9$|-526$|-527$|S-1-5-10'

  $CA = Get-CertificationAuthority
  $CAACL = $CA | Get-CertificationAuthorityAcl | Select-Object -ExpandProperty access

  #Dynamically retrieve CA name(e.g. test-CA-CA)
  $CAname = $(Find-ADCS -domain $domain).displayname

  #Find users with ManageCA or ManageCertificate right - parsing ACLs
  foreach ($ace in $CAACL) {
    $Principal = New-Object System.Security.Principal.NTAccount($ace.IdentityReference)
    if ($Principal -match '^(S-1|O:)') {
      $SID = $Principal
    }
    else {
      $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
    }
    if (($ace.Rights -match 'ManageCA' -OR $ace.Rights -match 'ManageCertificates') -and ($SID -notmatch $PrivilegedUsers)) {
      $Issue = [pscustomobject]@{
        Risk                  = (to_red "[CRITICAL]")
        Technique             = "ESC7"
        Score                 = 50
        Name                  = $CAname
        IdentityReference     = $ace.IdentityReference
        ActiveDirectoryRights = $ace.Rights
        Issue                 = "$($ace.IdentityReference) has $($ace.Rights) rights over this CA object"
      }
      $Issue
    }
  }
}
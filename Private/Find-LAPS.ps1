function Find-LAPS {
  <#
  .SYNOPSIS
  Tests to see if Local Administrator Password Solution (LAPS) is installed on local machine. 
  LAPS is a solution to manage local administrator passwords on domain joined computers and should be used instead of a shared local admin account to prevent lateral movement opportunities.
  Permission for a low privileged user to read any LAPS password is found through Find-ACLs

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-LAPS -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $true)]
    [String]
    $Domain
  )

  Write-Host '[*] Finding LAPS...' -ForegroundColor Yellow

  #Check LAPS on local machine
  $hostname = (Get-ADComputer -Identity $env:COMPUTERNAME).dnshostname

  $LAPS = Get-ChildItem "C:\Program Files\LAPS\CSE" -ErrorAction Ignore

  if ($LAPS -notmatch 'AdmPwd.dll') {
    $Issue = [pscustomobject]@{
      Domain    = $Domain
      Computer  = $hostname
      Issue     = "LAPS is not installed on $hostname. Lateral movement opportunities may exist through reuse of the local administrator password"
      Technique = (to_red "[HIGH]") + " LAPS is not utilized on all computers."
    }
    $Issue
  }
}
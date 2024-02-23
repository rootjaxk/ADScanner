function Find-LAPS {
    <#
  .SYNOPSIS
  Tests to see if LAPS is installed on machine being run on Local Administrator Password Solution (LAPS) is installed. LAPS is a solution to manage local administrator passwords on domain joined computers and should be used instead of a shared local admin account to prevent lateral movement opportunities.
  Limitation will only find computers user has permission to query for LAPS

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-LAPS -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Finding LAPS...' -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  #Check LAPS on local machine
  $hostname = (Get-ADComputer -Identity $env:COMPUTERNAME).dnshostname

  $LAPS = Get-ChildItem "C:\Program Files\LAPS\CSE" -ErrorAction Ignore

  if ($LAPS -notmatch 'AdmPwd.dll'){
    $Issue = [pscustomobject]@{
      Domain    = $Domain
      Computer = $hostname
      Issue     = "LAPS is not installed"
      Technique = "LAPS"
    }
    $Issue
  }

  #Check where can read LAPS password
  #(&(objectCategory=Computer)(ms-MCS-AdmPwd=*))


  #Best way - resolve ACLs for each computer and check for ms-Mcs-AdmPwd to see if installed  -check with badblood
  #Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "ms-Mcs-AdmPwd" -and $_.ActiveDirectoryRights -match "ReadProperty" } | select ObjectDn, SecurityIdentifier

  


}
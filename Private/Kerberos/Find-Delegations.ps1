function Find-Delegations {
  <#
  .SYNOPSIS
  Searches LDAP to return computers that have unconstrained / constrained / resource-based constrained delegation set within Active Directory. 

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-Delegations -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $true)]
    [String]
    $Domain
  )

  Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Finding Delegations..." -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  #Initialise objects
  $ConstrainedIssue = [pscustomobject]@{
    Technique           = (to_red "[HIGH]") + " Constrained delegation"
    Score               = 30
    Object              = ""
    AllowedToDelegateTo = ""
    Issue               = ""
  }

  $UnconstrainedIssue = [pscustomobject]@{
    Technique            = (to_red "[HIGH]") + " Unconstrained delegation"
    Score                = 30
    Object               = ""
    TrustedForDelegation = "$True"
    Issue                = "If computers with unconstrained delegation are compromised, full domain compromise is achievable by coercing auth from the DC which will be then be cached and extractable on the computer"
  }

  $ResourcebasedIssue = [pscustomobject]@{
    Technique                                  = (to_red "[HIGH]") + " Resource-based constrained delegation"
    Score                                      = 30
    Object                                     = ""
    'msDS-AllowedToActOnBehalfOfOtherIdentity' = ""
    Issue                                      = ""
  }

  #Constrained delegation - 'msDS-AllowedToDelegateTo'
  $constrained = Get-ADObject -SearchBase $searchBase -LDAPFilter '(&(objectCategory=*)(msDS-AllowedToDelegateTo=*))' -properties *

  if ($constrained) {
    foreach ($delegation in $constrained) {
      if ($ConstrainedIssue.Object -eq '') {
        $ConstrainedIssue.Object += $delegation.SamAccountName
        $ConstrainedIssue.AllowedToDelegateTo += $delegation.'msDS-AllowedToDelegateTo'
        $ConstrainedIssue.Issue += "$($delegation.samaccountname) has constrained delegation to $($delegation.'msDS-AllowedToDelegateTo')"
      }
      else {
        $ConstrainedIssue.Object += "`r`n$($delegation.SamAccountName)"
        $ConstrainedIssue.AllowedToDelegateTo += "`r`n$delegation.'msDS-AllowedToDelegateTo'"
        $ConstrainedIssue.Issue += "`r`n$($delegation.samaccountname) has constrained delegation to $($delegation.'msDS-AllowedToDelegateTo')"
      }
    }
  }
    
  #Unconstrained delegation - UAC set to TRUSTED_FOR_DELEGATION on users / computers
  $unconstrained = Get-ADObject -SearchBase $searchBase -LDAPFilter '(&(objectCategory=*)(userAccountControl:1.2.840.113556.1.4.803:=524288))' -properties *

  #remove domain controller - has unconstrained delegation by default
  $dcunconstrained = (Get-ADDomainController).name
  $unconstrained = $unconstrained | ? { $dcunconstrained -notmatch $_.name }

  if ($unconstrained) {
    foreach ($delegation in $unconstrained) {
      if ($UnconstrainedIssue.Object -eq '') {
        $UnconstrainedIssue.Object = $delegation.SamAccountName
      }
      else {
        $UnconstrainedIssue.Object += "`r`n$($delegation.SamAccountName)"
      }
    }
  }

  #Resource-based constrained delegation - 'msDS-AllowedToActOnBehalfOfOtherIdentity'  
  $resourcebased = Get-ADObject -SearchBase $searchBase -LDAPFilter '(&(objectCategory=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))' -properties *

  #Additional check for for GenericAll / WriteDACL permissions on computer objects is done in Find-ACL
  if ($resourcebased) {
    foreach ($delegation in $resourcebased) {
      if ($ResourcebasedIssue.Object -eq '') {
        $ResourcebasedIssue.Object += $delegation.SamAccountName
        $ResourcebasedIssue.'msDS-AllowedToActOnBehalfOfOtherIdentity' += $delegation.'msDS-AllowedToActOnBehalfOfOtherIdentity'.access.identityreference.value
        $ResourcebasedIssue.Issue += "$($delegation.SamAccountName) has the msDS-AllowedToActOnBehalfOfOtherIdentity property set to $($delegation.'msDS-AllowedToActOnBehalfOfOtherIdentity'.access.identityreference.value). `n$($delegation.'msDS-AllowedToActOnBehalfOfOtherIdentity'.access.identityreference.value) can delegate to any resource on $($delegation.SamAccountName) (can fully compromise it)"
      }
      else {
        $ResourcebasedIssue.Object += "`r`n$($delegation.SamAccountName)"
        $ResourcebasedIssue.'msDS-AllowedToActOnBehalfOfOtherIdentity' += "`r`n$($delegation.'msDS-AllowedToActOnBehalfOfOtherIdentity'.access.identityreference.value)"
        $ResourcebasedIssue.Issue += "`r`n$($delegation.SamAccountName) has the msDS-AllowedToActOnBehalfOfOtherIdentity property set to $($delegation.'msDS-AllowedToActOnBehalfOfOtherIdentity'.access.identityreference.value). `n$($delegation.'msDS-AllowedToActOnBehalfOfOtherIdentity'.access.identityreference.value) can delegate to any resource on $($delegation.SamAccountName) (can fully compromise it)"
      }
    }
  }

  #Output issues
  if ($ConstrainedIssue.Object -ne '') {
    $ConstrainedIssue
  }
  if ($UnconstrainedIssue.Object -ne '') {
    $UnconstrainedIssue
  }
  if ($ResourcebasedIssue.Object -ne '') {
    $ResourcebasedIssue
  }
}
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

  Write-Host '[*] Finding Delegations...' -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  #Constrained delegation - 'msDS-AllowedToDelegateTo'
  $constrained = Get-ADObject -SearchBase $searchBase -LDAPFilter '(&(objectCategory=*)(msDS-AllowedToDelegateTo=*))' -properties *

  if ($constrained) {
    foreach ($delegation in $constrained) {
      $Issue = [pscustomobject]@{
        Technique           = (to_red "[HIGH]") + " Constrained delegation"
        Object              = $delegation.SamAccountName
        AllowedToDelegateTo = $delegation.'msDS-AllowedToDelegateTo'
        Issue               = "$($delegation.samaccountname) has constrained delegation to $($delegation.'msDS-AllowedToDelegateTo')"
      }
      $Issue
    }
 
    #Unconstrained delegation - UAC set to TRUSTED_FOR_DELEGATION on users / computers
    $unconstrained = Get-ADObject -SearchBase $searchBase -LDAPFilter '(&(objectCategory=*)(userAccountControl:1.2.840.113556.1.4.803:=524288))' -properties *

    if ($unconstrained) {
      foreach ($delegation in $unconstrained) {
        $Issue = [pscustomobject]@{
          Technique = (to_red "[HIGH]") + " Unconstrained delegation"
          Object    = $delegation.SamAccountName
          Issue     = "$($delegation.samaccountname) has unconstrained delegation set"
        }
        $Issue
      }
    }
    #add check for unconstrained & spooler coercion - CRITICAL

    #Resource-based constrained delegation - 'msDS-AllowedToActOnBehalfOfOtherIdentity'  
    $resourcebased = Get-ADObject -SearchBase $searchBase -LDAPFilter '(&(objectCategory=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))' -properties *

    #Additional check for for GenericAll / WriteDACL permissions on computer objects is done in Find-ACL
    if ($resourcebased) {
      foreach ($delegation in $resourcebased) {
        $Issue = [pscustomobject]@{
          Technique                                  = (to_red "[HIGH]") + " Resource-based constrained delegation"
          Object                                     = $delegation.SamAccountName
          'msDS-AllowedToActOnBehalfOfOtherIdentity' = $delegation.'msDS-AllowedToActOnBehalfOfOtherIdentity'.access.identityreference.value
          Issue                                      = "$($delegation.SamAccountName) has the msDS-AllowedToActOnBehalfOfOtherIdentity property set to $($delegation.'msDS-AllowedToActOnBehalfOfOtherIdentity'.access.identityreference.value). `n$($delegation.'msDS-AllowedToActOnBehalfOfOtherIdentity'.access.identityreference.value) can delegate to any resource on $($delegation.SamAccountName) (can fully compromise it)"
        }
        $Issue
      }
    }
  }
}
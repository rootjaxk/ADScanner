function to_red ($msg) {
  "$([char]0x1b)[91m$msg$([char]0x1b)[0m"
}
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
        Domain              = $Domain
        Object              = $delegation.SamAccountName
        AllowedToDelegateTo = $delegation.'msDS-AllowedToDelegateTo'
        Issue               = "$($delegation.samaccountname) has constrained delegation to $($delegation.'msDS-AllowedToDelegateTo')"
        Technique           = (to_red "[HIGH]") + " Constrained delegation"
      }
      $Issue
    }
 
    #Unconstrained delegation - UAC set to TRUSTED_FOR_DELEGATION on users / computers
    $unconstrained = Get-ADObject -SearchBase $searchBase -LDAPFilter '(&(objectCategory=*)(userAccountControl:1.2.840.113556.1.4.803:=524288))' -properties *

    if ($unconstrained) {
      foreach ($delegation in $unconstrained) {
        $Issue = [pscustomobject]@{
          Domain    = $Domain
          Object    = $delegation.SamAccountName
          Issue     = "$($delegation.samaccountname) has unconstrained delegation set"
          Technique = (to_red "[HIGH]") + " Unconstrained delegation"
        }
        $Issue
      }
    }

    #Resource-based constrained delegation - 'msDS-AllowedToActOnBehalfOfOtherIdentity'  
    $resourcebased = Get-ADObject -SearchBase $searchBase -LDAPFilter '(&(objectCategory=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))'

    if ($resourcebased) {
      foreach ($delegation in $resourcebased) {
        $Issue = [pscustomobject]@{
          Domain    = $Domain
          Object    = $delegation.SamAccountName
          Issue     = "$($delegation.SamAccountName) has resource-based nconstrained delegation set from "
          Technique = (to_red "[HIGH]") + " Resource-based constrained delegation"
        }
        $Issue
      }
    }
  
    #Additional check for for GenericAll / WriteDACL permissions on computer objects is done in Find-ACL
  }
}
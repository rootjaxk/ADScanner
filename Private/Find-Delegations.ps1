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
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Finding Delegations...' -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  #Constrained delegation - 'msDS-AllowedToDelegateTo'
  Get-ADObject -SearchBase $searchBase -LDAPFilter '(&(objectCategory=*)(msDS-AllowedToDelegateTo=*))' -properties * | 
  Select-Object SamAccountName, Enabled, msDS-AllowedToDelegateTo, MemberOf, LastLogonDate, SID | Format-List 
 
  #Unconstrained delegation - UAC set to TRUSTED_FOR_DELEGATION on users / computers
  Get-ADObject -SearchBase $searchBase -LDAPFilter '(&(objectCategory=*)(userAccountControl:1.2.840.113556.1.4.803:=524288))'

  #Resource-based constrained delegation - 'msDS-AllowedToActOnBehalfOfOtherIdentity'  
  Get-ADObject -SearchBase $searchBase -LDAPFilter '(&(objectCategory=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))'
  
  Get-ADComputer -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -eq $True} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity    

#Account
#Enabled
#Active - if ($Account.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
#Admin account - if in privileged groups (DA/EA/built in administrators) - higher risk score!
#Last logon
#SID
#Domain
#Dynamically produce domain within Invoke-ADScanner.ps1?

}
function Find-PwdNotRequired {
    <#
  .SYNOPSIS
  Searches LDAP to return accounts that do not require a password (may have a blank password) within Active Directory. 
  This can occur if the PASSWD_NOTREQD" is set to "True" in the "useraccountcontrol" attribute.

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-PwdNotRequired -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Finding accounts not requiring a password...' -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  #Search searchbase for user accounts with "PASSWD_NOTREQD" set to "True" in the "useraccountcontrol" attribute
  Get-ADUser -SearchBase $searchBase -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))' -properties * | 
  Select-Object SamAccountName, Enabled, PasswordNotRequired, MemberOf, LastLogonDate, SID | Format-List
  
#Account
#Enabled
#Active - if ($Account.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
#Admin account - if in privileged groups (DA/EA/built in administrators) - higher risk score!
#Last logon 
#SID
#Domain
#Dynamically produce domain within Invoke-ADScanner.ps1?

}
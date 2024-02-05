function Find-ASREProast {
    <#
  .SYNOPSIS
  Searches LDAP to return accounts that do not require Kerberos pre-authentication within Active Directory. 

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-ASREProast -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Finding ASREProastable Accounts...' -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  #Search searchbase for user accounts with "Do Not require Kerberos preauthentication" set in their useraccountcontrol
  Get-ADUser -SearchBase $searchBase -LDAPFilter '(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' -properties * | 
  Select-Object SamAccountName, Enabled, DoesNotRequirePreAuth, MemberOf, LastLogonDate, SID | Format-List
  
#Account
#Enabled
#Active - if ($Account.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
#Admin account - if in privileged groups (DA/EA/built in administrators) - higher risk score!
#Last logon
#SID
#Domain
#Dynamically produce domain within Invoke-ADScanner.ps1?

}

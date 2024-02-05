function Find-Kerberoast {
    <#
  .SYNOPSIS
  Searches LDAP returning service accounts containing Service Principal Names (SPNs) set within Active Directory. Will exclude krbtgt that has a SPN set by default 

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-Kerberoast -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Finding Kerberoastable Accounts..' -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  #Search searchbase for user accounts with SPNs
  Get-ADUser -SearchBase $searchBase -LDAPFilter '(&(objectCategory=user)(servicePrincipalName=*)(!(SamAccountName=krbtgt)))' -properties * | 
  Select-Object SamAccountName, Enabled, ServicePrincipalName, MemberOf, LastLogonDate, SID | Format-List
  
#Account
#Enabled
#Active - if ($Account.lastlogontimestamp -ge $inactiveThreshold) { "True" } else { "False" }
#Admin account - if in privileged groups (DA/EA/built in administrators) - higher risk score!
#Last logon
#SID
#Domain    
#Dynamically produce domain within Invoke-ADScanner.ps1?

}

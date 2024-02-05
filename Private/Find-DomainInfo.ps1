function Find-DomainInfo {
    <#
  .SYNOPSIS
  Searches LDAP for generic domain information. This information is not vulnerabiltiies, but is used to build an overview of the domain. 

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-DomainInfo -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Extracting Domain information..' -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','


  #Domain name

  #Trusts

  #Functional level

  #OUs 

  #GPOs






  #Search searchbase for descriptions from user / computer accounts 
  Get-ADObject -SearchBase $searchBase -LDAPFilter '(&(|(objectClass=user)(objectClass=computer))(description=*))' -properties * |
  Select-Object SamAccountName, Description

  #Send to generative AI for analysis

}

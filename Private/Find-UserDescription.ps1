function Find-UserDescription {
    <#
  .SYNOPSIS
  Searches LDAP returning accounts containing user / computer descriptions. Generative AI will then determine if descriptions may contain sensitive information 

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-UserDescription -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Extracting User Descriptions..' -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  #Search searchbase for user accounts with SPNs
  Get-ADObject -SearchBase $searchBase -LDAPFilter '(&(|(objectClass=user)(objectClass=computer))(description=*))' -properties * |
  Select-Object SamAccountName, Description, Enabled | Format-List

  #Send to generative AI for analysis

}

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
    [Parameter(Mandatory = $true)]
    [String]
    $Domain
  )

  Write-Host '[*] Extracting User Descriptions..' -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  #Search searchbase for descriptions from user / computer accounts 
  $userswithdescription = Get-ADObject -SearchBase $searchBase -LDAPFilter '(&(|(objectClass=user)(objectClass=computer))(description=*))' -properties *

  $descriptions = $userswithdescription.description

  #Send to generative AI for analysis
  $possible_sensitive_descriptions = #chatgpt stuff

  if ($possible_sensitive_descriptions -eq $true) {
    $Issue = [pscustomobject]@{
      Domain      = $Domain
      User        = $userswithdescription.SamAccountName
      Description = $userswithdescription.descriptions
      Issue       = "$($userswithdescription.samaccountname) has the description $($userswithdescription.descriptions)"
      Technique   = (to_red "[HIGH]") + " plaintext credentials found in Active Directory description field"
    }
    $Issue
  }
}

function Find-GoldenTicket {
  <#
  .SYNOPSIS
  Searches LDAP to return the date the krbtgt password was last changed within Active Directory. Microsoft recommends resetting the KRBTGT account password at least every 180 days

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-GoldenTicket -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $true)]
    [String]
    $Domain
  )

  Write-Host '[*] Finding potential golden tickets...' -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  #krbtgt last set password
  $krbtgtpwdchange = (Get-ADUser -SearchBase $searchBase -LDAPFilter '(&(objectCategory=user)(SamAccountName=krbtgt))'  -properties passwordlastset).passwordlastset

  #Determine if pwd is more than 180 days ago
  $pwdAge = (Get-Date) - ($krbtgtpwdchange)
  $isPwdExpired = [math]::Round($pwdAge.TotalDays)

  if ($isPwdExpired -gt 180) {
    $Issue = [pscustomobject]@{
      Forest    = $Domain
      Name      = "krbtgt"
      Pwdlastset = $isPwdExpired
      Issue     = "The krbtgt password was last changed $isPwdExpired days ago. Microsoft reccomends changing the krbtgt account password every 180 days"
      Technique = "Golden ticket attack"
    }
    $Issue  
  }
}
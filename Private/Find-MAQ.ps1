function Find-MAQ {
    <#
  .SYNOPSIS
  Searches LDAP returning the machine account quota (MAQ). Also checks the default domain controller policy to see who has permission to add workstations to the domain as the MAQ might be
  10 but might be restricted to 'domain admins' which mitigates any attack efforts. By default this is 'NT AUTHORITY\Authenticated Users'. 

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-MAQ -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Finding MachineAccountQuota...' -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  #Retrieve MAQ
  $MAQ = Get-ADObject $searchBase -Properties ms-DS-MachineAccountQuota | select-object  ms-DS-MachineAccountQuota
  Write-Host "MAQ = $MAQ"

  #Also check default domain controller group policy to see who has permission to add workstations to domain
  $report = Get-GPOReport -Name 'Default Domain Controllers Policy' -ReportType html
  
  # Use regex to find the line containing "Add workstations to domain" and extract content within <td> tags
  $pattern = 'Add workstations to domain<\/td><td>(.*?)<\/td>'
  $match = $report | Select-String -Pattern $pattern -AllMatches | ForEach-Object { $_.Matches.Groups[1].Value }

  Write-Host "$match can add workstations to the domain"

}
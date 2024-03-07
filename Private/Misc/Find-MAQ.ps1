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
    [Parameter(Mandatory = $true)]
    [String]
    $Domain
  )

  Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Finding MachineAccountQuota..." -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  # Define privileged groups that should have permission to add machines to othe domain
  $privilegedgroups = @("Administrators", "Enterprise Admins", "Domain Admins", "Server Operators", "Backup Operators", "Server Operators")

  #Retrieve MAQ from domain
  $MAQ = (Get-ADObject $searchBase -Properties ms-DS-MachineAccountQuota).'ms-DS-MachineAccountQuota'

  #Also check default domain controller group policy to see who has permission to add workstations to domain
  $report = Get-GPOReport -Name 'Default Domain Controllers Policy' -ReportType html
  
  # Use regex to find the line containing "Add workstations to domain" and extract content within <td> tags
  $pattern = 'Add workstations to domain<\/td><td>(.*?)<\/td>'
  $additionprivileges = $report | Select-String -Pattern $pattern -AllMatches | ForEach-Object { $_.Matches.Groups[1].Value }

  #Check if the MAQ is default
  if ($MAQ -ne 0 -and $additionprivileges -eq "NT AUTHORITY\Authenticated Users") {
    $Issue = [pscustomobject]@{
      Technique                   = (to_yellow "[MEDIUM]") + " Non-admin users can add computers to the domain"
      Score                       = 19
      MachineAccountQuota         = $MAQ
      PermissiontoAddWorkstations = $additionprivileges
      Issue                       = "$additionprivileges can add $MAQ machines to $domain"
    } 
    $Issue
  }
  #If group changed to a custom group, may be mitigated but need to check - lower risk
  elseif ($MAQ -ne 0 -and $additionprivileges -ne "NT AUTHORITY\Authenticated Users" -and $additionprivileges -notmatch  $privilegedgroups) {
    $Issue = [pscustomobject]@{
      Technique                   = (to_green "[LOW]") + " Potential for non-admin users can add computers to the domain"
      Score                       = 5
      MachineAccountQuota         = $MAQ
      PermissiontoAddWorkstations = $additionprivileges
      Issue                       = "$additionprivileges can add $MAQ machines to $domain - check this group is restricted to tier 0 only" #[TODO] - check this group is restricted to tier 0 only
    }
    $Issue
  }
}
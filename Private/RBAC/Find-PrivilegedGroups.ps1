function Find-PrivilegedGroups {
  <#
.SYNOPSIS
Searches the Active Directory domain searching for the members of default privileged groups. These groups are overly permissive and should n ot be utilised in favour of a custom role-based access archiecture (RBAC).

Baselines:
Administrators       - 10
Domain Admins        - 10
Enterprise Admins    - 0
DNS Admins           - 0
Backup Operators     - 0
Server Operators     - 0
Account Operators    - 0
Print Operators      - 0
Remote Desktop Users - 0
Schema Admins        - 0

.PARAMETER Domain
The domain to run against, in case of a multi-domain environment

.EXAMPLE 
Find-PrivilegedGroups -Domain test.local

#>

  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $true)]
    [String]
    $Domain
  )
  
  Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Finding Privileged Groups..." -ForegroundColor Yellow

  # Define a hashtable to store group members - better than array as doesn't allow dupicate members (if in multiple groups)
  $groupMembers = @{}

  #Define groups - https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups
  $groups = @("Administrators", "Enterprise Admins", "Domain Admins", "DnsAdmins", "Backup Operators",
    "Server Operators", "Account Operators", "Print Operators", "Remote Desktop Users",
    "Schema Admins", "Cert Publishers")

  #Recursive to get all members of the group (including nested groups) and store in hashtable
  foreach ($group in $groups) {
    $members = (Get-ADGroupMember -Identity $group -Recursive).SamAccountName
    $groupMembers[$group] = $members
  }

  # Assign each group's members to a separate variable
  foreach ($group in $groups) {
    $variableName = "${group}"
    New-Variable -Name $variableName -Value $groupMembers[$group] -Force
  }

  $PrivilegedIssues = @()
  $PrivilegedMembers = @("[*] Privileged Group info:")

  # Count number of users in each group
  foreach ($group in $groupMembers.GetEnumerator()) {
    $groupName = $group.Key
    $userCount = $group.Value.Count
    $MemberCounts = [pscustomobject]@{
      Group   = $groupName
      Members = $group.Value
      Count   = $userCount
    }
    $PrivilegedMembers += $MemberCounts

    if ($groupName -eq "Administrators" -and $userCount -gt 10) {
      $Issue = [pscustomobject]@{
        Risk        = (to_red "[HIGH]")
        Issue       = "Administrators group does not meet the benchmark (maximum 10 users required)."
        Score       = 20
        Members     = $group.Value
        MemberCount = $group.Value.Count
      }
      $PrivilegedIssues += $Issue
    }
    elseif ($groupName -eq "Domain Admins" -and $userCount -gt 10) {
      $Issue = [pscustomobject]@{
        Risk        = (to_red "[HIGH]")
        Technique   = "Domain Admins group does not meet the benchmark (maximum 10 users required)."
        Score       = 20
        Members     = $group.Value
        MemberCount = $group.Value.Count
      }
      $PrivilegedIssues += $Issue
    }
    elseif ($groupName -eq "Enterprise Admins" -and $userCount -gt 0) {
      $Issue = [pscustomobject]@{
        Risk        = (to_red "[HIGH]")
        Technique   = "Enterprise Admins group does not meet the benchmark (maximum 0 users required)."
        Score       = 20
        Members     = $group.Value
        MemberCount = $group.Value.Count
      }
      $PrivilegedIssues += $Issue
    }
    elseif ($groupName -eq "DnsAdmins" -and $userCount -gt 0) {
      $Issue = [pscustomobject]@{
        Risk        = (to_red "[HIGH]")
        Technique   = "DnsAdmins group does not meet the benchmark (maximum 0 users required)."
        Score       = 20
        Members     = $group.Value
        MemberCount = $group.Value.Count
      }
      $PrivilegedIssues += $Issue
    }
    elseif ($groupName -eq "Backup Operators" -and $userCount -gt 0) {
      $Issue = [pscustomobject]@{
        Risk        = (to_red "[HIGH]")
        Technique   = "BackupOperators group does not meet the benchmark (maximum 0 users required)."
        Score       = 20
        Members     = $group.Value
        MemberCount = $group.Value.Count
      }
      $PrivilegedIssues += $Issue
    }
    elseif ($groupName -eq "Server Operators" -and $userCount -gt 0) {
      $Issue = [pscustomobject]@{
        Risk        = (to_red "[HIGH]")
        Technique   = "Server Operators group does not meet the benchmark (maximum 0 users required)."
        Score       = 20
        Members     = $group.Value
        MemberCount = $group.Value.Count
      }
      $PrivilegedIssues += $Issue
    }
    elseif ($groupName -eq "Account Operators" -and $userCount -gt 0) {
      $Issue = [pscustomobject]@{
        Risk        = (to_red "[HIGH]")
        Technique   = "Account Operators group does not meet the benchmark (maximum 0 users required)."
        Score       = 20
        Members     = $group.Value
        MemberCount = $group.Value.Count
      }
      $PrivilegedIssues += $Issue
    }
    elseif ($groupName -eq "Print Operators" -and $userCount -gt 0) {
      $Issue = [pscustomobject]@{
        Risk        = (to_red "[HIGH]")
        Technique   = "Print Operators group does not meet the benchmark (maximum 0 users required)."
        Score       = 20
        Members     = $group.Value
        MemberCount = $group.Value.Count
      }
      $PrivilegedIssues += $Issue
    }
    elseif ($groupName -eq "Remote Desktop Users" -and $userCount -gt 0) {
      $Issue = [pscustomobject]@{
        Risk        = (to_red "[HIGH]")
        Technique   = "Remote Desktop Users group does not meet the benchmark (maximum 0 users required)."
        Score       = 20
        Members     = $group.Value
        MemberCount = $group.Value.Count
      }
      $PrivilegedIssues += $Issue
    }
    elseif ($groupName -eq "Schema Admins" -and $userCount -gt 0) {
      $Issue = [pscustomobject]@{
        Risk        = (to_red "[HIGH]")
        Technique   = "Schema Admins group does not meet the benchmark (maximum 0 users required)."
        Score       = 20
        Members     = $group.Value
        MemberCount = $group.Value.Count
      }
      $PrivilegedIssues += $Issue
    }
  } 
  #$PrivilegedMembers - info could be used later in web report
  $PrivilegedIssues
}
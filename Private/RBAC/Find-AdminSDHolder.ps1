function Find-AdminSDHolder {
  <#
  .SYNOPSIS
  Searches Active Directory for all accounts with the adminCount attribute set to 1. Any user added to default privileged groups (e.g. Domain Admins) will have their adminCount attribute set to 1. 
  This attribute is used to protect privileged accounts from being modified by non-privileged users.
  If user has adminCount set to 1 and not a member of default privileged groups, it is a security risk.
  Attackers will commonly search for users with adminCount set to 1 to find accounts that may have left-over high privileges that are not members of default privileged groups.

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-AdminSDHolder -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $true)]
    [String]
    $Domain
  )

  Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Finding AdminSDHolder..." -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  # Define SIDs of privileged groups that will have adminCount set - https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory
  $privilegedgroups = @("Account Operators", "Administrators", "Backup Operators", "Enterprise Admins", "Domain Admins", "Domain Controllers", "Print Operators", "Read-only Domain Controllers", "Schema Admins", "Server Operators", "Key Admins", "Enterprise Key Admins", "Replicator")
  $adminCountGroupSIDs = '-502$|-500$|-512$|-551$|-552$|-550$|-549$|-548$|-519$|-518$|-516$|-544$|-526$|-527$|-521$'

  # Initialize arrays to store members
  $PrivilegedGroupMembers = @()
  $PrivilegedGroupMemberSIDs = @()

  foreach ($group in $privilegedgroups) {
    # Get members of the group and select only the SamAccountName
    $members = Get-ADGroupMember -Identity $group -Recursive | Select-Object -ExpandProperty SamAccountName
    # Add members to the array
    $PrivilegedGroupMembers += $members
  }

  # Remove duplicates from the array
  $PrivilegedGroupMembers = $PrivilegedGroupMembers | Select-Object -Unique
  
  #Find SIDs of privileged group members
  foreach ($member in $PrivilegedGroupMembers) {
    $member = New-Object System.Security.Principal.NTAccount($member)
    if ($member -match '^(S-1|O:)') {
      $SID = $member
    }
    else {
      $SID = ($member.Translate([System.Security.Principal.SecurityIdentifier])).Value
    }
    $PrivilegedGroupMemberSIDs += $SID
  }

  #get users with admincount set
  $AdminCount = Get-ADObject -searchBase $searchBase -LDAPFilter "(adminCount=1)" -properties samaccountname
  $AdminSDcount = 0

  #Initalise issue
  $AdminSDIssue = [pscustomobject]@{
    Risk       = (to_yellow "MEDIUM")
    Technique  = "Suspicious / legacy admin account"
    Score      = 15
    Name       = ""
    adminCount = "1"
    Issue      = ""
  }

  #Translate members to SIDs
  $AdminCount | ForEach-Object {
    try {
      foreach ($entry in $_.samaccountname) {
        $Principal = New-Object System.Security.Principal.NTAccount($entry)
        if ($Principal -match '^(S-1|O:)') {
          $SID = $Principal
        }
        else {
          $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
        }
        #check if user rights are a low-privileged user
        $privilegedGroupMatch = $false
        foreach ($i in $PrivilegedGroupMemberSIDs) {
          if ($SID -match $i) {
            $privilegedGroupMatch = $true
            break
          }
        }
      }
    }
    catch {}
    #filter admincount removing default protected groups and members of them
    if (($SID -notmatch $adminCountGroupSIDs) -and (!$privilegedGroupMatch)) {
      if ($AdminSDIssue.Name -eq '') {
        $AdminSDIssue.Name += $_.Name
      }
      else {
        $AdminSDIssue.Name += "`r`n$($_.Name)"
      }
      $AdminSDcount++
    }
  }
  if ($AdminSDIssue.Name -ne '') {
    $AdminSDIssue.Issue = "$AdminSDcount users have the admincount attribute set to 1 but is not a member of default privileged groups. These user may have unaudited high privileges."
    $AdminSDIssue
  }
}
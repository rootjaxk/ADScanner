function Find-LAPS {
  <#
  .SYNOPSIS
  Tests to see if Local Administrator Password Solution (LAPS) is installed on local machine. 
  LAPS is a solution to manage local administrator passwords on domain joined computers and should be used instead of a shared local admin account to prevent lateral movement opportunities.
  Permission for a low privileged user to read any LAPS password is found through Find-ACLs

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-LAPS -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $true)]
    [String]
    $Domain
  )

  
  Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Finding LAPS..." -ForegroundColor Yellow

  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  $domainControllers = "OU=Domain Controllers,$searchBase"
  $domainComputers = "CN=Computers,$searchBase"
  
  #Check LAPS on local machine
  $hostname = (Get-ADComputer -Identity $env:COMPUTERNAME).dnshostname

  $LAPS = Get-ChildItem "C:\Program Files\LAPS\CSE" -ErrorAction Ignore

  #Safe user rights to read LAPS
  $PrivilegedACLUsers = '-500$|-512$|-519$|-544$|-18$|-516$|S-1-5-9'

  # Define tier 0 privileged groups that would be allowed to read LAPS
  $privilegedgroups = @("Administrators", "Enterprise Admins", "Domain Admins", "Domain Controllers")

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

  #check if LAPS is installed on device
  if (!$LAPS) {
    $Issue = [pscustomobject]@{
      Risk      = (to_red "HIGH")
      Technique = "LAPS is not utilized on all computers."
      Score     = 20
      Computer  = $hostname
      Issue     = "LAPS is not installed on $hostname. Lateral movement opportunities may exist through reuse of the local administrator password"
    }
    $Issue
  }
  else {
    #do additional checks - enumerate who can read LAPS passwords on computers + domain controllers if LAPS module is installed. TODO - dynamically find servers OU based off tiering system
    try {
      $domaincontrollerLAPS = (Find-AdmPwdExtendedRights -Identity $domainControllers).ExtendedRightHolders
      $domaincomputerLAPS = (Find-AdmPwdExtendedRights -Identity $domainComputers).ExtendedRightHolders
    }
    catch {}
    
    #Initialise object
    $LAPSDCIssue = [pscustomobject]@{
      Risk              = (to_red "CRITICAL")
      Technique         = ""
      Score             = 50
      IdentityReference = ""
      LAPScomputer      = ""
      Issue             = ""
    }
    $LAPScomputerIssue = [pscustomobject]@{
      Risk              = (to_red "HIGH")
      Technique         = ""
      Score             = 35
      IdentityReference = ""
      LAPScomputer      = ""
      Issue             = ""
    }
    #Check for low privileged accounts can read LAPS
    foreach ($user in $domaincontrollerLAPS) {
      $Principal = New-Object System.Security.Principal.NTAccount($user)
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
      #check for LAPS read
      if ($SID -notmatch $PrivilegedACLUsers -and !$privilegedGroupMatch) {
        $LAPSDCIssue.Technique = "Low privileged principal can read LAPS password on domain controllers"
        $LAPSDCIssue.LAPSComputer = $domainControllers
        if ($LAPSDCIssue.IdentityReference -eq '') {
          $LAPSDCIssue.IdentityReference = $user
          $LAPSDCIssue.Issue = "$user has read LAPS password rights on $domainControllers meaning low privileged users low privileged users can read the local administrator password on domain controllers (effective domain admin). Permission to read the LAPS password should be delegated to administators only."
        }
        else {
          $LAPSDCIssue.IdentityReference += "`r`n$user"
          $LAPSDCIssue.Issue += "`r`n$user has read LAPS password rights on $domainControllers meaning low privileged users low privileged users can read the local administrator password on domain controllers (effective domain admin). Permission to read the LAPS password should be delegated to administators only."
        }
      }
    }
    foreach ($user in $domaincomputerLAPS) {
      $Principal = New-Object System.Security.Principal.NTAccount($user)
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
      #check for LAPS read
      if ($SID -notmatch $PrivilegedACLUsers -and !$privilegedGroupMatch) {
        $LAPScomputerIssue.Technique = "Low privileged principal can read LAPS password on domain computers"
        $LAPScomputerIssue.LAPSComputer = $domainComputers
        if ($LAPScomputerIssue.IdentityReference -eq '') {
          $LAPScomputerIssue.IdentityReference = $user
          $LAPScomputerIssue.Issue = "$user has read LAPS password rights on $domainComputers, meaning low privileged users can read the local administrator password on all of these computers within this OU. Permission to read the LAPS password should be delegated to administators only."
        }
        else {
          $LAPScomputerIssue.IdentityReference += "`r`n$user"
          $LAPScomputerIssue.Issue += "`r`n$user has read LAPS password rights on $domainComputers, meaning low privileged users can read the local administrator password on all of these computers within this OU. Permission to read the LAPS password should be delegated to administators only."
        }
      }
    }
  }
  #Output issues
  if ($LAPSDCIssue.IdentityReference -ne '') {
    $LAPSDCIssue
  }
  if ($LAPScomputerIssue.IdentityReference -ne '') {
    $LAPScomputerIssue
  }
}
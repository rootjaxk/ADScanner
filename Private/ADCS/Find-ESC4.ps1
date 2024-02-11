function Find-ESC4 {
  <#
  .SYNOPSIS
  Searches ADCS for misconfigured certificate templates vulnerable to ESC4. Certificate templates are securable objects in AD, meaning they have a security descriptor that
specifies which AD principals have specific permissions over the template.

  ESC4 relates to insecure permissions on certificate templates. This allows a low-privileged user to edit security settings on a certificate template and escalate their privileges.
  This can be either insecure template owners or insecure ACL rights over the template.

  This function improves logic from https://github.com/TrimarcJake/Locksmith.

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-ESC4 -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Finding ESC4...' -ForegroundColor Yellow
  
  #Get all ADCS objects
  $ADCSobjects = Find-ADCSobjects -Domain $Domain

  #####################################
  # Dynamically find privileged users #
  #####################################

  #Safe rights over template
  $PrivilegedUsers = '-500$|-512$|-519$|-544$|-18$|-517$|-516$|-9$|-526$|-527$|S-1-5-10'

  # Define privileged groups
  $privilegedgroups = @("Administrators", "Enterprise Admins", "Domain Admins")

  # Initialize array to store members
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
    } else {
      $SID = ($member.Translate([System.Security.Principal.SecurityIdentifier])).Value
    }
    $PrivilegedGroupMemberSIDs += $SID
  }

  ##########
  # Owners #
  ##########

   # Unsafe owner of template - will allow privilege escalation
   $ADCSObjects | ForEach-Object {
    $Principal = New-Object System.Security.Principal.NTAccount($_.nTSecurityDescriptor.Owner)
    if ($Principal -match '^(S-1|O:)') {
        $SID = $Principal
    } else {
        $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
    }

    $privilegedGroupMatch = $false
    foreach ($i in $PrivilegedGroupMemberSIDs) {
        if ($SID -match $i) {
            $privilegedGroupMatch = $true
            break
        }
    }
    # filter owner rights removing all domain/enterprise admin users (as they might have owner rights if they created template)
    if ( ($_.objectClass -eq 'pKICertificateTemplate') -and ($SID -notmatch $PrivilegedUsers) -and ($SID -notmatch $PrivilegedUsers -and !$privilegedGroupMatch)) {
        $Issue = [pscustomobject]@{
            Forest                = $Domain
            Name                  = $_.Name
            DistinguishedName     = $_.DistinguishedName
            Issue                 = "$($_.nTSecurityDescriptor.Owner) has Owner rights on this template"
            Technique             = 'ESC4'
        }
        $Issue
      }
    }

  ###########
  #  ACLs   #
  ###########

  #Unsafe rights over template (WriteProperty required to enrol)
  $DangerousRights = 'GenericAll|WriteOwner|WriteDacl'

  #Unsafe ACLs over template - will allow privilege escalation
  $ADCSObjects | ForEach-Object {
    foreach ($entry in $_.nTSecurityDescriptor.Access) {
    $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
    if ($Principal -match '^(S-1|O:)') {
        $SID = $Principal
    } else {
        $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
    }
    if ( ($_.objectClass -eq 'pKICertificateTemplate') -and
        ($SID -match $LowPrivilegedUsers) -and
        ($entry.ActiveDirectoryRights -match $DangerousRights)
        ) {
        $Issue = [pscustomobject]@{
            Forest                = $_.CanonicalName.split('/')[0]
            Name                  = $_.Name
            DistinguishedName     = $_.DistinguishedName
            IdentityReference     = $entry.IdentityReference
            ActiveDirectoryRights = $entry.ActiveDirectoryRights
            Issue                 = "$($entry.IdentityReference) has $($entry.ActiveDirectoryRights) rights on this template"
            Technique             = 'ESC4'
        }
        $Issue
       }
     }
    }
  }
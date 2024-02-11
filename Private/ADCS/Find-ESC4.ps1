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

  #Unsafe rights over template (Everyone, Authenticated Users, Domain Users, Domain Computers)
  $LowPrivilegedUsers = 'S-1-1-0|-11$|-513$|-515$'
   
  #Safe rights over template
  $PrivilegedUsers = '-500$|-512$|-519$|-544$|-18$|-517$|-516$|-9$|-526$|-527$|S-1-5-10'
  #Dynamically find privileged uers (from find-privilegedgroups) and highlight any users not in them that has dangerous rights over the template. or maybe when classify tiers can do it


  #Unsafe rights over template (WriteProperty required to enrol)
  $DangerousRights = 'GenericAll|WriteOwner|WriteDacl'

  ##########
  # Owners #
  ##########
  #Unsafe owner of template - will allow privilege escalation
   $ADCSObjects | ForEach-Object {
    $Principal = New-Object System.Security.Principal.NTAccount($_.nTSecurityDescriptor.Owner)
    if ($Principal -match '^(S-1|O:)') {
        $SID = $Principal
    } else {
        $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
    }

    if ( ($_.objectClass -eq 'pKICertificateTemplate') -and ($SID -match $LowPrivilegedUsers) ) {
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

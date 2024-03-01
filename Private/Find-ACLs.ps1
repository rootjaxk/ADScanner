function Find-ACLs {
  <#
  .SYNOPSIS
  Searches for low-privileged users with dangerous rights over every single object within the Active Directory domain. 
  Automatically excludes default privileged groups that have set ACLs protected by the AdminSDHolder which should not be utilised (separate finding) - https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory
  Will find dangerous rights including low-privileged principals with DCSync rights, unsafe privileges to modify GPOs/accounts, RBCD rights over computer objects and ability to read LAPS passwords.
  Will take longer on very large domains, as iterates over all domain objects.

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-ACLs -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $true)]
    [String]
    $Domain
  )

  Write-Host '[*] Finding Vulnerable ACLs... (may take a while depending on size of domain)' -ForegroundColor Yellow

   
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','


  #####################################
  # Dynamically find privileged users #
  #####################################
  
  #Unsafe privileges for ACLs
  $DangerousRights = 'AllExtendedRights|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|GpLink|Write|Create'

  #Dynamically get DNSAdmins SID (has variable RID)
  $DNSAdminsSID = (Get-ADGroup -Filter { Name -eq 'DNSAdmins' }).SID.Value

  #Safe user rights (mostly default groups with ACLs protected by AdminSDHolder) - https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
  $PrivilegedACLUsers = '-500$|-512$|-519$|-544$|-18$|-517$|-516$|S-1-5-9|-526$|-527$|S-1-5-10|-561$|-520$|S-1-3-0|-550$|-548$|-553$'

  # Define privileged groups that can DCSync by default - tier 0
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


  ##############
  # ACL checks #
  ##############

  #All objects in domain
  $Alldomainobjects = (Get-ADObject -SearchBase $searchBase -LDAPFilter '(&(objectClass=*))').distinguishedname

  #Get ACLs over iterating over all domain objects
  foreach ($object in $Alldomainobjects) {
    $DomainACLs = Get-Acl -Path "AD:$object"
    #Parse the security descriptor over the object
    $DomainACLs | ForEach-Object {
      foreach ($ace in $DomainACLS.access) {
        $Principal = New-Object System.Security.Principal.NTAccount($ace.IdentityReference)
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
        #check for RBCD (write over computer object) - if computer object then RBCD
        if (($object -match "CN=Computers" -or $object -match "OU=Domain Controllers") -and ($ace.AccessControlType -eq "Allow") -and ($ace.ActiveDirectoryRights -match $DangerousRights) -and ($SID -notmatch $PrivilegedACLUsers -and !$privilegedGroupMatch -and $SID -notmatch $DNSAdminsSID)) {
          $Issue = [pscustomobject]@{
            Forest                = $Domain
            ObjectName            = ($DomainACLs.path -split '/')[-1]
            IdentityReference     = $ace.IdentityReference
            AccessControlType     = $ace.AccessControlType
            ActiveDirectoryRights = $ace.ActiveDirectoryRights
            Issue                 = "$($ace.IdentityReference) has dangerous RBCD privileges ($($ace.ActiveDirectoryRights)) over $object"
            Technique             = (to_red "[CRITICAL]") + " [RBCD] Low privileged principal with dangerous RBCD rights"
          }
          $Issue
        }
        # if any low-privileged users have dangerous rights over object
        elseif (($ace.ActiveDirectoryRights -match $DangerousRights) -and ($ace.AccessControlType -eq "Allow") -and ($SID -notmatch $PrivilegedACLUsers -and !$privilegedGroupMatch -and $SID -notmatch $DNSAdminsSID)) {
          $Issue = [pscustomobject]@{
            Forest                = $Domain
            ObjectName            = ($DomainACLs.path -split '/')[-1]
            IdentityReference     = $ace.IdentityReference
            AccessControlType     = $ace.AccessControlType
            ActiveDirectoryRights = $ace.ActiveDirectoryRights
            Issue                 = "$($ace.IdentityReference) has dangerous ($($ace.ActiveDirectoryRights)) rights over $object"
            Technique             = (to_red "[CRITICAL]") + " [RIGHTS] - Low privileged principal with dangerous rights"
          }
          $Issue
        }
        #Parse DCSync (not in standard AD rights, need to search for matching ACL GUID)
        elseif (($ace.ObjectType -match '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2') -and ($ace.AccessControlType -eq "Allow") -and ($SID -notmatch $PrivilegedACLUsers -and $SID -notmatch $privilegedGroupMatch)) {
          $Issue = [pscustomobject]@{
            Forest                = $Domain
            ObjectName            = ($DomainACLs.path -split '/')[-1]
            IdentityReference     = $ace.IdentityReference
            AccessControlType     = $ace.AccessControlType
            ActiveDirectoryRights = $ace.ActiveDirectoryRights
            Issue                 = "$($ace.IdentityReference) has DCSync ($($ace.ActiveDirectoryRights)) rights over $searchBase"
            Technique             = (to_red "[CRITICAL]") + " [DCSync] - Low privileged principal with DCSync rights"
          }
          $Issue
        }
        #check for LAPS permissions read - f00000000-0000-0000-0000-000000000000 GUID - (read all properties - can read ms-mcs-admpwd) 
        elseif (($object -match "CN=Computers" -or ($object -match "OU=Domain Controllers" -and $object -notmatch "CN=.*,OU=Domain Controllers")) -and ($ace.ObjectType -eq "00000000-0000-0000-0000-000000000000") -and ($ace.ActiveDirectoryRights -match "ExtendedRights") -and ($SID -notmatch $PrivilegedACLUsers -and $SID -notmatch $privilegedGroupMatch)) {
          $Issue = [pscustomobject]@{
            Forest                = $Domain
            ObjectName            = ($DomainACLs.path -split '/')[-1]
            IdentityReference     = $ace.IdentityReference
            AccessControlType     = $ace.AccessControlType
            ActiveDirectoryRights = $ace.ActiveDirectoryRights
            Issue                 = "$($ace.IdentityReference) can read LAPS password over over $object"
            Technique             = (to_red "[CRITICAL]") + " [LAPS] - low privileged principal can LAPS password"
          }
          $Issue
        }
      }
    }
  }
}

#potential - todo

#Design tiering system first
  
#Check for tiering violations (with ACLs over all user/group/OU objects)

#Tier 1/2 over tier 0

#Tier 2 over tier 1
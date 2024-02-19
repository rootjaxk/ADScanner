function Find-ACLs {
    <#
  .SYNOPSIS
  Searches for low-privileged users with dangerous rights over every single object within the Active Directory domain. 
  Automatically excludes default privileged groups which shoulD not be utilised (separate finding)
  Will find dangerous rights including DCSync rights, write privileged over GPOs & accounts and RBCD rights over computer objects.

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-ACLs -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Finding vulnerable ACLs..' -ForegroundColor Yellow

   
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','


  #####################################
  # Dynamically find privileged users #
  #####################################
  
  #Unsafe privileges
  $DangerousRights = 'AllExtendedRights|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|GpLink|Write|Create'

  #Dynamically get DNSAdmins SID (has variable RID)
  $DNSAdminsSID = (Get-ADGroup -Filter { Name -eq 'DNSAdmins' }).SID.Value

  #Safe user rights (mostly default groups) - https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
  $PrivilegedACLUsers = '-500$|-512$|-519$|-544$|-18$|-517$|-516$|-9$|-526$|-527$|S-1-5-10|-561$|-520$|S-1-3-0|-550$|-548$'

  # Define privileged groups - tier 0
  $privilegedgroups = @("Administrators", "Enterprise Admins", "Domain Admins", "Domain Controllers")

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


  ##############
  # ACL checks #
  ##############

  #All objects in domain
  $Alldomainobjects = (Get-ADObject -SearchBase $searchBase -LDAPFilter '(&(objectClass=*))').distinguishedname

  #Get ACLs over iterating over all domain objects
  foreach ($object in $Alldomainobjects){
    $DomainACLs = Get-Acl -Path "AD:$object"
    #Parse the security descriptor over the object
    $DomainACLs | ForEach-Object {
      foreach ($ace in $DomainACLS.access) {
      $Principal = New-Object System.Security.Principal.NTAccount($ace.IdentityReference)
      if ($Principal -match '^(S-1|O:)') {
          $SID = $Principal
      } else {
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
     # if any low-privileged users have dangerous rights over object
     if (($ace.ActiveDirectoryRights -match $DangerousRights) -and ($SID -notmatch $PrivilegedACLUsers -and !$privilegedGroupMatch -and $SID -notmatch $DNSAdminsSID)){
        $Issue = [pscustomobject]@{
          Forest                = $Domain
          ObjectDistinguishedName     = ($DomainACLs.path -split '/')[-1]
          IdentityReference     = $ace.IdentityReference
          ActiveDirectoryRights = $ace.ActiveDirectoryRights
          Issue                 = "$($ace.IdentityReference) has dangerous ($($ace.ActiveDirectoryRights)) rights over $object"
          Technique             = '[CRITICAL] Low privileged principal with dangerous rights'
        }
        $Issue
        }
      #Parse DCSync (not in standard AD rights, need to search for matching ACL GUID)
      elseif (($ace.ObjectType -match '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2') -and ($SID -notmatch $PrivilegedACLUsers -and $SID -notmatch $privilegedGroupMatch)){
        $Issue = [pscustomobject]@{
            Forest                = $Domain
            ObjectDistinguishedName     = ($DomainACLs.path -split '/')[-1]
            IdentityReference     = $ace.IdentityReference
            ActiveDirectoryRights = $ace.ActiveDirectoryRights
            Issue                 = "$($ace.IdentityReference) has DCSync ($($ace.ActiveDirectoryRights)) rights over $searchBase" #   need to add dcsync
            Technique             = '[CRITICAL] Low privileged principal with DCSync rights'
          }
          $Issue
        }
        #Check for specifically RBCD (write over specifically computer object) $computer = Get-ADComputer -Identity $object - if computer then RBCD
      }
    }
  }
}





  
 #Design tiering system first
  

  

  #Get ACLs over computer objects (RBCD) - loop over all computer accounts, check ACLs match dangerous rights and not member of privileged groups


  #Check for tiering violations (with ACLs over all user/group/OU objects)

  #Tier 1/2 over tier 0

  #Tier 2 over tier 1
function Find-ACLs {
    <#
  .SYNOPSIS
  Searches for machines where the

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

  #Use similar algorithm to ESC5
   #####################################
  # Dynamically find privileged users #
  #####################################
  
  #Unsafe privileges
  $DangerousRights = 'AllExtendedRights|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|GpLink|Write|Create|Delete'

  #Safe user rights
  $PrivilegedUsers = '-500$|-512$|-519$|-544$|-18$|-517$|-516$|-9$|-526$|-527$|S-1-5-10'

  # Define privileged groups - tier 0
  $privilegedgroups = @("Administrators", "Enterprise Admins", "Domain Admins", "Domain Controllers")

  # Initialize array to store members
  $PrivilegedGroupMembers = @()s
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



  ########################################################################################################
  # ACL checks #
  ##############

 #Writes over domain object
  
 #Design tiering system first
  
  #Also non-domain admin users with DCSync rights
  

  #Get ACLs over computer objects (RBCD) - loop over all computer accounts, check ACLs match dangerous rights and not member of privileged groups


  #Check for tiering violations (with ACLs over all user/group/OU objects)

  #Tier 1/2 over tier 0

  #Tier 2 over tier 1


  $DomainACLs = Get-Acl -Path "AD:DC=test,DC=local"

   
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
   if ((($ace.ActiveDirectoryRights -match $DangerousRights) -or ($ace.ObjectType -match '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')) -and ($SID -notmatch $PrivilegedUsers -and !$privilegedGroupMatch)){
      $Issue = [pscustomobject]@{
        Forest                = $Domain
        Name                  = $Object
        DistinguishedName     = $distinguishedname
        IdentityReference     = $ace.IdentityReference
        ActiveDirectoryRights = $ace.ActiveDirectoryRights
        Issue                 = "$($ace.IdentityReference) has $($ace.ActiveDirectoryRights) rights over $(object)" #   need to add dcsync
        Technique             = 'Vulnerable ACL'
      }
      $Issue
      }
    }
  }
  
  if ($ace.ObjectType -match '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'){
    $Issue.Issues += "`r`n[HIGH] The user has DCSync rights over the object"
    $Issue.Technique = 'Weak Password Policy'


}
function Find-ESC1 {
  <#
  .SYNOPSIS
  Searches ADCS for misconfigured certificate templates vulnerable to ESC1. The following certficiate template conditions must be met for ESC1:
  
  1. Certificate EKUs permit Client Authentication,
    - Client Authentication (1.3.6.1.5.5.7.3.2), 
    - PKINIT Client Authentication (1.3.6.1.5.2.3.4)
    - Smart Card Logon (1.3.6.1.4.1.311.20.2.2), 
    - Any Purpose (2.5.29.37.0)
  2. Allows the enrollee to supply an arbitrary Subject Alternative Name (SAN).
  3. Manager approval is disabled
  4. Allows low-privileged users enrollment rights (Domain Users/Computers) 
  
  This allows a low-privileged user to obtain an authentication certificate for any user (domain admin) and escalate their privileges.

  This function improves logic from https://github.com/TrimarcJake/Locksmith.

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-ESC1 -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Finding ESC1...' -ForegroundColor Yellow
  
  #Get all ADCS objects
  $ADCSobjects = Find-ADCSobjects -Domain $Domain

  #Define client authentication EKUs
  $ClientAuthenticationEKUs = '1.3.6.1.5.5.7.3.2|1.3.6.1.5.2.3.4|1.3.6.1.4.1.311.20.2.2|2.5.29.37.0'

  #Define high privileged SIDs to exclude with regex (administrator, domain admins, enteprise admins, SYSTEM, cert publishers, administrator, domain controllers, enterprise domain controllers, key admins, enterprise key admins, self)
  $PrivilegedUsers = '-500$|-512$|-519$|-544$|-18$|-517$|-516$|-9$|-526$|-527$|S-1-5-10'

  #Search for possible ESC1 templates
  # pKICertificateTemplate = certificate template objects
  # pkiExtendedKeyUsage = certificate tempate EKUs
  # msPKI-Certificate-Name-Flag = 1 (enrollee supplies an arbitrary SAN)
  # msPKI-Enrollment-Flag = 2 (manager approval required - certificates go into pending state)
  # msPKI-RA-Signature = 0 / null (manager approval is disabled)
  $ADCSobjects | Where-Object {
    ($_.objectClass -eq 'pKICertificateTemplate') -and
    ($_.pkiExtendedKeyUsage -match $ClientAuthenticationEKUs) -and
    ($_.'msPKI-Certificate-Name-Flag' -eq 1) -and
    !($_.'msPKI-Enrollment-Flag' -band 2) -and
    ( ($_.'msPKI-RA-Signature' -eq 0) -or ($_.'msPKI-RA-Signature' -eq $null) )
} | 
#Parse the security descriptor to find users who can enroll in the template
ForEach-Object {
    foreach ($entry in $_.nTSecurityDescriptor.Access) {
        $Principal = New-Object System.Security.Principal.NTAccount($entry.IdentityReference)
        #check if principal is in SID format 
        if ($Principal -match '^(S-1|O:)') {
            $SID = $Principal
        } 
        #if not, convert principal name to SID
        else {
            $SID = ($Principal.Translate([System.Security.Principal.SecurityIdentifier])).Value
        }

        # Parse to find SID if any low-privileged users can enroll in the template (ExtendedRight = Enroll and/or Autoenroll for a certificate)
        if ( ($SID -notmatch $PrivilegedUsers) -and ($entry.ActiveDirectoryRights -match 'ExtendedRight') ) {
            $adcsIssue = [pscustomobject]@{
                Domain                = $Domain
                Name                  = $_.Name
                DistinguishedName     = $_.DistinguishedName
                IdentityReference     = $entry.IdentityReference
                ActiveDirectoryRights = $entry.ActiveDirectoryRights
                Issue = "$($entry.IdentityReference) can enroll in this Client Authentication template using a SAN without Manager Approval"
                Technique = 'ESC1'
            }
            $adcsIssue
        }
      } 
    }
  }
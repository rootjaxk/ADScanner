function Find-ESC3 {
  <#
  .SYNOPSIS 
  Searches ADCS for misconfigured certificate templates vulnerable to ESC3. The following certficiate template conditions must be met for ESC3:
  
  -Certificate template defines Certificate Request Agent EKU (OID 1.3.6.1.4.1.311.20.2.1) allowing a principal to enroll a certificate on behalf of another user
  -Enrollment agent restrictions are not implemented on the CA.
  -Allows low-privileged users enrollment rights (Domain Users/Computers) - same as ESC1
  -Allows the enrollee to supply an arbitrary Subject Alternative Name (SAN) - same as ESC1
  -Manager approval is disabled - same as ESC1
  
  ESC3 is like ESC1 and ESC2 but with specific EKU

  This function improves logic from https://github.com/TrimarcJake/Locksmith.

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-ESC3 -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $true)]
    [String]
    $Domain
  )

  Write-Host '[*] Finding ESC3...' -ForegroundColor Yellow
  
  #Get all ADCS objects
  $ADCSobjects = Find-ADCSobjects -Domain $Domain

  #EKU on behalf of another ser
  $CertificateRequestAgentEKU = '1.3.6.1.4.1.311.20.2.1'
  
  #Define high privileged SIDs to exclude with regex (administrator, domain admins, enteprise admins, SYSTEM, cert publishers, administrator, domain controllers, enterprise domain controllers, key admins, enterprise key admins, self)
  $PrivilegedUsers = '-500$|-512$|-519$|-544$|-18$|-517$|-516$|-9$|-526$|-527$|S-1-5-10'

  ###############
  # Condition 1 #
  ###############

  #Search for possible ESC3 templates
  # pKICertificateTemplate = certificate template objects
  # pkiExtendedKeyUsage = enroll on behalf of another user
  # msPKI-Enrollment-Flag = 2 (manager approval required - certificates go into pending state)
  # msPKI-RA-Signature = 0 / null (manager approval is disabled)
  $ADCSobjects | Where-Object {
    ($_.objectClass -eq 'pKICertificateTemplate') -and
    ($_.pkiExtendedKeyUsage -match $CertificateRequestAgentEKU) -and
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
          Issue                 = "$($entry.IdentityReference) can enroll in this template on behalf of another user"
          Technique             = 'ESC3'
        }
        $adcsIssue
      }
    } 
  }
}
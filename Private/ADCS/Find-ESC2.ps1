function Find-ESC2 {
  <#
  .SYNOPSIS
  Searches ADCS for misconfigured certificate templates vulnerable to ESC2. The following certficiate template conditions must be met for ESC2:
  
  -Certificate template permit any purpose EKU (2.5.29.37.0) or no EKU (not present) 
  -Allows low-privileged users enrollment rights (Domain Users/Computers) - same as ESC1
  -Manager approval is disabled - same as ESC1
  
  ESC2 is similar to ESC1 with the specification of any purpose or lack of EKU, and can be exploited in conjunction with ESC3.

  This function improves logic from https://github.com/TrimarcJake/Locksmith.(flawed as it searches for msPKI-Certificate-Name-Flag = 1 (enrollee supplies an arbitrary SAN)

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-ESC2 -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $true)]
    [String]
    $Domain
  )

  Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Finding ESC2..." -ForegroundColor Yellow
  
  #Get all ADCS objects
  $ADCSobjects = Find-ADCSobjects -Domain $Domain
  $anyPurposeEKU = '2.5.29.37.0'
  
  #Define high privileged SIDs to exclude with regex (administrator, domain admins, enteprise admins, SYSTEM, cert publishers, administrator, domain controllers, enterprise domain controllers, key admins, enterprise key admins, self)
  $PrivilegedUsers = '-500$|-512$|-519$|-544$|-18$|-517$|-516$|-9$|-526$|-527$|S-1-5-10'

  #Search for possible ESC2 templates
  # pKICertificateTemplate = certificate template objects
  # pkiExtendedKeyUsage = any purpose EKU or no EKU
  # msPKI-Enrollment-Flag = 2 (manager approval required - certificates go into pending state)
  # msPKI-RA-Signature = 0 / null (manager approval is disabled)
  $ADCSobjects | Where-Object {
    ($_.objectClass -eq 'pKICertificateTemplate') -and
    (($_.pkiExtendedKeyUsage -match $anyPurposeEKU) -or (!$_.pkiExtendedKeyUsage)) -and
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
          Technique             = (to_red "[CRITICAL]") + " ESC2"
          Score                 = 50
          Name                  = $_.Name
          DistinguishedName     = $_.DistinguishedName
          IdentityReference     = $entry.IdentityReference
          ActiveDirectoryRights = $entry.ActiveDirectoryRights
          Issue                 = "$($entry.IdentityReference) can enroll in this template and use it for any purpose, e.g. request certificate template on behalf of another prinicpal (ESC3)"
        }
        $adcsIssue
      }
    } 
  }
}
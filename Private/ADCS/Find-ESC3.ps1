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

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-ESC3 -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Finding ESC3...' -ForegroundColor Yellow
  

}
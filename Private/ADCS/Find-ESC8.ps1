function Find-ESC8 {
    <#
  .SYNOPSIS
  Finds ESC8 (NTLM relay to ADCS HTTP endpoints). The web enrollment interface (http://<caserver>/certsrv) is vulnerable to NTLM relay attacks. 
  This can be exploited to issue arbitrary certificates, in the context of the coerced authentication.
  HTTPS must be enforced in combination with Extended Protection for Authentication on IIS to enforce channel binding to mitigate this vulnerability.
  
  Certificate Web Enrollment Web Service
  Certificate Enrollment Service (CES) 
  Network Device Enrollment Service (NDES) Web Service

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-ESC8 -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Finding ESC8...' -ForegroundColor Yellow
  
  # Find web endpoints
  $CAinfo = Find-ADCS -Domain $Domain

  #Find web enrollment interface 
  $CAendpoint = "$($CAinfo.dNSHostName)/certsrv/"
  $httpurl = "http://$CAendpoint"
  $httpsurl = "https://$CAendpoint"

  #test repsonse of cert endpoint
  $httpresponse = Invoke-WebRequest -Uri $httpurl -UseBasicParsing -TimeoutSec 5
  $httpsresponse = Invoke-WebRequest -Uri $httpsurl -UseBasicParsing -TimeoutSec 5

  if(($httpresponse.statuscode -eq 200) ){
    Write-Host "ESC8: $httpurl" -ForegroundColor Green
  }
  elseif(($httpsresponse.statuscode -eq 200) ) {
    Write-Host "HTTPS: $httpsurl" -ForegroundColor Yellow
    Write-Host "Checking EPA is enforced"
 
    # Create a web request to the endpoint
  $response = Invoke-WebRequest -Uri $httpsurl -UseBasicParsing -Method Head
  
  # Check if HTTPS & Extended Protection is enabled (full channel binding mitigation)
  if ($response.Headers['WWW-Authenticate'] -match 'NTLM') {
    Write-Output "Extended Protection for Authentication is enabled on $httpsurl."
  } else {
    Write-Output "Extended Protection for Authentication is not enabled on $httpsurl."
  }

  }
  else {
    Write-Host "ESC8: No web enrollment interface found" -ForegroundColor Green
  }


 # also else check if kerberos is disabled? - check if HTTPS & Kerberos works as a mitigation
 if ($response.Headers['WWW-Authenticate'] -match 'Negotiate' -and -not $response.Headers['WWW-Authenticate'] -match 'NTLM') {
    Write-Output "Only Kerberos authentication is permitted on $httpsurl."
} else {
    Write-Output "Kerberos authentication is not exclusively permitted on $httpsurl."
}
}

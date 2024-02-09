function Find-ESC8 {
  <#
  .SYNOPSIS
  Finds ESC8 (NTLM relay to ADCS HTTP endpoints). The web enrollment interface (http://<caserver>/certsrv) is vulnerable to 'NTLM relay' attacks. 
  This can be exploited to issue arbitrary certificates, in the context of the coerced authentication (through printerbug/dfscoerce/petitpotam).
  To migiate:
  -NTLM must be disabled in favour of Kerberos
  or
  -HTTPS must be enforced in combination with Extended Protection for Authentication on IIS to enforce channel binding to mitigate this vulnerability.
  
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
  
##################
# Find endpoints #
##################

  $CAinfo = Find-ADCS -Domain $Domain

  #Find web enrollment interface 
  $CAendpoint = "$($CAinfo.dNSHostName)/certsrv/"
  $httpurl = "http://$CAendpoint"
  $httpsurl = "https://$CAendpoint"

  #test repsonse of http cert endpoint  useing curl (not alias of iwr) to retrieve raw HTTP headers (www-authenticate) as invoke-webrequest doesnt support response of all headers
  Write-Host "Testing HTTP" -ForegroundColor Yellow
  $httpresponse = cmd /c "curl $httpurl -verbose --connect-timeout 3 2>&1" 

  if ($httpresponse -match "Timed Out"){
    $httpresponse = $null
  } else {
    #parse response code from response using regex - HTTP + digit + . + digit + space + 3 digits
    $httpResponseCode = ($httpresponse | Select-String -Pattern 'HTTP/\d\.\d\s+(\d{3})').Matches.Groups[1].Value
  }

  #test response of https cert endpoint
  Write-Host "Testing HTTPS" -ForegroundColor Yellow
  $httpsresponse = cmd /c "curl $httpsurl -k -verbose --connect-timeout 3 2>&1" 
  if ($httpsresponse -match "Timed Out"){
    $httpsresponse = $null
  } else {
    #parse response code from response using regex - HTTP + digit + . + digit + space + 3 digits
    $httpsResponseCode = ($httpsresponse | Select-String -Pattern 'HTTP/\d\.\d\s+(\d{3})').Matches.Groups[1].Value
  }

  #If no endpoints found
  if ($httpresponse -eq $null -and $httpsresponse -eq $null) {
    Write-Host "ESC8: No web enrollment interface found" -ForegroundColor Green
    return
  }

##################
#   ESC8 check   #
##################

  #Possible ESC8 on HTTP (200 or 401 indicate endpoint is reachable)
  if(($httpResponseCode -eq 200 -or $httpResponseCode -eq 401) ){
    $httpwwwAuthenticate = $httpresponse | Select-String -Pattern 'WWW-Authenticate: (.*)' | ForEach-Object { $_.Matches.Groups[1].Value }
    #Check first if kerberos is disabled on http
    if ($httpwwwAuthenticate -match 'NTLM') {
      Write-Host "ESC8: $httpurl" -ForegroundColor Red  #ESC8 confirmed
    }
    elseif ($httpwwwAuthenticate -match 'Negotiate' -and $httpwwwAuthenticate -notmatch 'NTLM'){
      Write-Host "Kerberos is enforced on HTTP" -ForegroundColor Green   #Successful Mitigation
    } 
  }
 
  #Possible ESC8 on HTTPS, check if mitigations are effective
  if(($httpsResponseCode -eq 200 -or $httpsResponseCode -eq 401) ) {
    Write-Host "HTTPS: $httpsurl" -ForegroundColor Yellow
    Write-Host "Checking EPA is enforced" -ForegroundColor Yellow
  
    #parse www-authenticate header from curl output
    $httpswwwAuthenticate = $httpsresponse | Select-String -Pattern 'WWW-Authenticate: (.*)' | ForEach-Object { $_.Matches.Groups[1].Value }

    # Check if HTTPS & Extended Protection is enabled (full channel binding mitigation)
    if ($httpswwwAuthenticate -match 'NTLM') {
      Write-Output "Extended Protection for Authentication is likely enabled on $httpsurl."  #Successful mitigation
    } elseif ($httpswwwAuthenticate -match 'Negotiate' -and $httpswwwAuthenticate -notmatch 'NTLM') {
        Write-Output "Only Kerberos authentication is permitted on $httpsurl."  #Successful mitigation
    } else {
        Write-Output "Neither EPA or Kerberos authentication are enforced on $httpsurl."
    }
}

}

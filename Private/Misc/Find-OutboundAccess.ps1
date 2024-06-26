function Find-OutboundAccess {
  <#
  .SYNOPSIS
  Searches Active Directory to see if a proxy web filterting solution is in effect to disallow users from accessing malicious / uneeded websites as a DLP control.

  Uses proxyaware method to test outbound access & checks if the user is an administrative user. If server has outbound access this is a high risk.

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-OutboundAccess -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $true)]
    [String]
    $Domain
  )

  Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Finding Outbound Access..." -ForegroundColor Yellow
  
  #Dynamically extract hostname that script is run on
  $hostname = (Get-ADComputer -Identity $env:COMPUTERNAME).dnshostname
  $userrun = whoami

  #see if host is a server
  $Isserver = (Get-WmiObject Win32_OperatingSystem -Property caption).caption

  #malicious sites like exploitDB should always be blocked
  $exploitDB = "https://www.exploit-db.com"

  #other sites not essential for server operation should also be blocked
  $socialURL = "https://www.facebook.com"
  $nonessentialbuisnessURL = "https://www.bbc.co.uk/"

  #test repsonses just using head to get HTTP response code
  Write-Host "Checking access to malicious sites..." -ForegroundColor Yellow
  $exploitresponse = cmd /c "curl $exploitDB --head --verbose --connect-timeout 3 2>&1" 
  Write-Host "Checking access to non-essential business sites..." -ForegroundColor Yellow
  $socialURLresponse = cmd /c "curl $socialURL --head --verbose --connect-timeout 3 2>&1"
  $nonessentialbuisnessURLresponse = cmd /c "curl $nonessentialbuisnessURL --head --verbose --connect-timeout 3 2>&1"
 
  #administrator check
  $admincheck = whoami /groups | findstr /i 'BUILTIN\Administrators'

  if ($admincheck -match 'Administrators') {
    $admin = $true
  }
  else {
    $admin = $false
  }

  #check if user is administrative user - outbound access is higher risk 
  if ($admin -eq $true -and ($exploitresponse -match "200 OK" -or $socialURLresponse -match "200 OK" -or $nonessentialbuisnessURLresponse -match "200 OK")) {
    $Issue = [pscustomobject]@{
      Risk      = (to_red "HIGH")
      Technique = "Unrestricted outbound access permitted"
      Score     = 35
      Name      = $hostname
      User      = $userrun
      Issue     = "Administrator account $userrun has internet access on $hostname. A tiering model should prevent admin accounts from having internet access in favour of a lower privileged account for everyday use."
    }
    $Issue
  }
  elseif ($exploitresponse -match "200 OK") {
    $Issue = [pscustomobject]@{
      Risk      = (to_red "HIGH")
      Technique = "Unrestricted outbound access permitted"
      Score     = 25
      Name      = $hostname
      User      = $userrun
      Issue     = "$userrun has unrestricted outbound internet access on $hostname permitting access to malicious sites or attacker controlled c2 infrastructure."
    }
    $Issue
  } 
  #if run on server this will be high
  elseif ($Isserver -match "server" -and ($socialURLresponse -match "200 OK" -or $nonessentialbuisnessURLresponse -match "200 OK")) {
    $Issue = [pscustomobject]@{
      Risk      = (to_red "HIGH")
      Technique = "Unrestricted outbound access permitted"
      Score     = 20
      Name      = $hostname
      User      = $userrun
      Issue     = "$userrun can access non-essential business sites on $hostname, which as a server internet access should be heavily restricted for all users."
    }
    $Issue
  }
}
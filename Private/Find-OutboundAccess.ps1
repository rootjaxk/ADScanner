function Find-OutboundAccess {
    <#
  .SYNOPSIS
  Searches Active Directory to see if a proxy web filterting solution is in effect to disallow users from accessing malicious / uneeded websites as a DLP control.

  Uses proxyaware method to test outbound access & checks if the user is an administrative user.

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-OutboundAccess -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Finding outbound access..' -ForegroundColor Yellow
  
  #Dynamically extract hostname that script is run on
  $hostname = (Get-ADComputer -Identity $env:COMPUTERNAME).dnshostname
  $userrun = whoami

  #malicious sites like exploitDB should always be blocked
  $exploitDB = "https://www.exploit-db.com"

  #other sites not essential for server operation should also be blocked
  $socialURL = "https://www.facebook.com"
  $nonessentialbuisnessURL = "https://www.bbc.co.uk/"

  #test repsonses just using head to get HTTP response code
  $exploitresponse = cmd /c "curl $exploitDB --head --verbose --connect-timeout 3 2>&1" 
  $socialURLresponse = cmd /c "curl $socialURL --head --verbose --connect-timeout 3 2>&1"
  $nonessentialbuisnessURLresponse = cmd /c "curl $nonessentialbuisnessURL --head --verbose --connect-timeout 3 2>&1"
 
  #administrator check
  $admincheck = whoami /groups | findstr /i 'BUILTIN\Administrators'

  if ($admincheck -match 'Administrators'){
    $admin = $true
  } else {
    $admin = $false
  }

  #check if user is administrative user - outbound access is higher risk 
  if ($admin -eq $true -and ($exploitresponse -match "200 OK" -or $socialURLresponse -match "200 OK" -or $nonessentialbuisnessURLresponse -match "200 OK")){
    $Issue = [pscustomobject]@{
        Forest                = $Domain
        Name                  = $hostname
        User                  = $userrun
        Issue                 = "Administrator account $userrun has internet access on $hostname. Block internet access for all administrative users"
        Technique             = (to_red "[CRITICAL]") + " Unrestricted outbound access"
      }
      $Issue
    }
  elseif ($exploitresponse -match "200 OK"){
    $Issue = [pscustomobject]@{
        Forest                = $Domain
        Name                  = $hostname
        User                  = $userrun
        Issue                 = "$userrun has unrestricted outbound internet access on $hostname"
        Technique             = (to_red "[HIGH]") + " Unrestricted outbound access"
      }
      $Issue
    } 
  #if run on server this will be high
  elseif ($socialURLresponse -match "200 OK" -or $nonessentialbuisnessURLresponse -match "200 OK"){
    $Issue = [pscustomobject]@{
        Forest                = $Domain
        Name                  = $hostname
        User                  = $userrun
        Issue                 = "$userrun can access non-essential buisness sites on $hostname. If this is a server, block internet access for all users"
        Technique             = (to_red "[HIGH]") + " Unrestricted outbound access"
      }
      $Issue
    }
  }
function Find-PwdNotRequired {
  <#
  .SYNOPSIS
  Searches LDAP to return accounts that do not require a password (may have a blank password) within Active Directory. 
  This can occur if the PASSWD_NOTREQD" is set to "True" in the "useraccountcontrol" attribute.

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-PwdNotRequired -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $true)]
    [String]
    $Domain
  )

  
  Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Finding accounts not requiring a password..." -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  #Search searchbase for user accounts with "PASSWD_NOTREQD" set to "True" in the "useraccountcontrol" attribute
  $PASSWDnotREQD = Get-ADUser -SearchBase $searchBase -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))' -properties *

  #define privileged groups to check for PASSWD_NOTREQD users
  $privilegedgroups = @("Administrators", "Enterprise Admins", "Domain Admins", "DnsAdmins", "Backup Operators",
    "Server Operators", "Account Operators", "Print Operators", "Remote Desktop Users", "Schema Admins", "Cert Publishers")
  
  #Initialise issues
  $PWDdisabled = [pscustomobject]@{
    Risk      = (to_green "[LOW]")
    Technique = "Disabled account does not require a password"
    Score     = 5  
    Users     = ""
    Enabled   = "$False"
    Issue     = ""
  }
  $PWDdisabledcount = 0

  $PWDprivileged = [pscustomobject]@{
    Risk      = (to_red "[CRITICAL]")
    Technique = "Highly privileged user does not require a password"
    Score     = 40
    Users     = ""
    MemberOf  = ""
    Enabled   = "$True"
    Issue     = ""
  }
  $PWDprivilegedcount = 0

  $PWDstandard = [pscustomobject]@{
    Risk      = (to_yellow "[MEDIUM]")
    Technique = "Standard user does not require a password"
    Score     = 15
    Users     = ""
    Enabled   = "$True"
    Issue     = ""
  }
  $PWDstandardcount = 0

  foreach ($user in $PASSWDnotREQD) {
    # Check if user is disabled first
    if ($user.Enabled -eq $false) {
      if ($PWDdisabled.Users -eq '') {
        $PWDdisabled.Users += $user.SamAccountName
      }
      else {
        $PWDdisabled.Users += "`r`n$($user.SamAccountName)"
      }
      $PWDdisabledcount++
    }
    # Then check if user is a member of a default privileged group
    else {
      $IsPrivileged = $false
      foreach ($group in $privilegedgroups) {
        if ($user.MemberOf -match $group) {
          $IsPrivileged = $true
          break
        }
      }
      if ($IsPrivileged) {
        if ($PWDprivileged.Users -eq '') {
          $PWDprivileged.Users += $user.SamAccountName
          $PWDprivileged.Memberof += $user.memberof
        }
        else {
          $PWDprivileged.Users += "`r`n$($user.SamAccountName)"
          $PWDprivileged.Memberof += "`r`n$($user.memberof)"
        }
        $PWDprivilegedcount++
      }
      #else standard user
      else {
        if ($PWDstandard.Users -eq '') {
          $PWDstandard.Users += $user.SamAccountName
        }
        else {
          $PWDstandard.Users += "`r`n$($user.SamAccountName)"
        }
        $PWDstandardcount++
      }
    }
  }
  #If issues, in order of severity
  if ($PWDprivileged.Users -ne "") {
    $PWDprivileged.Issue = "$PWDprivilegedcount users do not require a password and are a member of a privileged group"
    $PWDprivileged
  }
  if ($PWDstandard.Users -ne "") {
    $PWDstandard.Issue = "$PWDstandardcount users do not require a password and are not a member of a privileged group"
    $PWDstandard
  }
  if ($PWDdisabled.Users -ne "") {
    $PWDdisabled.Issue = "$PWDdisabledcount users do not require a password but are disabled"
    $PWDdisabled
  }
}
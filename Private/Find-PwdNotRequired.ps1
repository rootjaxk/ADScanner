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

  Write-Host '[*] Finding accounts not requiring a password...' -ForegroundColor Yellow
  
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
    Technique = (to_green "[LOW]") + " Disabled account not requiring a password"
    Users     = ""
    Enabled   = "$False"
    Issue     = "Users do not require a password but are disabled"
  }

  $PWDprivileged = [pscustomobject]@{
    Technique = (to_red "[HIGH]") + " Highly privileged user not requiring a password"
    Users     = ""
    MemberOf  = ""
    Enabled   = "$True"
    Issue     = "Users do not require a password and are a member of a privileged group"
  }

  $PWDstandard = [pscustomobject]@{
    Technique = (to_yellow "[MEDIUM]") + " Standard user not requiring a password"
    Users     = ""
    Enabled   = "$True"
    Issue     = "Users do not require a password but are not a member of a privileged group"
  }

  foreach ($user in $PASSWDnotREQD) {
    # Check if user is disabled first
    if ($user.Enabled -eq $false) {
      if ($PWDdisabled.Users -eq '') {
        $PWDdisabled.Users += $user.SamAccountName
      }
      else {
        $PWDdisabled.Users += "`r`n$($user.SamAccountName)"
      }
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
      }
      #else standard user
      else {
        if ($PWDstandard.Users -eq '') {
          $PWDstandard.Users += $user.SamAccountName
        }
        else {
          $PWDstandard.Users += "`r`n$($user.SamAccountName)"
        }
      }
    }
  }
  #If issues, in order of severity
  if ($PWDprivileged.Users -ne "") {
    $PWDprivileged
  }
  if ($PWDstandard.Users -ne "") {
    $PWDstandard
  }
  if ($PWDdisabled.Users -ne "") {
    $PWDdisabled
  }
}
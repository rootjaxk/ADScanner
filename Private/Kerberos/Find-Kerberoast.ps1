function Find-Kerberoast {
  <#
  .SYNOPSIS
  Searches LDAP returning service accounts containing Service Principal Names (SPNs) set within Active Directory. Will exclude krbtgt that has a SPN set by default. 
  Will combine finding with password policy length and privileged group membership to accurately assess the risk of the kerberoastable account.

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-Kerberoast -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $true)]
    [String]
    $Domain
  )

  Write-Host '[*] Finding Kerberoastable Accounts...' -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  #Search searchbase for user accounts with SPNs
  $kerberoastableusers = Get-ADUser -SearchBase $searchBase -LDAPFilter '(&(objectCategory=user)(servicePrincipalName=*)(!(SamAccountName=krbtgt)))' -properties *

  #define privileged groups to check for kerberoastable users
  $privilegedgroups = @("Administrators", "Enterprise Admins", "Domain Admins", "DnsAdmins", "Backup Operators",
    "Server Operators", "Account Operators", "Print Operators", "Remote Desktop Users", "Schema Admins", "Cert Publishers")
  
  #get password policy length
  $PwdPolicyLength = (Get-ADDefaultDomainPasswordPolicy -Identity $Domain).MinPasswordlength

  #define weak service account password
  if ($PwdPolicyLength -lt 24) {
    $WeakPwdPolicy = $true
  }

  #Initalise issues
  $KerberoastDisabled = [pscustomobject]@{
    Technique = (to_green "[LOW]") + " Disabled kerberoastable account"
    Score     = 10
    Users     = ""
    SPN       = ""
    Enabled   = "False"
    Issue     = ""
  }
  $KerberoastDisabledcount = 0

  $Kerberoastprivileged_weakpwd = [pscustomobject]@{
    Technique = (to_red "[CRITICAL]") + " Highly privileged kerberoastable user with a weak password"
    Score     = 50
    Users     = ""
    SPN       = ""
    Memberof  = ""
    Enabled   = "True"
    Issue     = ""
  }
  $Kerberoastprivileged_weakpwdcount = 0

  $Kerberoastprivileged_strongpwd = [pscustomobject]@{
    Technique = (to_red "[HIGH]") + " Highly privileged kerberoastable user with strong password"
    Score     = 40
    Users     = ""
    SPN       = ""
    Memberof  = ""
    Enabled   = "True"
    Issue     = ""
  }
  $Kerberoastprivileged_strongpwdcount = 0

  $Kerberoastlowprivileged_weakpwd = [pscustomobject]@{
    Technique = (to_red "[HIGH]") + " Low privileged kerberoastable user with a weak password"
    Score     = 25
    Users     = ""
    SPN       = ""
    Enabled   = "True"
    Issue     = ""
  }
  $Kerberoastlowprivileged_weakpwdcount = 0

  $Kerberoastlowprivileged_strongpwd = [pscustomobject]@{
    Technique = (to_green "[LOW]") + " Low privileged kerberoasable user, but strong password set"
    Score     = 12
    Users     = ""
    SPN       = ""
    Enabled   = "True"
    Issue     = ""
  }
  $Kerberoastlowprivileged_strongpwdcount = 0

  foreach ($kerberoastableuser in $kerberoastableusers) {
    # Check if user is disabled first
    if ($kerberoastableuser.Enabled -eq $false) {
      if ($KerberoastDisabled.Users -eq '') {
        $KerberoastDisabled.Users += $kerberoastableuser.SamAccountName
        $KerberoastDisabled.SPN += $kerberoastableuser.servicePrincipalName
      }
      else {
        $KerberoastDisabled.Users += "`r`n$($kerberoastableuser.SamAccountName)"
        $KerberoastDisabled.SPN += "`r`n$($kerberoastableuser.servicePrincipalName)"
      }
      $KerberoastDisabledcount++
    }
    # Then check if user is a member of a default privileged group
    else {
      $IsPrivileged = $false
      foreach ($group in $privilegedgroups) {
        if ($kerberoastableuser.MemberOf -match $group) {
          $IsPrivileged = $true
          break
        }
      }
      #if privileged & weak password
      if ($IsPrivileged -and $WeakPwdPolicy) {
        if ($Kerberoastprivileged_weakpwd.Users -eq '') {
          $Kerberoastprivileged_weakpwd.Users += $kerberoastableuser.SamAccountName
          $Kerberoastprivileged_weakpwd.SPN += $kerberoastableuser.servicePrincipalName
          $Kerberoastprivileged_weakpwd.MemberOf += $kerberoastableuser.memberof
        }
        else {
          $Kerberoastprivileged_weakpwd.Users += "`r`n$($kerberoastableuser.SamAccountName)"
          $Kerberoastprivileged_weakpwd.SPN += "`r`n$($kerberoastableuser.servicePrincipalName)"
          $Kerberoastprivileged_weakpwd.MemberOf += "`r`n$($kerberoastableuser.memberof)"
        }
        $Kerberoastprivileged_weakpwdcount++
      }
      #privileged but strong pasword
      elseif ($Isprivileged -and !$WeakPwdPolicy) {
        if ($Kerberoastprivileged_strongpwd.Users -eq '') {
          $Kerberoastprivileged_strongpwd.Users += $kerberoastableuser.SamAccountName
          $Kerberoastprivileged_strongpwd.SPN += $kerberoastableuser.servicePrincipalName
          $Kerberoastprivileged_strongpwd.MemberOf += $kerberoastableuser.memberof
        }
        else {
          $Kerberoastprivileged_strongpwd.Users += "`r`n$($kerberoastableuser.SamAccountName)"
          $Kerberoastprivileged_strongpwd.SPN += "`r`n$($kerberoastableuser.servicePrincipalName)"
          $Kerberoastprivileged_strongpwd.MemberOf += "`r`n$($kerberoastableuser.memberof)"
        }
        $Kerberoastprivileged_strongpwdcount++
      }
      #not privileged & weak password
      elseif ($WeakPwdPolicy) {
        if ($Kerberoastlowprivileged_weakpwd.Users -eq '') {
          $Kerberoastlowprivileged_weakpwd.Users += $kerberoastableuser.SamAccountName
          $Kerberoastlowprivileged_weakpwd.SPN += $kerberoastableuser.servicePrincipalName
        }
        else {
          $Kerberoastlowprivileged_weakpwd.Users += "`r`n$($kerberoastableuser.SamAccountName)"
          $Kerberoastlowprivileged_weakpwd.SPN += "`r`n$($kerberoastableuser.servicePrincipalName)"
        }
        $Kerberoastlowprivileged_weakpwdcount++
      }
      #low privileged, with strong password
      else { 
        if ($Kerberoastlowprivileged_strongpwd.Users -eq '') {
          $Kerberoastlowprivileged_strongpwd.Users += $kerberoastableuser.SamAccountName
          $Kerberoastlowprivileged_strongpwd.SPN += $kerberoastableuser.servicePrincipalName
        }
        else {
          $Kerberoastlowprivileged_strongpwd.Users += "`r`n$($kerberoastableuser.SamAccountName)"
          $Kerberoastlowprivileged_strongpwd.SPN += "`r`n$($kerberoastableuser.servicePrincipalName)"
        }
        $Kerberoastlowprivileged_strongpwdcount++
      }
    }
  }

  #output if users are present in any of the issues in order of severity
  if ($Kerberoastprivileged_weakpwd.Users) {
    $Kerberoastprivileged_weakpwd.Issue = "$Kerberoastprivileged_weakpwdcount users have an SPN set with a weak password and is a member of a privileged group."
    $Kerberoastprivileged_weakpwd
  }
  if ($Kerberoastprivileged_strongpwd.Users) {
    $Kerberoastprivileged_strongpwd.Issue = "$Kerberoastprivileged_strongpwdcount users have an SPN set and is a member of a privileged group but has a strong password set. A threat actor with unlimited computation power can compromise this account and thus the full domain"
    $Kerberoastprivileged_strongpwd
  }
  if ($Kerberoastlowprivileged_weakpwd.Users) {
    $Kerberoastlowprivileged_weakpwd.Issue = "$Kerberoastlowprivileged_weakpwdcount users have an SPN and a weak password set. This service wont facilitate direct domain privilege escalation but allows full compromise of the service"
    $Kerberoastlowprivileged_weakpwd
  }
  if ($Kerberoastlowprivileged_strongpwd.Users) {
    $Kerberoastlowprivileged_strongpwd.Issue = "$Kerberoastlowprivileged_strongpwdcount users have an SPN set but are not a member of a privileged group and has a strong password set. A threat actor with unlimited computation power can compromise this service"
    $Kerberoastlowprivileged_strongpwd
  }
  if ($KerberoastDisabled.Users) {
    $KerberoastDisabled.Issue = "$KerberoastDisabledcount users have an SPN set but are disabled"
    $KerberoastDisabled
  }
}
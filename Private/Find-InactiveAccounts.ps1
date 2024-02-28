function Find-InactiveAccounts {
    <#
    .SYNOPSIS
    Searches Active Directory for accounts that have not logged in for a specified number of days (or ever).
    Will also find inactive priviliged accounts - this will aid in quickly reducing the number of accounts from high privileged groups by highlighting those that are not used.
  
    .PARAMETER Domain
    The domain to run against, in case of a multi-domain environment
  
    .EXAMPLE 
    Find-InactiveAccounts -Domain test.local
    #>  
  
    #Add mandatory domain parameter
    [CmdletBinding()]
    Param(
      [Parameter(Mandatory = $true)]
      [String]
      $Domain
    )
  
    Write-Host '[*] Finding Inactive Accounts...' -ForegroundColor Yellow
  
    #Dynamically produce searchbase from domain parameter
    $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
    $searchBase = $SearchBaseComponents -join ','
    
    # Set the number of days since last logon
    $DaysInactive = 90
    $InactiveDate = (Get-Date).Adddays( - ($DaysInactive))
  
    # Find stale users that are not disabled (will also find never logged on users)
    $staleusers = Search-ADAccount -searchBase $searchBase -AccountInactive -DateTime $InactiveDate -UsersOnly | Select-Object SamAccountName, Enabled, LastLogonDate
  
    #get objects that are not disabled
    $stale_not_disabled = $staleusers | Where-Object { $_.Enabled -eq $true }
  
    # Find total number of users that are stale
    $totalstale = $stale_not_disabled.count
  
    # Get number of stale users (not in privileged groups - just number)
    if ($stale_not_disabled) {
      $Issue = [pscustomobject]@{
        Domain        = $Domain
        Totalinactive = $totalstale
        StaleUsers    = $stale_not_disabled.samaccountname
        Issue         = "The are $totalstale inactive accounts found in $domain. A JML process should be enforced that disables accounts not used after a period of inactivity to prevent unauthorised use and conform to principle of least privilege "
        Technique     = (to_yellow "[MEDIUM]") + " Inactive/stale accounts are not disabled"
      }
      $Issue
    }
  
    #check if member of privileged group
    $privilegedgroups = @("Administrators", "Enterprise Admins", "Domain Admins", "DnsAdmins", "Backup Operators",
      "Server Operators", "Account Operators", "Print Operators", "Remote Desktop Users", "Schema Admins", "Cert Publishers")
    
    $stale_and_privileged = @()
  
    #get what groups users are in
    foreach ($user in $stale_not_disabled.samaccountname) {
      $stale_and_privileged += Get-ADUser -Identity $user -properties memberof
    }
  
    #loop through for any stale user in privileged groups
    foreach ($stale in $stale_and_privileged) {
      $IsPrivileged = $false
      foreach ($group in $privilegedgroups) {
        if ($stale.MemberOf -match $group) {
          $IsPrivileged = $true
          break
        }
      }
      if ($IsPrivileged) {
        $Issue = [pscustomobject]@{
          Domain           = $Domain
          User             = $stale.SamAccountName
          Enabled          = $stale.Enabled
          MemberOf         = $stale.memberof
          Inactivityperiod = "90 days"
          Issue            = "$($stale.samaccountname) has not logged in 90 days and is a member of privileged groups.  A JML process should be enforced that disables accounts not used after a period of inactivity to prevent unauthorised use and conform to principle of least privilege"
          Technique        = (to_red "[HIGH]") + " Inactive/stale accounts are not disabled in privileged groups"
        }
        $Issue
      }
    }
  }
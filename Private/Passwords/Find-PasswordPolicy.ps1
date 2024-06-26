function Find-PasswordPolicy {
  <#
  .SYNOPSIS
  Searches the Active Directory domain searching for the password policy configuration, then highlights any weaknesses based on best practice.

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-PasswordPolicy -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $true)]
    [String]
    $Domain
  )

  Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Finding Password Policy..." -ForegroundColor Yellow

  $PwdPolicy = Get-ADDefaultDomainPasswordPolicy -Identity $Domain

  #Dynamically build pwd policy issue
  if ($PwdPolicy.ComplexityEnabled -ne $true) {
    $Complexity = $false
  } else {
    $Complexity = $true
  }
  if ($PwdPolicy.MinPasswordLength -lt 12) {
    $LengthIssue = $true
  }
  if ($PwdPolicy.LockoutThreshold -gt 10) {
    $LockoutIssue = $true
  }
  #guidance is 1 day
  if ($PwdPolicy.MinPasswordAge.Days -lt 1) {
    $MinPwdAgeIssue = $true
  }
  #guidance is yearly or should not expire
  if (($PwdPolicy.MaxPasswordAge.Days -lt 365 -and $PwdPolicy.MaxPasswordAge.Days -ne 0)) {
    $MaxPwdAgeIssue = $true
  }
  #guidance is 24
  if ($PwdPolicy.PasswordHistoryCount -lt 24) {
    $PasswordHistoryIssue = $true
  }
  if ($PwdPolicy.LockoutDuration -lt 15) {
    $LockoutDurationIssue = $true
  }
  if ($PwdPolicy.ReversibleEncryptionEnabled -eq $true) {
    $ReverseEncryption = $true
  }
  else {
    $ReverseEncryption = $false
  }

  #Array for issues
  $PWDIssues = @()
  $Policy = @("[*] $Domain password policy:")

  # Initialize the Issue PSCustomObject
  $Policy += [pscustomobject]@{ 
    ComplexityEnabled    = $Complexity
    MinPasswordLength    = $PwdPolicy.MinPasswordLength
    LockoutThreshold     = $PwdPolicy.LockoutThreshold
    MinPasswordAge       = $PwdPolicy.MinPasswordAge.Days
    MaxPasswordAge       = $PwdPolicy.MaxPasswordAge.Days
    PasswordHistoryCount = $PwdPolicy.PasswordHistoryCount
    LockoutDuration      = $PwdPolicy.LockoutDuration
    ReverseEncryption    = $PwdPolicy.ReversibleEncryptionEnabled
  }
 
  if ($Complexity -eq $false) {
    $PWDIssues += [pscustomobject]@{
      Risk              = (to_red "HIGH")
      Technique         = "Password complexity requirement is not enabled"
      Score             = 20
      ComplexityEnabled = $Complexity
      Issue             = "The password complexity requirement not being enforced allows passwords without a capital letter, number, special character or can contain the user's username."
    }
  }
  if ($LengthIssue -eq $true) {
    $PWDIssues += [pscustomobject]@{
      Risk      = (to_red "HIGH")
      Technique = "Password length requirement is less than 12 characters"
      Score     = 25
      Length    = $PwdPolicy.MinPasswordLength
      Issue     = "Passwords with lengths less than 14 characters can easily be bruteforced, and if hash is obtained, easily cracked. NCSC recommends 12 characters as a minimum length for a password."
    }
  }
  if ($LockoutIssue -eq $true) {
    $PWDIssues += [pscustomobject]@{
      Risk             = (to_red "HIGH")
      Technique        = "Account lockout threshold is greater than 10"
      Score            = 20
      LockoutThreshold = $PwdPolicy.LockoutThreshold
      Issue            = "If the account lockout threshold is too large or not set, attackers get a large number of attempts to guess or brute force a users password. This makes it much easier for accounts to be compromised."
    }
  }
  if ($MinPwdAgeIssue -eq $true) {
    $PWDIssues += [pscustomobject]@{
      Risk           = (to_green "LOW")
      Technique      = "The minimum password age is less than 1 day"#otherwise user can rotate back to previous password - https://www.tenable.com/audits/items/CIS_MS_Windows_Server_2008_R2_MS_Level_1_v3.3.0.audit:f6acf617d6b6a9efd90267aba213653b 
      Score          = 9
      MinPasswordAge = $PwdPolicy.MinPasswordAge.Days
      Issue          = "If minimum password age is not set, if a user is forced to change their password, they can cycle through the passwordhistory and change it straight away to a previously used password (password reuse). The recommended minimum password age is 1 day."
    }
  }
  if ($MaxPwdAgeIssue -eq $true) {
    $PWDIssues += [pscustomobject]@{
      Risk           = (to_red "HIGH")
      Technique      = "The maximum password age is less than 365 days" 
      Score          = 20
      MaxPasswordAge = $PwdPolicy.MaxPasswordAge.Days
      Issue          = "NCSC guidance recommends passwords should not expire, in favour of one long complex password that is only changed if thought to be compromised. If users change their passwords to regularly they are more likely to use weaker passwords. If you must enforce a maximum password age, the recommended maximum password age is 365 days."
    }
  }
  if ($PasswordHistoryIssue -eq $true) {
    $PWDIssues += [pscustomobject]@{
      Risk                 = (to_green "LOW")
      Technique            = "The password history count is less than 24" 
      Score                = 9
      PasswordHistoryCount = $PwdPolicy.PasswordHistoryCount
      Issue                = "Enforce password history setting prevents the easy reuse of old passwords, preventing users from changing their password to any of their last $($PwdPolicy.PasswordHistoryCount) passwords. This prevents password reuse."
    }
  }
  if ($LockoutDurationIssue -eq $true) {
    $PWDIssues += [pscustomobject]@{
      Risk            = (to_yellow "MEDIUM")
      Technique       = "The account lockout duration is less than 15 minutes" 
      Score           = 10
      LockoutDuration = $PwdPolicy.LockoutDuration
      Issue           = "After too many failed login attempts defined in the lockout threshold, the account will be locked out for a period of time. If the lockout threshold is too short, this can be taken advantage of to brute force the account after the lockout period has expired."
    }
  }
  if ($ReverseEncryption -eq $True) {
    $PWDIssues += [pscustomobject]@{
      Risk              = (to_red "HIGH")
      Technique         = "Reversible encryption is enabled"  # encrypted passwords stored can be decrypted
      Score             = 20
      ReverseEncryption = $PwdPolicy.ReversibleEncryptionEnabled
      Issue             = "Passwords stored with reversible encryption is the same as storing them in plaintext, meaning an attacker extract them from memory in plaintext."
    }
  }
  #Output findings
  #$Policy - might be useful for web report later
  $PwdIssues
}
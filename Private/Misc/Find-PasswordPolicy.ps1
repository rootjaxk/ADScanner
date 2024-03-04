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
      [Parameter(Mandatory=$true)]
      [String]
      $Domain
  )

  Write-Host '[*] Finding Password Policy...' -ForegroundColor Yellow

  $PwdPolicy = Get-ADDefaultDomainPasswordPolicy -Identity $Domain

  #Dynamically build pwd policy issue
  if ($PwdPolicy.ComplexityEnabled -ne $true){
    $Complexity = "False"
  } else {
    $Complexity = "True"
  }
  if ($PwdPolicy.MinPasswordLength -lt 14){
    $LengthIssue = $true
  }
  if ($PwdPolicy.LockoutThreshold -gt 10){
    $LockoutIssue = $true
  }
  #guidance is 1 day
  if ($PwdPolicy.MinPasswordAge.Days -lt 1){
    $MinPwdAgeIssue = $true
  }
  #guidance is yearly or should not expire
  if (($PwdPolicy.MaxPasswordAge.Days -lt 365) -or ($PwdPolicy.MaxPasswordAge.Days -ne 0)){
    $MaxPwdAgeIssue = $true
  }
  #guidance is 24
  if ($PwdPolicy.PasswordHistoryCount -lt 24){
    $PasswordHistoryIssue = $true
  }
  if ($PwdPolicy.LockoutDuration -lt 15){
   $LockoutDurationIssue = $true
  }
  if ($PwdPolicy.ReversibleEncryptionEnabled -eq $true){
    $ReverseEncryption = "Yes"
  } else {
    $ReverseEncryption = "No"
  }

  # Initialize the Issue PSCustomObject
  $Issue = [pscustomobject]@{
    Technique = ""
    Name = "$Domain Password Policy"
    Score = ""
    ComplexityEnabled = $Complexity
    MinPasswordLength = $PwdPolicy.MinPasswordLength
    LockoutThreshold = $PwdPolicy.LockoutThreshold
    MinPasswordAge = $PwdPolicy.MinPasswordAge.Days
    MaxPasswordAge = $PwdPolicy.MaxPasswordAge.Days
    PasswordHistoryCount = $PwdPolicy.PasswordHistoryCount
    LockoutDuration = $PwdPolicy.LockoutDuration
    ReverseEncryption = $PwdPolicy.ReversibleEncryptionEnabled
    Issues = ""
  }
 
  # Update PSCustomObject with any issues
  if ($Complexity -eq "False" -or $LengthIssue -eq $true -or $LockoutIssue -eq $true -or $MinPwdAgeIssue -eq $true -or $MaxPwdAgeIssue -eq $true -or $PasswordHistoryIssue -eq $true -or $LockoutDurationIssue -eq $true -or $ReverseEncryption -eq "True"){
    $Issue.Issues = "The following issues were found with the password policy:"
    
    if ($Complexity -eq "False"){
        $Issue.Issues += "`r`n" + (to_red "[HIGH]") + " The password complexity requirement is not enabled."
        $Issue.Score = 20
    }
    if ($LengthIssue -eq $true){
        $Issue.Issues += "`r`n" + (to_red "[HIGH]") + " The minimum password length requirement is less than 14 characters."
        $Issue.Score = 25
    }
    if ($LockoutIssue -eq $true){
        $Issue.Issues += "`r`n" + (to_red "[HIGH]") + " The account lockout threshold is greater than 10."
        $Issue.Score = 20
    }
    if ($MinPwdAgeIssue -eq $true){
        $Issue.Issues += "`r`n" + (to_yellow "[MEDIUM]") + " The minimum password age is less than 1 day." #otherwise user can rotate back to previous password - https://www.tenable.com/audits/items/CIS_MS_Windows_Server_2008_R2_MS_Level_1_v3.3.0.audit:f6acf617d6b6a9efd90267aba213653b 
        $Issue.Score = 10
    }
    if ($MaxPwdAgeIssue -eq $true){
        $Issue.Issues += "`r`n" + (to_red "[HIGH]") + " The maximum password age is less than 365 days." #guidance is should not expire
        $Issue.Score = 20
    }
    if ($PasswordHistoryIssue -eq $true){
        $Issue.Issues += "`r`n" + (to_yellow "[MEDIUM]") + " The password history count is less than 24."
        $Issue.Score = 10
    }
    if ($LockoutDurationIssue -eq $true){
        $Issue.Issues += "`r`n" + (to_yellow "[MEDIUM]") + " The account lockout duration is less than 15 minutes."
        $Issue.Score = 10
    }
    if ($ReverseEncryption -eq "True"){
        $Issue.Issues += "`r`n" + (to_red "[HIGH]") + " Reversible encryption is enabled." # encrypted passwords stored can be decrypted
        $Issue.Score = 20
    }
    if ($Issue.Issues -match "[HIGH]"){
      $Issue.Technique = (to_red "[HIGH]") + " Weak Password Policy"
    } else {
      $Issue.Technique = (to_yellow "[MEDIUM]") + " Weak Password Policy"}
  }
  $Issue
}
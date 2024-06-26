function Find-UserDescriptions {
  <#
  .SYNOPSIS
  Searches LDAP returning accounts containing user / computer descriptions. Generative AI will then determine if descriptions may contain sensitive information 

  This requires the temperature of GPT to be 0.1 to avoid returnign any excess information 

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-UserDescription -Domain test.local

  PS C:\Users\jack> Connect-ChatGPT -APIkey $apikey -Prompt $prompt
  Password i=s 72783*&
  m&skd03(*#o
  Just so I dont forget my password is 9q!3xTeHkgETd&xMm9np8F6mu
  Just so I dont forget my password is z&M!Z6Pf7L!YQRva8GyLHmiXM
  Just so I dont forget my password is 7KEqG4N9GyuNHENyH&b&8f5C2
  Just so I dont forget my password is JmrYyu9K#iB%WeNZ%PwykH

  #>
 
  #Add mandatory domain parameter & APIkey
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $true)]
    [String]
    $APIkey,

    [Parameter(Mandatory = $true)]
    [String]
    $Domain
  )

  
  Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Finding Sensitive User Descriptions..." -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  #Search searchbase for descriptions from user / computer accounts 
  $userswithdescription = Get-ADObject -SearchBase $searchBase -LDAPFilter '(&(|(objectClass=user)(objectClass=computer))(description=*))' -properties *
  $descriptions = $userswithdescription.description

  #Define how want AI to respond cleanly & send to Generate AI
  $AiSystemMessage = "You are a cyber security assistant. I will provide you with some information I want you to respond with the interesting data I determine in a clean and concise way. I want no other information returned."
  $prompt = "which of these descriptions contain password information which should not be readable by all users? I want all information that looks like it would contain a password `r`n" + ($descriptions -join "`r`n") + " If no passwords are found return only 'No passwords found'" #chatgpt stuff

  #Send all descriptions to API
  $userdescriptionresponse = Connect-ChatGPT -APIkey $APIkey -Prompt $prompt -Temperature 0.1 -AiSystemMessage $AiSystemMessage

  #define privileged groups
  $privilegedgroups = @("Administrators", "Enterprise Admins", "Domain Admins", "DnsAdmins", "Backup Operators",
    "Server Operators", "Account Operators", "Print Operators", "Remote Desktop Users", "Schema Admins", "Cert Publishers")


  #Initialise issues
  $Highprivpassworddesc = [pscustomobject]@{
    Risk        = (to_red "CRITICAL")
    Technique   = "Plaintext credentials found in a privileged user's Active Directory description"
    Score       = 50
    User        = ""
    MemberOf    = ""
    Description = ""
    Issue       = "Privileged users have passwords in their Active Directory description field. These attributes are readable by any authenticated user so these priviliged account should be assumed compromised"
  }

  $Lowprivpassworddesc = [pscustomobject]@{
    Risk        = (to_red "HIGH")
    Technique   = "Plaintext credentials found in a standard user's Active Directory description"
    Score       = 30
    User        = ""
    Description = ""
    Issue       = "Standard users have passwords in their Active Directory description field. These attributes are readable by any authenticated user so these accounts should be assumed compromised"
  }

  #see if GPT found passwords
  if ($userdescriptionresponse -notmatch 'No passwords found') {
    #split all possible passwords and match description back to user
    foreach ($pwd in $userdescriptionresponse.split("`n")) {
      $user = Get-ADObject -Filter { description -eq $pwd } -properties *
      
      #if password in privileged user description
      $IsPrivileged = $false
      foreach ($group in $privilegedgroups) {
        if ($user.MemberOf -match $group) {
          $IsPrivileged = $true
          break
        }
      }
      if ($IsPrivileged) {
        if ($Highprivpassworddesc.User -eq '') {
          $Highprivpassworddesc.User += $user.SamAccountName
          $Highprivpassworddesc.MemberOf += $user.memberof
          $Highprivpassworddesc.Description += $user.description
        }
        else {
          $Highprivpassworddesc.User += "`r`n$($user.SamAccountName)"
          $Highprivpassworddesc.MemberOf += "`r`n$($user.memberof)"
          $Highprivpassworddesc.Description += "`r`n$($user.description)"
        }
      }
      #else standard user
      else {
        if ($Lowprivpassworddesc.User -eq '') {
          $Lowprivpassworddesc.User += $user.SamAccountName
          $Lowprivpassworddesc.Description += $user.description
        }
        else {
          $Lowprivpassworddesc.User += "`r`n$($user.SamAccountName)"
          $Lowprivpassworddesc.Description += "`r`n$($user.description)"
        }
      }
    }
  }
  if($Highprivpassworddesc.User) {
    $Highprivpassworddesc
  }
  if($Lowprivpassworddesc.User) {
    $Lowprivpassworddesc
  }
}

  #test how accurately GPT finds sensitive information in descriptions
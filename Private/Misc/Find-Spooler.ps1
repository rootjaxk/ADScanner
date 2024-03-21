function Find-Spooler {
  <#
  .SYNOPSIS
  Searches for servers within AD that have the print spooler service enabled. The print spooler service on servers exposes the named pipe - \\<netbiosname>\pipe\spoolss

  .PARAMETER Domain
  The domain to run against, in case of a multi-domain environment

  .EXAMPLE 
  Find-Spooler -Domain test.local

  #>
 
  #Add mandatory domain parameter
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $true)]
    [String]
    $Domain
  )
  
  Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Finding Spooler..." -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  #Get computers that have dns record (active), removing nulls
  $Computers = (Get-ADComputer -SearchBase $searchBase -filter *).dnshostname
  $Computers = $Computers | ? { $_ }

  #Initliase object
  $SpoolerIssue = [pscustomobject]@{
    Risk           = (to_red "HIGH")
    Technique      = "Spooler service is enabled (authentication coercion) "
    Score          = 30 
    Computers      = ""
    SpoolerEnabled = "$true"
    Issue          = ""
  }
  $Spoolercount = 0
  
  $timeout = 1
  #Check active computers
  foreach ($computer in $Computers) {
    $ping = New-Object System.Net.NetworkInformation.Ping
    $reply = $ping.Send($computer, $Timeout * 1000)
  
    #If host is active, search for named pipes
    if ($reply.Status -eq 'Success') {
      try {
        Write-Host "Checking \\$computer\pipe\spoolss" -ForegroundColor Yellow
        $spooler = Get-ChildItem "\\$computer\pipe\spoolss" -ErrorAction Ignore

        # If the spooler exists, add a custom object with hostname and spooler status to results
        if ($spooler) {
          if ($SpoolerIssue.Computers -eq '') {
            $SpoolerIssue.Computers += $computer
          }
          else {
            $SpoolerIssue.Computers += "`r`n$computer"
          }
          $Spoolercount++
        }
      }
      catch {
        Write-Error $_
      }
    }
  }
  if ($SpoolerIssue.Computers -ne '') {
    $SpoolerIssue.Issue = "The spooler service is enabled on $Spoolercount computers which are vulnerable to printerbug (authentication coercion)."
    $SpoolerIssue
  }
}
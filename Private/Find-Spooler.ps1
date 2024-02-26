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

  Write-Host '[*] Finding spooler..' -ForegroundColor Yellow
  
  #Dynamically produce searchbase from domain parameter
  $SearchBaseComponents = $Domain.Split('.') | ForEach-Object { "DC=$_" }
  $searchBase = $SearchBaseComponents -join ','

  #Get computers that have dns record - active
  $Computers = (Get-ADComputer -SearchBase $searchBase -filter *).dnshostname

  #Array to store multiple server having spooler enabled
  $results = @()

  #Check each for presence of the spooler named pipe
  foreach ($computer in $Computers) {
    try {
      $spooler = Get-ChildItem "\\$computer\pipe\spoolss" -ErrorAction Ignore

      # If the spooler exists, add a custom object with hostname and spooler status to results
      if ($spooler) {
        $results += [pscustomobject]@{
          Domain         = $Domain
          Computer       = $computer
          SpoolerEnabled = $true
          Issue          = "Spooler service is enabled"
          Technique      = (to_red "[HIGH]") + " Spooler service is vulnerale to printerbug (authentication coercion)"
        }
      }
    }
    catch {
      Write-Error $_
    }
  }
  $results
}
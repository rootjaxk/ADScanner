function Invoke-ADScanner {
    <#
    .SYNOPSIS
    Scans Active Directory for common vulnerabilities and produces an intelligent report to support remediation of vulnerabilities.

    .DESCRIPTION
    Invoke-ADScanner primarily uses the Active Directory (AD) Powershell (PS) module to identify common and highly dangerous misconfigurations
    found in Enterprise Active Directory environments.

    .COMPONENT
    Invoke-ADScanner requires the AD & ADCS modules to be installed in the scope of the Current User. This will require the Remote System Administration
    Toolkit (RSAT) installed on the device. 
    If Locksmith does not identify RSAT installed, it will attempt to install the relevant modules, else will fail.

    .PARAMETER Scans
    Specify which scans you want to run. Available scans: 'All' or ADCS or Kerberos, or , or 'PromptMe'

    -Scans All
    Run all scans (default)

    -Scans PromptMe
    Presents a grid view of the available scan types that can be selected and run them after you click OK.

    .PARAMETER Domain
    Specify a domain to run the scan in to cater to more complex environments

    .PARAMETER OutputPath
    Specify the path where you want to save the report.

    .OUTPUTS
    Different report output types (compliance with different report formats):
    1. To console
    2. HTML

    .EXAMPLE 
    Invoke-ADScanner -Domain test.local -Scans All -Format html -OutputPath c:\temp\
    Invoke-ADScanner -Domain staging.test.local -Scans ADCS,Kerberos -Format csv -OutputPath c:\temp\

    #>

    [CmdletBinding()]
    Param(
        [Parameter()]
        [String]
        $Domain,
    
        [Parameter()]
        [String]
        $Scans = "All",

        [Parameter()]
        [Switch]
        $Help,

        [Parameter()]
        [String]
        $APIkey
    )    


    # Display help menu if ran incorrectly
    if (-not $Domain -or $Help) {
        Write-Host "Example Usage:  Invoke-ADScanner -Domain test.local -Scans All -Format html -OutputPath c:\temp\
            -Domain     The domain to scan. If don't know scanner will automatically use the current domain the system is joined to (Get-ADDomain)
            -Scans      The scan type to choose (Info, Kerberos, PKI, RBAC, ACLs, Passwords, MISC, Legacy (Default: All))
            -Format     The report format (console/html)
            -OutputPath The location to save the report
            -APIkey     The API key for ChatGPT to generate a summary of the report
    " 
        return
    }

    #Logo made with https://patorjk.com/software/taag/#p=display&f=Big&t=ADScanner
    $Logo = @"

    /\   |  __ \ / ____|                                
    /  \  | |  | | (___   ___ __ _ _ __  _ __   ___ _ __ 
   / /\ \ | |  | |\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
  / ____ \| |__| |____) | (_| (_| | | | | | | |  __/ |   
 /_/    \_\_____/|_____/ \___\__,_|_| |_|_| |_|\___|_|   

 [+] Version: 1.0.0 - 15/03/2024
 [+] Jack G (@rootjack) https://github.com/rootjaxk/ADScanner
                                                   
"@

    Write-Host $Logo -ForegroundColor Yellow

    #Colours for console output
    function to_red ($msg) {
        "$([char]0x1b)[91m$msg$([char]0x1b)[0m"
    }
    function to_yellow ($msg) {
        "$([char]0x1b)[93m$msg$([char]0x1b)[0m"
    }
    function to_cyan ($msg) {
        "$([char]0x1b)[36m$msg$([char]0x1b)[0m"
    }
    function to_green ($msg) {
        "$([char]0x1b)[92m$msg$([char]0x1b)[0m"
    }

    #Add a check to see if RSAT is installed, if not, say to install it before importing AD module
    function Test-RSAT-Installed {
        $RSAT = Get-WindowsFeature -Name RSAT-AD-PowerShell
        if ($RSAT.Installed -eq $true) {
            return $true
        }
        else {
            return $false
        }
    }
    #required for esc7 check
    function Test-RSATADCS-Installed {
        $RSAT = Get-WindowsFeature -Name RSAT-ADCS
        if ($RSAT.Installed -eq $true) {
            return $true
        }
        else {
            return $false
        }
    }
    function Test-PSPKI-Installed {
        $PSPKI = Get-Module -ListAvailable -Name PSPKI
        if ($PSPKI -eq $null) {
            return $false
        }
        else {
            return $true
        }
    }

    Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Checking pre-requisites..." -ForegroundColor Yellow

    if (Test-RSAT-Installed) {
        Import-Module ActiveDirectory
    }
    else {
        Write-Host "RSAT is not installed. Please install RSAT as an elevated user before running this script." -ForegroundColor Yellow
        Write-Host "Command: Install-WindowsFeature -Name RSAT-AD-PowerShell" -ForegroundColor Yellow #- only works on servers, on workstaions need to do Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online (see locksmith) - https://github.com/TrimarcJake/Locksmith/blob/main/Private/Install-RSATADPowerShell.ps1
        Write-Host "Command: Install-WindowsFeature -Name GPMC" -ForegroundColor Yellow         #For GPOs
        return
    }   
    
    if (-not (Test-RSATADCS-Installed)) {
        Write-Host "RSAT is not installed. Please install RSAT as an elevated user before running this script." -ForegroundColor Yellow
        Write-Host "Command: Install-WindowsFeature -Name RSAT-ADCS" -ForegroundColor Yellow
        return
    }

    if (Test-PSPKI-Installed) {
        Import-Module PSPKI
    }
    else {
        Write-Host "PSPKI is not installed. Please install PSPKI as an elevated user before running this script." -ForegroundColor Yellow
        Write-Host "Command: Install-Module -Name PSPKI -Force" -ForegroundColor Yellow
        return
    }   

    #TO-DO - add functionality to do individual scans (for prioritised remediation)

    #TD-DO - add functionality to exclude GPT (if executing in environment where outbound access is not permitted / privacy concerns)

    
    # Create variables to store the findings
    $DomainInfo = @()
    $Kerberos = @()
    $PKI = @()
    $RBAC = @()
    $ACLs = @()
    $Passwords = @()
    $MISC = @()
    $Legacy = @()

    #Perform vulnerability checks
    $startTime = Get-Date
    Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Starting scan of $domain..." -ForegroundColor Yellow

    # Domain info
    if ($Scans -eq "Info" -or $Scans -eq "All") {
        $DomainInfo += Find-DomainInfo -Domain $Domain
    }
    #Generate report
    $htmlreportheader = @"
    <html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$Domain Vulnerability Report</title>
    <link rel="stylesheet" href="styles.css">
    <link rel="icon" type="image/x-icon" href="/Private/Report/Images/favicon-32x32.png">
</head>

<body>
    <div class="banner">
        <img src="./Images/kerberos-text2.png" alt="ADScanner logo" class="banner-img">
    </div>
    <div class="main-header">Domain vulnerability report for $Domain</div>
"@



    $CertificateTemplates = $domaininfo.CertificateTemplates -join ', '
    $CertificateAuthority = $domaininfo.CertificateAuthority -join ', '

    $DomainInfohtml = @"
<!-- Technical section -->
<div class="main-header">Technical section</div>
<div class="finding-header">Domain info</div>
<div class="domain-info">
<p>This section provides a general overview of the Active Directory domain, which can be taken as an indication of the size and complexity of the domain. Before appreciating any risks it is important to understand which assets within the domain require protecting.</p>
<table>
<th>Category</th>
<th>Value</th>
<tr><td class="grey">Domain:</td><td>$($domaininfo.Domain)</td></tr>
<tr><td class="grey">FunctionalLevel:</td><td>$($domaininfo.FunctionalLevel)</td></tr>
<tr><td class="grey">DomainControllers:</td><td>$($domaininfo.DomainControllers)</td></tr>
<tr><td class="grey">Users:</td><td>$($domaininfo.Users)</td></tr>
<tr><td class="grey">Groups:</td><td>$($domaininfo.Groups)</td></tr>
<tr><td class="grey">Computers:</td><td>$($domaininfo.Computers)</td></tr>
<tr><td class="grey">Trusts:</td><td>$($domaininfo.Trusts)</td></tr>
<tr><td class="grey">OUs:</td><td>$($domaininfo.OUs)</td></tr>
<tr><td class="grey">GPOs:</td><td>$($domaininfo.GPOs)</td></tr>
<tr><td class="grey">CertificateAuthority:</td><td>$CertificateAuthority</td></tr>
<tr><td class="grey">CAtemplates:</td><td>$($domaininfo.CAtemplates)</td></tr>
<tr><td class="grey">CertificateTemplates:</td><td>$CertificateTemplates</td></tr>
</table>
</div>
"@


    # PKI - ADCS
    if ($Scans -eq "ADCS" -or $Scans -eq "All") {
        $PKI += Find-ESC1 -Domain $Domain
        $PKI += Find-ESC2 -Domain $Domain 
        $PKI += Find-ESC3 -Domain $Domain
        $PKI += Find-ESC4 -Domain $Domain 
        $PKI += Find-ESC5 -Domain $Domain
        $PKI += Find-ESC6 -Domain $Domain
        $PKI += Find-ESC7 -Domain $Domain
        $PKI += Find-ESC8 -Domain $Domain
        $PKI = $PKI | Sort-Object -Property Score -Descending
    }
    $PKIhtml = Generate-PKIhtml -PKI $PKI


    # Kerberos
    if ($Scans -eq "Kerberos" -or $Scans -eq "All") {
        $Kerberos += Find-Kerberoast -Domain $Domain
        $Kerberos += Find-ASREProast -Domain $Domain
        $Kerberos += Find-Delegations -Domain $Domain
        $Kerberos += Find-GoldenTicket -Domain $Domain
        $Kerberos = $Kerberos | Sort-Object -Property Score -Descending
    }
    $Kerberoshtml = Generate-Kerberoshtml -Kerberos $Kerberos    


    # ACLs
    if ($Scans -eq "ACLs" -or $Scans -eq "All") {
        $ACLs += Find-ACLs -Domain $Domain
        $ACLs = $ACLs | Sort-Object -Property Score -Descending
    }
    $ACLshtml = Generate-ACLshtml -ACLs $ACLs
    
    
    # RBAC
    if ($Scans -eq "RBAC" -or $Scans -eq "All") {
        $RBAC += Find-PrivilegedGroups -Domain $Domain
        $RBAC += Find-AdminSDHolder -Domain $Domain
        $RBAC += Find-InactiveAccounts -Domain $Domain
        $RBAC += Find-AnonymousAccess -Domain $Domain
        $RBAC += Find-SensitiveAccounts -Domain $Domain
        $RBAC += Find-AdminSDHolder -Domain $Domain
    }
    if (!$RBAC) {
        $RBAChtml = @"
        <div class="finding-header">RBAC</div>
        <h2 class="novuln">No vulnerabilities found!</h2>
"@
    }
    else {
        $RBAChtml = @"
        <div class="finding-header">RBAC</div>
"@
    }









    # Passwords
    if ($Scans -eq "PwdPolicy" -or $Scans -eq "All" ) {
        $Passwords += Find-PasswordPolicy -Domain $Domain
        $Passwords += Find-PwdNotRequired -Domain $Domain
        $Passwords += Find-LAPS -Domain $Domain
        $Passwords += Find-SensitiveInfo -Domain $Domain
        #$Passwords += Find-UserDescriptions -Domain $Domain -APIKey $APIkey
        $Passwords = $Passwords | Sort-Object -Property Score -Descending
    }
    if (!$Passwords) {
        $Passwordshtml = @"
        <div class="finding-header">Passwords</div>
        <h2 class="novuln">No vulnerabilities found!</h2>
"@
    }
    else {
        $Passwordshtml = @"
        <div class="finding-header">Passwords</div>
"@
    }
    
    # MISC
    if ($Scans -eq "MISC" -or $Scans -eq "All") {
        $MISC += Find-MAQ -Domain $Domain
        $MISC += Find-OutboundAccess -Domain $Domain
        $MISC += Find-SMBSigning -Domain $Domain
        $MISC += Find-LDAPSigning -Domain $Domain
        $MISC += Find-Spooler -Domain $Domain
        $MISC += Find-WebDAV -Domain $Domain
        $MISC += Find-EfficiencyImprovements -Domain $Domain
        $MISC = $MISC | Sort-Object -Property Score -Descending
    }
    $MISChtml = Generate-MISChtml -MISC $MISC

    # Legacy
    if ($Scans -eq "Legacy" -or $Scans -eq "All") {
        $Legacy += Find-LegacyProtocols -Domain $Domain
        $Legacy += Find-UnsupportedOS -Domain $Domain
        $Legacy = $Legacy | Sort-Object -Property Score -Descending
    }
    $Legacyhtml = Generate-Legacyhtml -Legacy $Legacy

   
    #Generate report
    Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Generating report..." -ForegroundColor Yellow
    if ($Scans -eq "All") {
        
        Write-Host @"
#####################################################################################
#                                   Run Info                                        #
##################################################################################### 
"@
        $endTime = Get-Date
        $elapsedTime = $endTime - $startTime
        $Runinfo = [PSCustomObject]@{
            "Domain Assessed" = $Domain
            "Ran as User"     = "$env:USERDOMAIN\$env:USERNAME"
            "Ran on Host"     = (Get-ADComputer -Identity $env:COMPUTERNAME).dnshostname
            "Date and Time"   = $startTime
            "Time to Run"     = $($elapsedTime.TotalSeconds)
        }
        $Runinfo | Format-List

        $runinfoHTML = @"
        <!-- Executive summary section -->
        <div class="summary">
        <!-- Left section for the tables -->
        <div class="left-section">
            <div class="table-container">
                <table class="summary-table">
                    <thead>
                        <tr>
                            <th colspan="2">Details when ran</th>
                        </tr>
                        <tr>
                            <td>Domain Assessed</td>
                            <td>$Domain</td>
                        </tr>
                        <tr>
                            <td>Ran as User</td>
                            <td>$env:USERDOMAIN\$env:USERNAME</td>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Ran on Host</td>
                            <td>$($(Get-ADComputer -Identity $env:COMPUTERNAME).dnshostname)</td>
                        </tr>
                        <tr>
                            <td>Date and Time</td>
                            <td>$startTime</td>
                        </tr>
                        <tr>
                            <td>Time to Run</td>
                            <td>$($elapsedTime.TotalSeconds)</td>
                        </tr>
                    </tbody>
                </table>
            </div>
"@

        Write-Host @"
#####################################################################################
#                          Risk Prioritisation Summary                              #
#####################################################################################
"@
        #Category of risks - array of hashtables
        $categoryVariables = @(
            @{Name = "Kerberos"; Variable = $Kerberos },
            @{Name = "PKI"; Variable = $PKI },
            @{Name = "RBAC"; Variable = $RBAC },
            @{Name = "ACLs"; Variable = $ACLs },
            @{Name = "Passwords"; Variable = $Passwords },
            @{Name = "MISC"; Variable = $MISC },
            @{Name = "Legacy"; Variable = $Legacy }
        )

        #Domain risk score
        foreach ($item in $categoryVariables) {
            $totaldomainriskscore += ($item.Variable | Measure-Object -Property Score -Sum).Sum
        } 
        $Domainrisk = [PSCustomObject]@{
            Category   = $Domain
            TotalScore = "$TotalDomainRiskScore / 100"
        }
        Write-Host "[*] Domain risk score:"
        $Domainrisk | Format-Table

        #Dynamically resolve risk image based on score
        $riskOverallHTML = @"
        <!-- Risk overall section -->
        <div class="risk-overall">
        <div class="left-image"> 
"@
        if ($TotalDomainRiskScore -ge 100) {
            $riskOverallHTML += @"  
            <img src="./Images/Risk-scores/Critical.png" alt="Overall risk score">
            </div>
"@
        }
        elseif ($TotalDomainRiskScore -ge 75) {
            $riskOverallHTML += @"
            <img src="./Images/Risk-scores/High.png" alt="Overall risk score">
            </div>
"@
        }
        elseif ($TotalDomainRiskScore -ge 50) {
            $riskOverallHTML += @"
            <img src="./Images/Risk-scores/Medium.png" alt="Overall risk score">
            </div>
"@ 
        }
        elseif ($TotalDomainRiskScore -ge 25) {
            $riskOverallHTML += @"
            <img src="./Images/Risk-scores/Low.png" alt="Overall risk score">
            </div>
"@   
        }
        elseif ($TotalDomainRiskScore -eq 1) {
            $riskOverallHTML += @"
            <img src="./Images/Risk-scores/Very-low.png" alt="Overall risk score">
            </div> 
"@
        }
        elseif ($TotalDomainRiskScore -eq 0) {
            $riskOverallHTML += @"
            <img src="./Images/Risk-scores/Perfect.png" alt="Overall risk score">
            </div> 
"@   
        }
        #Risk level commentry
        $riskOverallHTML += @"
        <div class="risk-overall-text">
            <h1>Domain risk level: $TotalDomainRiskScore / 100</h1>
             <p>The maximum score is 100, anything above this presents a significant risk to ransomware.</p>
             <p>Attackers will always exploit the path of least resistance (higher scores) - low hanging fruit.</p>
             <a href="#category-summary">See score breakdown table</a>
        </div>
    </div>
"@


        #Category risk scores
        Write-Host "`r`n[*] Category Risk scores:"
        $categoryRisks = @()
        foreach ($item in $categoryVariables) {
            $score = ($item.Variable | Measure-Object -Property Score -Sum).Sum
            $categoryRisks += [PSCustomObject]@{
                Category = $item.Name
                Score    = $score
            }
        }
        #Order category by score
        $categoryRisks = $categoryRisks | Sort-Object -Property Score -Descending
        $categoryRisks

        $categoryRisksHTML = @"
        <div class="table-container">
                <table class="summary-table" id="category-summary">
                    <thead>
                        <tr>
                            <th>Category</th>
                            <th>Risk Score</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        foreach ($item in $categoryRisks) {
            if ($item.score -ge 100) {
                $categoryRisksHTML += @"
                <tr>
                    <td>$($item.Category)</td>
                    <td class="category-riskcritical">$($item.score)</td>
                </tr>
"@
            }
            elseif ($item.score -ge 75) {
                $categoryRisksHTML += @"
                <tr>
                    <td>$($item.Category)</td>
                    <td class="category-riskhigh">$($item.score)</td>
                </tr>
"@
            }
            elseif ($item.score -ge 50) {
                $categoryRisksHTML += @"
                <tr>
                    <td>$($item.Category)</td>
                    <td class="category-riskmedium">$($item.score)</td>
                </tr>
"@
            }
            elseif ($item.score -ge 1) {
                $categoryRisksHTML += @"
                <tr>
                    <td>$($item.Category)</td>
                    <td class="category-risklow">$($item.score)</td>
                </tr>
"@          
            }
            elseif ($item.score -eq 0) {
                $categoryRisksHTML += @"
                <tr>
                    <td>$($item.Category)</td>
                    <td class="category-riskinformational">$($item.score)</td>
                </tr>       
"@
            }
        }
        $categoryRisksHTML += @"
                    </tbody>
                </table>
            </div>
        </div>
"@


        #Ordered summary of risks
        $Risksummaries = "`r`n[*] Risk summaries:"
        $Allissues += $PKI + $Kerberos + $RBAC + $ACLs + $Passwords + $MISC + $Legacy

        #Add category to each issue
        $Allissues | ForEach-Object {
            try {
                if ($_ -in $PKI) {
                    $_ | Add-Member -NotePropertyName "Category" -NotePropertyValue "PKI"
                }
                elseif ($_ -in $Kerberos) {
                    $_ | Add-Member -NotePropertyName "Category" -NotePropertyValue "Kerberos"
                }
                elseif ($_ -in $RBAC) {
                    $_ | Add-Member -NotePropertyName "Category" -NotePropertyValue "RBAC"
                }
                elseif ($_ -in $ACLs) {
                    $_ | Add-Member -NotePropertyName "Category" -NotePropertyValue "ACLs"
                }
                elseif ($_ -in $Passwords) {
                    $_ | Add-Member -NotePropertyName "Category" -NotePropertyValue "Passwords"
                }
                elseif ($_ -in $Legacy) {
                    $_ | Add-Member -NotePropertyName "Category" -NotePropertyValue "Legacy"
                }
                elseif ($_ -in $MISC) {
                    $_ | Add-Member -NotePropertyName "Category" -NotePropertyValue "MISC"
                }
            
            }
            catch {}
        }
        $Risksummaries
        $AllissuesHTML = $Allissues | Where-Object { $null -ne $_.Score } | Select-Object Risk, Technique, Category, Score | Sort-Object -Property Score -Descending
        $AllissuesHTML | Format-Table


        #Define top of table
        $RisksummaryHTMLoutput = @"
        <!-- Risk prioritisation section -->
        <div class="risk-summary-container">
        <div class="risk-summary-heading">
            <h2>Risk Prioritisation Summary</h2>
            <p>The table below summarizes the number and severity of findings in order of decreasing risk. Full
                details can be found by clicking on each vulnerability which will take you to the relevant technical
                section.</p>
        </div>
        <table class="risk-prioritisation-summary">
            <thead>
                <tr>
                    <th class="risk-column">Risk</th>
                    <th class="technique-column">Issue</a></th>
                    <th class="category-column">Category</th>
                    <th class="score-column">Score</th>
                </tr>
            </thead>
            <tbody>
"@

        #Dynamically add rows to table based on risk
        foreach ($row in $AllissuesHTML) {
            $nospace = $row.Technique.Replace(" ", "-")
            if ($row.risk -match "CRITICAL") {
                #replace whitespace with - as HTML id's cannot have whitespace
                $RisksummaryHTMLoutput += @"
                <tr class="critical">
                    <td>Critical</td>
                    <td><a href="#$nospace">$($row.technique)</a></td>
                    <td>$($row.category)</td>
                    <td>$($row.score)</td>
                </tr>
"@
            }
            elseif ($row.risk -match "HIGH") {
                $RisksummaryHTMLoutput += @"
                <tr class="high">
                    <td>High</td>
                    <td><a href="#$nospace">$($row.technique)</a></td>
                    <td>$($row.category)</td>
                    <td>$($row.score)</td>
                </tr>
"@
            }
            elseif ($row.risk -match "MEDIUM") {
                $RisksummaryHTMLoutput += @"
                <tr class="medium">
                    <td>Medium</td>
                    <td><a href="#$nospace">$($row.technique)</a></td>
                    <td>$($row.category)</td>
                    <td>$($row.score)</td>
                </tr>
"@
            }
            elseif ($row.risk -match "LOW") {
                $RisksummaryHTMLoutput += @"
                <tr class="low">
                    <td>Low</td>
                    <td><a href="#$nospace">$($row.technique)</a></td>
                    <td>$($row.category)</td>
                    <td>$($row.score)</td>
                </tr>
"@
            }
            elseif ($row.risk -match "INFO") {
                $RisksummaryHTMLoutput += @"
                <tr class="information">
                    <td>Informational</td>
                    <td><a href="#$nospace">$($row.technique)</a></td>
                    <td>$($row.category)</td>
                    <td>$($row.score)</td>
                </tr>
"@
            }
        }
        #end the table
        $RisksummaryHTMLoutput += "</tbody></table></div>"
    }

    
        
    # Output all findings in separate sections
    if ($Scans -eq "Info" -or $Scans -eq "All") {
        
        Write-Host @"
#####################################################################################
#                                    Domain Info                                    #
#####################################################################################
"@
        $DomainInfo | Format-List
    }

    if ($Scans -eq "ADCS" -or $Scans -eq "All") {

        Write-Host @"
#####################################################################################
#                                       PKI                                         #
#####################################################################################
"@
        $PKI | Format-List      #all 50 points and already in order
    }

    if ($Scans -eq "Kerberos" -or $Scans -eq "All") {
        Write-Host @"
#####################################################################################
#                                    Kerberos                                       #
#####################################################################################
"@
        $Kerberos | Sort-Object -Property Score -Descending | Format-List
    }    

    if ($Scans -eq "RBAC" -or $Scans -eq "All") {
        Write-Host @"
#####################################################################################
#                                       RBAC                                        #
#####################################################################################
"@
        $RBAC | Sort-Object -Property Score -Descending | Format-List
    }

    if ($Scans -eq "ACLs" -or $Scans -eq "All") {
        Write-Host @"
#####################################################################################
#                                       ACLs                                        #
#####################################################################################
"@
        $ACLs | Sort-Object -Property Score -Descending | Format-List
    }

    if ($Scans -eq "Passwords" -or $Scans -eq "All") {
        Write-Host @"
#####################################################################################
#                                     Passwords                                     #
#####################################################################################
"@
        $Passwords | Sort-Object -Property Score -Descending | Format-List
    }

    if ($Scans -eq "MISC" -or $Scans -eq "All") {
        Write-Host @"
#####################################################################################
#                                       MISC                                        #
#####################################################################################
"@
        $MISC | Sort-Object -Property Score -Descending | Format-List
    }

    if ($Scans -eq "Legacy" -or $Scans -eq "All") {
        Write-Host @"
#####################################################################################
#                                       LEGACY                                      #
#####################################################################################
"@
        $Legacy | Sort-Object -Property Score -Descending | Format-List
    }


    #wont output to screen in order as different ones take different amount of time, but when testing this is ok. real will save to variable for use in report

    #Attribute risk score - maybe have own file - attribute it here or elsewhere?
  
    # Caclulate-risk-score

    #Get generative AI input
    $executiveSummaryHTML = @"
    <!-- Right section for the executive summary -->
        <div class="executive-summary">
            <h2>Executive Summary (GPT to contextualize)</h2>
            <p>ADscanner was commissioned to perform a vulnerability assessment against the test.local Active Directory
                domain to ensure correct security configuration and operation of the Directory.
                The audit indicates that the security of the Active Directory is reduced by the X, Y & Z. a number of
                misconfigurations significantly increases the attack surface of Active Directory, and therefore the
                network could be exploited by a determined attacker deploying ransomware and malware.</p>
            <p>ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...</p>
            <p>ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...</p>
            <p>ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...ChatGPT will fill the rest of this in...</p>
        </div>
    </div>
"@

    #Produce report
    #Generate-Report


    $htmlreportheader # banner and top heading
    $riskOverallHTML # domain risk level
    $runinfoHTML   # details when ran
    $categoryRisksHTML # category risk scores
    $executiveSummaryHTML # executive summary with GPT
    $RisksummaryHTMLoutput # risk prioritisation summary
    $DomainInfohtml # first bit of technical section

    #Technical sections
    #$PKIhtml
    #$Kerberoshtml
    #$ACLshtml
    #$RBAChtml
    #$Passwordshtml
    #$MISChtml
    #$Legacyhtml

    #output to a file
    #$DomainInfohtml | Out-File -FilePath "report.html"
    
}
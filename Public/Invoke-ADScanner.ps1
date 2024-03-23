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
        Write-Host -ForegroundColor Yellow "Example Usage:  Invoke-ADScanner -Domain test.local -Scans All -Format html -OutputPath c:\temp\
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

 [+] Version: 1.0.0 - 23/03/2024
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
    $DomainInfohtml = Generate-DomainInfohtml -DomainInfo $DomainInfo
    
    #Generate report header
    $htmlreportheader = Generate-HTMLReportHeader -Domain $Domain

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
    
    # Kerberos
    if ($Scans -eq "Kerberos" -or $Scans -eq "All") {
        $Kerberos += Find-Kerberoast -Domain $Domain
        $Kerberos += Find-ASREProast -Domain $Domain
        $Kerberos += Find-Delegations -Domain $Domain
        $Kerberos += Find-GoldenTicket -Domain $Domain
        $Kerberos = $Kerberos | Sort-Object -Property Score -Descending
    }   

    # ACLs
    if ($Scans -eq "ACLs" -or $Scans -eq "All") {
        $ACLs += Find-ACLs -Domain $Domain
        $ACLs = $ACLs | Sort-Object -Property Score -Descending
    }
    
    # RBAC
    if ($Scans -eq "RBAC" -or $Scans -eq "All") {
        $RBAC += Find-PrivilegedGroups -Domain $Domain
        $RBAC += Find-AdminSDHolder -Domain $Domain
        $RBAC += Find-InactiveAccounts -Domain $Domain
        $RBAC += Find-AnonymousAccess -Domain $Domain
        $RBAC += Find-SensitiveAccounts -Domain $Domain
        $RBAC = $RBAC | Sort-Object -Property Score -Descending
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

    # Legacy
    if ($Scans -eq "Legacy" -or $Scans -eq "All") {
        $Legacy += Find-LegacyProtocols -Domain $Domain
        $Legacy += Find-UnsupportedOS -Domain $Domain
        $Legacy = $Legacy | Sort-Object -Property Score -Descending
    }

   
    #Generate console report
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
        $riskOverallHTML = Generate-Riskoverallhtml -TotalDomainRiskScore $totaldomainriskscore
    
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
        $categoryRisksHTML = Generate-CategoryRisksHTML -CategoryRisks $categoryRisks


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
        $RisksummaryHTMLoutput = Generate-RisksummaryHTMLoutput -AllissuesHTML $AllissuesHTML  
    }
        
    # Output console report
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
        $PKI | Format-List
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

    #Get generative AI input - put in own function
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

    #HTML Findings
    $PKIhtml = Generate-PKIhtml -PKI $PKI
    $Kerberoshtml = Generate-Kerberoshtml -Kerberos $Kerberos 
    $ACLshtml = Generate-ACLshtml -ACLs $ACLs
    $RBAChtml = Generate-RBAChtml -RBAC $RBAC
    $Passwordshtml = Generate-Passwordshtml -Passwords $Passwords
    $MISChtml = Generate-MISChtml -MISC $MISC
    $Legacyhtml = Generate-Legacyhtml -Legacy $Legacy
    $Reportfooter = Generate-ReportFooter
    $JSend = Generate-javascripthtml

    #Generate Web Report
    $FinalHTML = $htmlreportheader + $riskOverallHTML + $runinfoHTML + $categoryRisksHTML + $executiveSummaryHTML + $RisksummaryHTMLoutput + $DomainInfohtml + $PKIhtml + $Kerberoshtml + $ACLshtml + $RBAChtml + $Passwordshtml + $MISChtml + $Legacyhtml + $Reportfooter + $JSend

    #Output HTML report
    $FinalHTML | Out-File -FilePath "report.html"
    Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Report outputted to report.html" -ForegroundColor Yellow
    Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Done!" -ForegroundColor Yellow
    
}
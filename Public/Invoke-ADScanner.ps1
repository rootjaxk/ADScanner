function Invoke-ADScanner {
    <#
    .SYNOPSIS
    Scans Active Directory for common vulnerabilities and produces an intelligent report to support remediation of vulnerabilities.

    .DESCRIPTION
    Invoke-ADScanner primarily uses the Active Directory (AD) Powershell (PS) module to identify common and highly dangerous misconfigurations
    found in Enterprise Active Directory environments.

    .COMPONENT
    Invoke-ADScanner requires the AD & ADCS modules to be installed in the scope of the Current User. This will require the Remote System Administration
    Toolkit (RSAT) as well as the PSPKI module  installed on the device. 
    If ADScanner does not identify any pre-requisites installed, it will attempt to install the relevant modules.

    .PARAMETER Scans
    Specify which scans you want to run. Available scans: 'All, Info, PKI, Kerberos, RBAC, ACLs, Passwords, MISC, Legacy'

    -Scans All
    Run all scans (default)

    .PARAMETER Domain
    Specify a domain to run the scan in to cater to more complex environments

    .PARAMETER OutputPath
    Specify the path where you want to save the report.

    .PARAMETER Format
    Different report output types (compliance with different report formats):
    1. To console
    2. HTML

    .PARAMETER APIKey
    The API key for ChatGPT (only needed for HTML format)

    .PARAMETER Help
    Display the help menu

    .EXAMPLE 
    Invoke-ADScanner -Domain test.local -APIKey <API key> -OutputPath c:\temp\
    Invoke-ADScanner -Domain test.local -Scans PKI -Format Console

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
        $Format = "HTML",

        [Parameter()]
        [String]
        $OutputPath = (Get-Location).Path,

        [Parameter()]
        [String]
        $APIkey
    )    


    # Display help menu if ran incorrectly
    if ($Help -or $Scans -notmatch "All|Info|Kerberos|PKI|RBAC|ACLs|Passwords|MISC|Legacy" -or ($format -notmatch "console" -and $scans -notmatch "all") -or ($format -match "HTML" -and -not $APIkey)) {
        Write-Host -ForegroundColor Yellow "Invalid usage. Options:
            -Domain     The domain to scan. If don't know scanner will automatically use the current domain the system is joined to (Get-ADDomain)
            -Scans      The scan type to choose - All, Info, PKI, Kerberos, RBAC, ACLs, Passwords, MISC, Legacy (Default: All)
            -Format     The report format - HTML/Console (Default: HTML)
            -OutputPath The location to save the report (Default: current directory)
            -APIkey     The API key for ChatGPT (only needed for HTML format). Exclude if don't want to send data to ChatGPT and just use the console output

            Default Usage (Generate HTML domain report): Invoke-ADScanner -Domain test.local -APIKey <API key> -OutputPath c:\temp\
            Console example (check remediation for PKI is succesful): Invoke-ADScanner -Domain test.local -Scans PKI -Format Console
    " 
        return
    }

    if (-not $Domain) {
        $Domain = (Get-ADDomain).DNSRoot
    }

    #Logo made with https://patorjk.com/software/taag/#p=display&f=Big&t=ADScanner
    $Logo = @"

     /\   |  __ \ / ____|                                
    /  \  | |  | | (___   ___ __ _ _ __  _ __   ___ _ __ 
   / /\ \ | |  | |\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
  / ____ \| |__| |____) | (_| (_| | | | | | | |  __/ |   
 /_/    \_\_____/|_____/ \___\__,_|_| |_|_| |_|\___|_|   

 [+] Version: 1.0.0 - 27/03/2024
 [+] Jack G (@rootjack) https://github.com/rootjaxk/ADScanner
                                                   
"@
    Write-Host $Logo -ForegroundColor Yellow
    if($format -ne $HTML -and -not $APIkey){
        Write-Host "Console output chosen - no data will be sent to GPT and some checks will be missed." -ForegroundColor Yellow
        $noGPT = $true
    }

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

    function Test-RSAT-Installed {
        $RSAT = Get-Module -ListAvailable -Name 'ActiveDirectory'
        if ($RSAT) {
            return $true
        }
        else {
            return $false
        }
    }
    function Test-RSATADCS-Installed {
        try {
            $RSAT = Get-WindowsFeature -Name RSAT-ADCS
            if ($RSAT.Installed -eq $true) {
                return $true
            }
            else {
                return $false
            }
        }
        catch {
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

    #Check if elevated to install pre-requisites
    function Is-Admin {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $context = New-Object Security.Principal.WindowsPrincipal $identity
        return $context.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    }
    $OS = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType  # 1 - workstation, 2 - domain controller, 3 - non-dc server

    Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Checking pre-requisites..." -ForegroundColor Yellow

    #Check if RSAT is installed
    if (Test-RSAT-Installed) {
        Import-Module ActiveDirectory
        Import-Module GroupPolicy
    }
    elseif (Is-Admin -eq $true) {
        #AD module install - different install on workstations
        Write-Host "Installing RSAT-AD-PowerShell..." -ForegroundColor Yellow
        if ($OS -eq 1) {
            Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online
        }
        else {
            Install-WindowsFeature -Name RSAT-AD-PowerShell
        }    
        #GPO install - different on workstattions
        Write-Host "Installing GPMC..." -ForegroundColor Yellow
        if ($OS -eq 1) {
            Add-WindowsCapability -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0 -Online
        }
        else {
            Install-WindowsFeature -Name GPMC  
        }
    }
    else {
        Write-Host "RSAT-AD is not installed, please run ADScanner in an elevated powershell prompt to install the required RSAT modules." -ForegroundColor Yellow
        return
    }
    
    #Chec if PSPKI is installed
    if (Test-PSPKI-Installed) {
        Import-Module PSPKI
    }
    elseif (Is-Admin -eq $true) {
        Write-Host "Installing PSPKI..." -ForegroundColor Yellow
        Install-Module -Name PSPKI -Force
    }
    else {
        Write-Host "PSPKI is not installed. Please install PSPKI as an elevated user before running this script." -ForegroundColor Yellow
        return
    }

    #Check if RSAT-ADCS is installed (for ESC7 check)
    if (-not (Test-RSATADCS-Installed)) {
        if (Is-Admin -eq $true) {
            Write-Host "Installing RSAT-ADCS..." -ForegroundColor Yellow
            if ($OS -eq 1) {
                Add-WindowsCapability -Name Rsat.CertificateServices.Tools~~~~0.0.1.0 -Online
            }
            else {
                Install-WindowsFeature -Name RSAT-ADCS 
            }
        }
        else {
            if ($OS -eq 1) {
                import-module PSPKI
                #check if RSAT-ADCS works
                try {
                    $success = Get-CertificateTemplate
                } catch {}
                if (-not $success) {
                    Write-Host "RSAT-ADCS is not installed - please run ADScanner in an elevated powershell prompt to install the required RSAT modules." -ForegroundColor Yellow
                    return
                }
            }
        }
    }


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

    if ($Scans -eq "Info" -or $Scans -eq "All") {
        $DomainInfo += Find-DomainInfo -Domain $Domain
    }
    if ($Scans -eq "ADCS" -or $Scans -eq "All") {
        #First check if PKI exists
        $ADCSexists = Find-ADCS -Domain $Domain
        if($ADCSexists) {
            $PKI += Find-ESC1 -Domain $Domain
            $PKI += Find-ESC2 -Domain $Domain 
            $PKI += Find-ESC3 -Domain $Domain
            $PKI += Find-ESC4 -Domain $Domain 
            $PKI += Find-ESC5 -Domain $Domain
            $PKI += Find-ESC6 -Domain $Domain
            $PKI += Find-ESC7 -Domain $Domain
            $PKI += Find-ESC8 -Domain $Domain
            $PKI = $PKI | Sort-Object -Property Score -Descending
        } else{
            Write-Host "No ADCS found in $domain - PKI checks skipped" -ForegroundColor Yellow
            $ADCSexists = $false
        }
    }
    if ($Scans -eq "Kerberos" -or $Scans -eq "All") {
        $Kerberos += Find-Kerberoast -Domain $Domain
        $Kerberos += Find-ASREProast -Domain $Domain
        $Kerberos += Find-Delegations -Domain $Domain
        $Kerberos += Find-GoldenTicket -Domain $Domain
        $Kerberos = $Kerberos | Sort-Object -Property Score -Descending
    }   
    if ($Scans -eq "ACLs" -or $Scans -eq "All") {
        $ACLs += Find-ACLs -Domain $Domain
        $ACLs = $ACLs | Sort-Object -Property Score -Descending
    }
    if ($Scans -eq "RBAC" -or $Scans -eq "All") {
        $RBAC += Find-PrivilegedGroups -Domain $Domain
        $RBAC += Find-AdminSDHolder -Domain $Domain
        $RBAC += Find-InactiveAccounts -Domain $Domain
        $RBAC += Find-AnonymousAccess -Domain $Domain
        $RBAC += Find-SensitiveAccounts -Domain $Domain
        $RBAC = $RBAC | Sort-Object -Property Score -Descending
    }
    if ($Scans -eq "PwdPolicy" -or $Scans -eq "All" ) {
        $Passwords += Find-PasswordPolicy -Domain $Domain
        $Passwords += Find-PwdNotRequired -Domain $Domain
        $Passwords += Find-LAPS -Domain $Domain
        $Passwords += Find-SensitiveInfo -Domain $Domain
        #If console output only, skip GPT
        if (-not $noGPT) {
            $Passwords += Find-UserDescriptions -Domain $Domain -APIKey $APIkey
        }
        $Passwords = $Passwords | Sort-Object -Property Score -Descending
    }
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
    if ($Scans -eq "Legacy" -or $Scans -eq "All") {
        $Legacy += Find-LegacyProtocols -Domain $Domain
        $Legacy += Find-UnsupportedOS -Domain $Domain
        $Legacy = $Legacy | Sort-Object -Property Score -Descending
    }

  
   
    #Generate console report
    if ($Scans -eq "All") {
        Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Console report summary..." -ForegroundColor Yellow
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
       
        Write-Host @"
#####################################################################################
#                          Risk Prioritisation Summary                              #
#####################################################################################
"@
        #Account for no PKI
        if ($ADCSexists -eq $false){
            $pki = New-Object PSObject
            Add-Member -InputObject $pki -MemberType NoteProperty -Name score -Value 0
        }
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
    }
        
    # Output console report
    if ($Format -eq "Console" -and ($Scans -eq "Info" -or $Scans -eq "All")) {
        Write-Host @"
#####################################################################################
#                                    Domain Info                                    #
#####################################################################################
"@
        $DomainInfo | Format-List
    }

    if ($Format -eq "Console" -and ($Scans -eq "ADCS" -or $Scans -eq "All")) {
        Write-Host @"
#####################################################################################
#                                       PKI                                         #
#####################################################################################
"@
        if ($ADCSexists -eq $false){
            Write-Host "No ADCS found in $domain" -ForegroundColor Yellow
        }
        else{
            $PKI | Format-List
        }
    }

    if ($Format -eq "Console" -and ($Scans -eq "Kerberos" -or $Scans -eq "All")) {
        Write-Host @"
#####################################################################################
#                                    Kerberos                                       #
#####################################################################################
"@
        $Kerberos | Sort-Object -Property Score -Descending | Format-List
    }    

    if ($Format -eq "Console" -and ($Scans -eq "RBAC" -or $Scans -eq "All")) {
        Write-Host @"
#####################################################################################
#                                       RBAC                                        #
#####################################################################################
"@
        $RBAC | Sort-Object -Property Score -Descending | Format-List
    }

    if ($Format -eq "Console" -and ($Scans -eq "ACLs" -or $Scans -eq "All")) {
        Write-Host @"
#####################################################################################
#                                       ACLs                                        #
#####################################################################################
"@
        $ACLs | Sort-Object -Property Score -Descending | Format-List
    }

    if ($Format -eq "Console" -and ($Scans -eq "Passwords" -or $Scans -eq "All")) {
        Write-Host @"
#####################################################################################
#                                     Passwords                                     #
#####################################################################################
"@
        $Passwords | Sort-Object -Property Score -Descending | Format-List
    }

    if ($Format -eq "Console" -and ($Scans -eq "MISC" -or $Scans -eq "All")) {
        Write-Host @"
#####################################################################################
#                                       MISC                                        #
#####################################################################################
"@
        $MISC | Sort-Object -Property Score -Descending | Format-List
    }

    if ($Format -eq "Console" -and ($Scans -eq "Legacy" -or $Scans -eq "All")) {
        Write-Host @"
#####################################################################################
#                                       LEGACY                                      #
#####################################################################################
"@
        $Legacy | Sort-Object -Property Score -Descending | Format-List
    }


    #HTML Findings
    if ($Format -eq "HTML") {
        Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Generating HTML report..." -ForegroundColor Yellow
        Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Producing contextualized remediation..." -ForegroundColor Yellow
    
        #Executive section    
        $htmlreportheader = Generate-HTMLReportHeader -Domain $Domain
        $riskOverallHTML = Generate-Riskoverallhtml -TotalDomainRiskScore $totaldomainriskscore #Dynamically resolve risk image based on score
        $runinfoHTML = Generate-runinfo -domain $domain -starttime $startTime -elapsedtime $elapsedTime
        $categoryRisksHTML = Generate-CategoryRisksHTML -CategoryRisks $categoryRisks
        $RisksummaryHTMLoutput = Generate-RisksummaryHTMLoutput -AllissuesHTML $AllissuesHTML 
        $executiveSummaryHTML = Generate-ExecutiveSummary -APIKey $APIkey -RisksummaryHTMLoutput $RisksummaryHTMLoutput -RiskOverallHTML $riskOverallHTML -Domain $Domain

        #Technical section
        $DomainInfohtml = Generate-DomainInfohtml -DomainInfo $DomainInfo
        #Account for PKI not existing
        if ($ADCSexists -eq $false) {
            $PKI  = "None"
        } 
        $PKIhtml = Generate-PKIhtml -PKI $PKI -APIKey $APIkey
        $Kerberoshtml = Generate-Kerberoshtml -Kerberos $Kerberos -APIKey $APIkey
        $ACLshtml = Generate-ACLshtml -ACLs $ACLs -APIKey $APIkey
        $RBAChtml = Generate-RBAChtml -RBAC $RBAC -APIKey $APIkey
        $Passwordshtml = Generate-Passwordshtml -Passwords $Passwords -APIKey $APIkey
        $MISChtml = Generate-MISChtml -MISC $MISC -APIKey $APIkey
        $Legacyhtml = Generate-Legacyhtml -Legacy $Legacy -APIKey $APIkey
        $Reportfooter = Generate-ReportFooter
        $JSend = Generate-javascripthtml

        #Generate Web Report
        $FinalHTML = $htmlreportheader + $riskOverallHTML + $runinfoHTML + $categoryRisksHTML + $executiveSummaryHTML + $RisksummaryHTMLoutput + $DomainInfohtml + $PKIhtml + $Kerberoshtml + $ACLshtml + $RBAChtml + $Passwordshtml + $MISChtml + $Legacyhtml + $Reportfooter + $JSend

        #Output HTML report
        if ($outputpath.EndsWith('\')) {
            $outputpath = $outputpath.TrimEnd('\')
        }
        #give file name with output and date
        $Endpath = $OutputPath + "\ADScanner-$domain-$((Get-Date).ToString("dd-MM-yyyy")).html"
        $FinalHTML | Out-File -FilePath $Endpath
        Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Report outputted to $Endpath" -ForegroundColor Yellow
        Write-Host "$((Get-Date).ToString(""[HH:mm:ss tt]"")) Done!" -ForegroundColor Yellow
    }
}
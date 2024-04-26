![Banner](https://raw.githubusercontent.com/rootjaxk/ADScanner/main/Private/Report/Images/kerberos-text2.png)  
# ADScanner
ADScanner is an improved Active Directory vulnerability scanner with intelligent report capability designed to quickly and easily reduce the risk of Active Directory environments that are victims of 10+ years of technical debt with compounding misconfigurations. 

ADscanner will scan for 120+ vulnerability checks and produce a professional HTML vulnerability report and risk register ordered by risk severity. The report has attack demonstrations with contextualized remediation aided by ChatGPT to understand how threat actors will compromise your environment and help reduce risk as quickly as possible.

Within a few minutes you can understand the biggest risks impacting your Active Directory and can work on minimizing the likelihood of ransomware. 

Inspired from the [pingcastle](https://github.com/vletoux/pingcastle) and [locksmith](https://github.com/TrimarcJake/Locksmith) projects.

## Why this tool?
Typical penetration tests are costly, time-constrained, not consistent and depend highly on the skill of the tester. Reports can be rushed and generic remediation recommendations given, resulting in clients accepting their risks rather than actually remediating their issues. 

ADScanner addresses this, providing a free way to perform an Active Directory pentest on-demand and receive a professional report within minutes. It has been designed based of years of assessing vulnerable Active Directory environments & improving current gaps and accessibility in current tooling.

Capable of finding comprehensive attack vectors and your biggest risks across categories like PKI, Kerberos, RBAC, ACLs, Passwords, MISC and Legacy. 


## Features
 - Overall domain risk score - explain risk to management in a quantitative way
 - Executive summary for management produced by GPT - get senior management on side 
 - Risk prioritisation summary - understand the correct order of remediation
 - Quick and easy to run - no technical skills required
 - Run on any domain joined system - no admin privileges required
 - Improved risk scoring - understand vulnerability impact better
 - Comprehensive vulnerability checks - capable of linking chained vulnerabilities together
 - Category risk scores - understand which area needs the most remediation focus
 - MITRE ATT&CK mapping - understand the attacks your business is most vulnerable to
 - Technical vulnerability explanations - understand exactly what the vulnerabilities mean and the impact have
 - Visual attack demonstrations - understand attack vectors to see how modern threat actors attackers will exploit your Active Directory vulnerabilities to take over your infrastructure
 - Contextualized remediation using generative AI - understand step-by-step what needs to be done to fix the issues
 - Bypass security alerts due to RSAT integration
 - Can be run repeatedly - allow for validation of successful remediation and to track risk reduction over time
 - Usable as an aid for penetration testers or security analysts - professional report caters to both blue and red teams
 - Check vulnerabilities in a specific category  - instantly verify if remediation was effective



# Run ADScanner
## Pre-requisites
Requires Remote Administration Toolkit (RSAT) to be installed. If not installed, on first run the module will try and install the relevant dependencies. 

Will require outbound internet access to https://raw.githubusercontent.com and https://api.openai.com.

Works best executing on a system with full connectivity to all assets in a flat AD environment - if stateful firewalls segment portions of the network then this tool will not accurately test them. 

## Usage
Bypass execution policy (as script isn't signed yet)
```
PS C:\> powershell -ep bypass
```

Download and import the module
```
PS C:\> Import-Module .\ADScanner.psd1
```

Run specifying OpenAI API key - average scan for 120 checks costs $0.01
```
PS C:\> Invoke-ADScanner -Domain test.local -APIKey <api key>

     /\   |  __ \ / ____|
    /  \  | |  | | (___   ___ __ _ _ __  _ __   ___ _ __
   / /\ \ | |  | |\___ \ / __/ _ | '_ \| '_ \ / _ \ '__|
  / ____ \| |__| |____) | (_| (_| | | | | | | |  __/ |
 /_/    \_\_____/|_____/ \___\__,_|_| |_|_| |_|\___|_|

 [+] Version: 1.0.0 - 27/03/2024
 [+] Jack G (@rootjack) https://github.com/rootjaxk/ADScanner

[17:24:47 PM] Checking pre-requisites...
[17:24:51 PM] Starting scan of test.local...
```

## Example report 
Preview an example report of a very vulnerable directory [here](http://adscanner-rootjack.s3-website.eu-north-1.amazonaws.com/) and a default directory [here](https://adscanner-rootjack.s3.eu-north-1.amazonaws.com/ADScanner-lims.co.uk-26-04-2024.html).

![Report preview](https://raw.githubusercontent.com/rootjaxk/ADScanner/main/Private/Report/Images/report-preview.png)  

## Disclaimer
ADScanner is intended for use on authorised systems only. Users must obtain explicit consent from system owners before using the tool on any network or actions could lead to serious legal repercussions. The creator is not responsible nor liable for any resulting damages or losses. GPT remediation has been prompt engineered but steps are a best effort and should be checked before implementation. This has not been tested in production environments.

When producing the HTML report potentially sensitive vulnerability information will be sent to ChatGPT - this is a PoC tool. If you don't want to send information to GPT but still want to find vulnerabilities, run ADScanner with the `-format console` flag and don't specify an API key. 
```
Invoke-ADScanner -Domain test.local -Scans All -Format Console
```

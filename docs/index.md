# PowIRShell
PowerShell scripts useful for incident response and Active Directory auditing.

This is a collection of Powershell scripts which are useful for information security tasks. Currently the
main script Get-M365CompromiseInfo.  It takes Microsoft365 Unified Audit Log (UAL) files in JSON
format and looks up IP addresses using either IPInfo.io, Scamalytics, IPQualityScore, or all three.

## Quick start:
```
git clone https://github.com/PlacidSecurity/PowIRShell.git
cd PowIRShell
Import-Module .\M365CompromiseInfo.psd1
Install-module -Name ExchangeOnlineManagement # Must run PowerShell as admin, installs prerequisite. Hit Y then enter, then hit A then enter
Connect-ExchangeOnline -UserPrincipalName analyst@contoso.com
Get-M365UnifiedAuditLog -StartDate '09/14/2026' -EndDate '09/18/2026' -OutputDir C:\temp\365Comp\UAL
Get-M365CompromiseInfo -searchdir C:\temp\365Comp\UAL -outputDir C:\temp\365Comp\ -ipinfoLookup -ipinfoAPIKey '<IpInfoKeyHere>' -ScamalyticsLookup -scamalyticsAPIKey '<ScamalyticsKeyHere>'
```
The script will then start doing its work.  A gridview will appear, offering you the option of selecting IP addresses based on ASN, geo-ip lookup, etc.  If you pay for an IPQS license, this may not be necessary.  The grid allows you to weed out IP addresses to save time and money on threat intel lookups.

The grid looks like this.  Select your IPs, and click OK in the gridview.

![image](https://github.com/kgeil/PowIRShell/assets/10849557/a8663036-3901-40df-9bfb-3123e3790fe4)

**Caveat Emptor: The results of this script are only as good as your IP threat intel lookups. 
If you fail to select an IP in the gridview, it will not be checked!  Also, if a malicious IP 
comes through as non-malicious from scamalytics or IPQS, it will not be detected by the script.**

### Output:
The script will produce some log files, and two csv files: MaliciousLogons.csv, and MaliciousMailItemsAccessed.csv. These files contain event information for activities associated with malicious IPs detected by threat intel services.
![image](https://github.com/kgeil/PowIRShell/assets/10849557/af3ea276-50ec-48a9-94cb-9445d90e591a)


## Other stuff:

The script "PowerConTalk.ps1" is not really  a script, but rather  a series of useful commands.  The first section provides ideas for auditing Active Directory, and the second section is a walkthrough of a business email compromise investigation, using some of the scripts from this repository.

## Included scripts:

* Get-IPInfoLookup.ps1: Input: list of IP addresses separated by newlines. Output: Geo-ip and ASN info for each IP. IPInfo's API. API Key required.  Get it here: *https://ipinfo.io/*
* Get-IPQSLookup.ps1: Input: list of IP addresses separated by newlines. Output: IP Quality Score's threat intelligence information. API Key required. Get it here: *https://www.ipqualityscore.com/*
* Get-Scamalytics_lookup.ps1: Input: list of IP addresses separated by newlines. Output: Scamalytics threat intelligence information. API Key required. Get it here: *https://scamalytics.com/*
* Get-M365CompromiseInfo.ps1. Use PowerShell's built-in help for usage: Get-help &lt; path-to-script &gt; -ShowWindow
* PowerConTalk.ps1 Used to provide a live demo of some useful PowerShell techniques and some scripts from this repository.
* Get-Artifacts.ps1: Parses evtx files and returns output usful in incident response triage. Use PowerShell's built-in help for usage: Get-help &lt; path-to-script &gt; -ShowWindow.
* Get-emailInfoFromInternetMessageID.ps1 (Get-emailInformation): Takes a CSV of InternetMessageIds (such as MaliciousMailItemsAccessed.csv) and looks each email up in the victim's mailbox via Microsoft Graph, including Recoverable Items. Outputs sender, recipients, folder, attachment names, key headers (SPF/DKIM/DMARC, originating IP) and more to emaildetails.csv, and with -ExportEml saves each email as a .eml file with its SHA-256 hash. Requires an Entra app registration with the Mail.Read application permission. Use PowerShell's built-in help for usage: Get-Help Get-emailInformation -ShowWindow
* Resolve-Hostnames.ps1: *A work in progress*.  Takes a list of hostnames and returns A and AAAA records. 

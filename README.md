# PowIRShell
PowerShell scripts useful for incident response and Active Directory auditing.

This is a collection of Powershell scripts which are useful for information security tasks. Currently the
main script Get-M365CompromiseInfo.  It takes Microsoft365 Unified Audit Log (UAL) files in JSON
format and looks up IP addresses using either IPInfo.io, Scamalytics, IPQualityScore, or all three. API Keys for these services are required.

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

### Getting UAL data straight from your tenant:
If you don't already have UAL JSON exports on disk, `Get-M365UnifiedAuditLog` will pull them directly from Microsoft 365 and write them into the format `Get-M365CompromiseInfo` expects.
```
Connect-ExchangeOnline -UserPrincipalName analyst@contoso.com
Get-M365UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -OutputDir C:\temp\365Comp\UAL
Get-M365CompromiseInfo -searchdir C:\temp\365Comp\UAL\ -outputDir C:\temp\365Comp\ -ipinfoLookup -ipinfoAPIKey '<IpInfoKeyHere>'
```
Requires the `ExchangeOnlineManagement` module and a role that can read audit logs (Compliance Administrator, Security Reader, Global Reader, or View-Only Audit Logs). Use PowerShell's built-in help for full parameter details: `Get-Help Get-M365UnifiedAuditLog -ShowWindow`.

The grid looks like this.  Select your IPs, and click OK in the gridview.

![image](https://github.com/kgeil/PowIRShell/assets/10849557/a8663036-3901-40df-9bfb-3123e3790fe4)

**Caveat Emptor: The results of this script are only as good as your IP threat intel lookups. 
If you fail to select an IP in the gridview, it will not be checked!  Also, if a malicious IP 
comes through as non-malicious from scamalytics or IPQS, it will not be detected by the script.**

### Output:
The script will produce some log files, plus these CSVs: MaliciousActivities.csv, MaliciousLogons.csv, MaliciousFileOps.csv, and MaliciousMailItemsAccessed.csv (with Subject and SizeInBytes columns when the UAL record populates them). These files contain event information for activities associated with malicious IPs detected by threat intel services. A "Detection Rule Parameters" summary -- which lookups ran, the thresholds used, and the resulting bad-IP list -- prints to the console at the end of the run and is also appended to MaliciousActivities.csv.
![image](https://github.com/kgeil/PowIRShell/assets/10849557/af3ea276-50ec-48a9-94cb-9445d90e591a)

MailboxRuleActivity.csv is produced separately and is **not** filtered by IP reputation: it lists every New/Set/Remove/Enable/Disable-InboxRule and UpdateInboxRules event found in the UAL, with a `FromFlaggedIP` column noting whether that change also came from an IP in the bad-IP list. Mailbox rule tampering (auto-forwarding, auto-deleting, hiding mail) is a strong indicator of compromise on its own, so review these even when `FromFlaggedIP` is `False`.

### Microsoft IP allowlisting:
Before any threat-intel lookups or the gridview, IPs matching Microsoft's published Office 365 IP address ranges (Exchange Online / SharePoint Online / Skype for Business-Teams endpoints) are filtered out automatically -- a lot of UAL noise is Microsoft's own backend infrastructure (mail transport hops, Defender Safe Links/Safe Attachments scanning, etc.), not a real client. Excluded IPs are written to `MicrosoftAllowlistedIPs.txt` so nothing is silently dropped without a record. Use `-SkipMicrosoftAllowlist` to see every IP, unfiltered. See `Get-MicrosoftIPRanges` in `Get-IPAddressInfo.psm1` for details, including the deliberate choice to only trust Microsoft's first-party Office 365 ranges and not the broader `AzureCloud` tag (which also covers customer-leased VMs, including attacker-hosted ones).

### Entra OAuth / illicit consent grant hunting:
`Get-EntraOAuthGrantInventory` is a separate, standalone check against Microsoft Entra ID / Graph (not the M365 UAL): it inventories OAuth2 delegated permission grants and application (app-role) permission assignments tenant-wide, flags risky/tenant-wide/unverified-publisher/external grants, and optionally correlates against directory audit log consent events. Illicit OAuth consent grants are a well-known way an attacker keeps mailbox/data access after a password reset (MITRE T1528), so this is worth running against the affected user -- and the tenant broadly -- as a companion to the UAL-based BEC checks above. Requires the Microsoft.Graph.Authentication/Applications/Identity.SignIns/Users modules (checked at runtime, not a hard dependency of the rest of this module) and a role that can read directory/application data (e.g. Global Reader, Security Reader, or Cloud Application Administrator). Use PowerShell's built-in help for full parameter details: `Get-Help Get-EntraOAuthGrantInventory -ShowWindow`.


## Other stuff:

The script "PowerConTalk.ps1" is not really  a script, but rather  a series of useful commands.  The first section provides ideas for auditing Active Directory, and the second section is a walkthrough of a business email compromise investigation, using some of the scripts from this repository.

## Included scripts:

* Get-IPInfoLookup.ps1: Input: list of IP addresses separated by newlines. Output: Geo-ip and ASN info for each IP. IPInfo's API. API Key required.  Get it here: *https://ipinfo.io/*
* Get-IPQSLookup.ps1: Input: list of IP addresses separated by newlines. Output: IP Quality Score's threat intelligence information. API Key required. Get it here: *https://www.ipqualityscore.com/*
* Get-Scamalytics_lookup.ps1: Input: list of IP addresses separated by newlines. Output: Scamalytics threat intelligence information. API Key required. Get it here: *https://scamalytics.com/*
* Get-M365CompromiseInfo.ps1. Use PowerShell's built-in help for usage: Get-help &lt; path-to-script &gt; -ShowWindow
* Get-M365UnifiedAuditLog.ps1: Pulls UAL events directly from your M365 tenant via Search-UnifiedAuditLog and writes them out in the JSON format Get-M365CompromiseInfo expects, so you can skip a separate extraction tool. Requires the ExchangeOnlineManagement module and an active Connect-ExchangeOnline session. Use PowerShell's built-in help for usage: Get-help &lt; path-to-script &gt; -ShowWindow
* PowerConTalk.ps1 Used to provide a live demo of some useful PowerShell techniques and some scripts from this repository.
* Get-Artifacts.ps1: Parses evtx files and returns output usful in incident response triage. Use PowerShell's built-in help for usage: Get-help &lt; path-to-script &gt; -ShowWindow.
* Get-EntraOAuthGrantInventory.ps1: Read-only inventory of OAuth2 delegated permission grants and application (app-role) permission assignments in a Microsoft Entra ID tenant, with risk flagging (MITRE T1528 illicit-consent-grant hunting) and JSON/XML/CSV output. Use PowerShell's built-in help for usage: Get-help &lt; path-to-script &gt; -ShowWindow.
* Resolve-Hostnames.ps1: *A work in progress*.  Takes a list of hostnames and returns A and AAAA records. 

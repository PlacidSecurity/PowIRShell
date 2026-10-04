function Get-M365CompromiseInfo {
<#

.Synopsis 
  This script parses Microsoft365 unified audit logs (UAL) in JSON format. If a 
  list of suspicious IP addresses is provided with the badiplist parameter, the 
  script will parse the UAL for events originating from those IP addresses, and 
  export pertinent forensic information.  
  **NB: Unless you use the badiplist parameter, an API key for at least one of 
  these services is required: IP QualityScore, IPInfo.io, or Scamalytics.com.
  **NB: The malicious activity detected by this script is entirely dependent on
  either a list of known-bad IP addresses, or the results of the IP threat intel.
 
  The easiest way to get input for this script is Get-M365UnifiedAuditLog (included
  in this module), which pulls UAL events directly from your tenant via
  Search-UnifiedAuditLog and writes them in the JSON format this script expects --
  no separate tool required. Alternatively, you can retrieve JSON output from the
  Invictus Extractor Suite: https://github.com/invictus-ir/Microsoft-Extractor-Suite.
  The script will work with M365 logs in JSON format regardless of how they are 
  extracted. If, for example, you have CSV output, you can use the AuditData field,
  which is json.
  

.Description
  This script parses Microsoft365 Unified Audit Logs (UAL) (JSON FORMAT ONLY). If a list of bad IP addresses is provided with the
  badiplist parameter, the script will parse the UAL for events originating from those IP addresses, and export pertinent 
  information to a CSV file. If you have a subscription for IPQualityScore, simply provide it in the ipqsAPIKey parameter, and
  the script will query IPQualityScore for each IP address in the UAL, and will consider any IP address with a fraud score of 75 or
  higher to be malicious.

  If you need to use the free IPQualityScore API, the best approach is to use the ipinfolookup switch parameter, which will
  run your IP addresses through the IPInfo.io API, and present a gridview to the user in which you should check the information,
  select suspicious entries (Based on geography or ASN) using the control key, and click OK, after which the script will either use that 
  list as the suspect IP list, or if you select the ipqslookup switch parameter, it will pass the list to the Get-IPQSLookup 
  function, again, regarding any IP address with a fraud score of 75 or higher to be malicious.  
  Please see individual function help for these by invoking: get-help Get-IPQSLookup -showwindow. 

  If the ipinfolookup switch parameter is specified, the script will retrieve all IP addresses from the M365 JSON files,
  and run them through the IPInfo.io API, then present a grid-view to the user in which you should check the information,
  and select suspicious entries. This creates a suspectIP list, which is passed to the next IP threat
  intelligence lookup function, either Get-IPQSLookup, or Get-ScamalyticsInfo, or both, if specified. 
  If you don't have a paid subscription to IPQualityScore, my recommendation is to start with ipinfolookup, 
  and try to get the number of IPs down to 199 or fewer, then specify the IPQSLookup switch parameter.
  The suspectIP list will be passed to the Get-IPQSLookup function. The script creates a badip list containing any IP
  with an IPQS fraud score of 75 or greater. The fraud score threshold is adjustable with the fraudscorethreshold parameter.
  This suspect IP list will then be used to parse the UAL for events associated
  with the IP addresses in the badIP list. The scamalyticsLookup function can be used as well, although
  it's not as useful as IPQS. The scamalyticsLookup function creates the badIP list with any address
  with a scamalytics risk score of anything other than "low".

  The script will output three CSV files: MaliciousActivities.csv, MaliciousLogons.csv, and MaliciousFileOps.csv.
  MaliciousActivities.csv will contain all events from the UAL that originated from the IP addresses in the badIPList.
  MaliciousLogons.csv will contain all logon events from the UAL that originated from the IP addresses in the badIPList.
  MaliciousFileOps.csv will contain all file operations from the UAL that originated from the IP addresses in the badIPList.
  A future iteration of this script will put them all in an excel spreadsheet.

.Parameter Searchdir
  Specifies the directory containing stored json files. Get-M365UnifiedAuditLog (or the Invictus Extractor Suite) will create multiple json files here. 
  ** NB Currently, you need to include the trailing slash at the end of the dir. This will be fixed in a future update.

.Parameter Outputpath
  Specifies path for exported event data. Output will be a file named MaliciousActivities.csv in the specified
  directory.

.Parameter ipinfolookup
  *API KEY FOR IPinfo.io REQUIRED* This is a switch that will retrieve all IP addresses from the M365 
  JSON files, and run them through the IPInfo.io API, then present
  a grid-view to the user in which you should check the information,
  select suspicious entries using the control key, and click OK. After this, 
  the script will either use that list as the suspect IP list, 
  or pass it along to the next IP lookup function, either Get-IPQSLookup,
  or Get-ScamalyticsInfo. Please see individual function help for these by 
  invoking: get-help Get-IPQSLookup -showwindow after the module is imported.

.Parameter IPQSLookup
  *IPQualityScore API KEY REQUIRED* Switch parameter that passes IP
  Addresses through the IP QUality Score database. This is the 
  best ip threatintel I have used (as of 10/21/2023), but the free
  API is limited to 200, and the commercial service is pretty
  expensive for my needs.  If you want to limit lookups, use the
  ipinfolookup  parameter as well.

.Parameter ScamalyticsLookup
  *SCAMALYTICS API KEY REQUIRED* Switch parameter which passes IPAddresses through
   the scamalytics IP lookup service.  Their data was a bit unreliable in August
   2023, it appears as if they have their problems sorted.  This script considers
   any IP address with a risk score of anything other than "low" to be malicious.
   This is likely too aggressive, but it's a good starting point, especially if you
   run the ipqualityscore parameter.


.paramater allLookups
    API KEYS FOR IPinfo.io, IPQualityScore, and Scamalytics REQUIRED* This is a switch that will run IP addresses
    through all three services, and create a badIP list based on the results.  This is the best way to go if you have a 
    free API keys and a significant number of events. 


.Parameter badIPList
  Carriage-return separated list of IP addresses deemed to be bad.

.PARAMETER fraudScoreThreshold
    Specifies the fraud score threshold for IPQS.  Default is 75.
    This is the threshold for considering an IP address to be malicious.
    It's worth reading the IPQS documentation:
    https://www.ipqualityscore.com/documentation/fraud-prevention-scoring

.PARAMETER SkipMicrosoftAllowlist
    By default, IPs belonging to Microsoft's own first-party service ranges
    (Microsoft's published Office 365 IP address ranges -- Exchange Online,
    SharePoint Online, Skype for Business/Teams endpoints) are filtered out of
    the unique-IP list
    before any threat-intel lookups or the gridview, since these are commonly
    Microsoft's own backend infrastructure (mail transport hops, Defender Safe
    Links/Safe Attachments scanning, Substrate, etc.) rather than a real client.
    Specify this switch to disable that filtering and see every IP, unfiltered.
    See Get-MicrosoftIPRanges (in Get-IPAddressInfo.psm1) for details and caveats.

  .Example
  C:\Scripts\PowIRShell\Get-M365CompromiseInfo.ps1 -searchdir C:\Scripts\PowIRShell\Test_data\M365Output\UnifiedAuditLog\20231012092146\ -outputDir C:\Temp\365Results -ipinfoLookup -ipinfoAPIKey <ipinfoAPIKey> -IPQSLookup -ipqsAPIKey "<IPQSAPIKey>" -ScamalyticsLookup -scamalyticsAPIKey "<ScamalyticsAPIKey>" -Verbose

  .Inputs
  UAL (Unified Audit Logs) from Microsoft 365 tenant. Use Get-M365UnifiedAuditLog
   (included in this module) to pull these directly, or the Invictus Extractor
   Suite: https://github.com/invictus-ir/Microsoft-Extractor-Suite

.Outputs
  CSV files containing evnts of interest from the forensic perspective:
  MaliciousActivities.csv, MaliciousLogons.csv, MaliciousMailItemsAccessed.csv,
  MaliciousFileOps.csv, and MailboxRuleActivity.csv.

  MaliciousMailItemsAccessed.csv includes Subject and SizeInBytes columns when the
  UAL record populates them (not guaranteed for every record/tenant/audit config).

  MaliciousFileOps.csv includes a LikelyBenignReason column. A file operation
  with Platform "Wac" (edited via Office Online in-browser) always shows
  Office Online's own backend IP rather than the user's real IP, so these get
  labeled with an explanation rather than silently dropped -- the row stays in
  the CSV either way. A blank LikelyBenignReason means no known-benign pattern
  matched.

  MailboxRuleActivity.csv covers New-InboxRule, Set-InboxRule, Remove-InboxRule,
  Enable-InboxRule, Disable-InboxRule, and UpdateInboxRules events -- a classic
  post-compromise persistence/exfil technique (auto-forwarding, auto-deleting, or
  hiding incoming mail). Unlike the other CSVs, this one is NOT filtered by IP
  reputation: every mailbox rule change in the UAL is included, with a
  FromFlaggedIP column noting whether the change also came from an IP in the
  bad-IP list. A rule change from an IP your threat intel hasn't flagged is still
  worth reviewing -- don't assume FromFlaggedIP = False means benign.

  Unless -SkipMicrosoftAllowlist is specified, IPs matching Microsoft's own
  Office365 service ranges are removed from the unique-IP list before any
  threat-intel lookups or the gridview -- these are typically Microsoft's own
  backend infrastructure, not a real client. Excluded IPs are written to
  MicrosoftAllowlistedIPs.txt so nothing is silently dropped without a record.

  At the end of the run, a "Detection Rule Parameters" summary -- which lookups ran,
  the thresholds/criteria applied (e.g. IPQS fraud_score threshold, the Scamalytics
  risk rule), the resulting bad-IP list, and the mailbox rule operations monitored --
  is written to the console and appended as a comment-prefixed block at the bottom
  of MaliciousActivities.csv, for reproducibility and reporting.

#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$searchdir,
    [Parameter(Mandatory = $true)]
    [string]$outputDir,
    #[array]$ipListArray,
    [string]$badIPList,
    [switch]$ipinfoLookup,
    [switch]$IPQSLookup,
    [switch]$ScamalyticsLookup,
    [switch]$allLookups, # requires three API keys: ipinfo, ipqs, and scamalytics.
    [string]$ipinfoAPIKey,
    [string]$ipqsAPIKey,
    [string]$scamalyticsAPIKey,
    [int]$fraudScoreThreshold = 75,
    [switch]$SkipMicrosoftAllowlist
)
$ErrorActionPreference = "Stop"
function Confirm-apikeys{

    if ($ScamalyticsLookup){
        if(!$scamalyticsAPIKey){
            Write-Host "Scamalytics API key required when using scamalyticsLookup  Exiting." -ForegroundColor Red
            Write-Host "Go get one: https://scamalytics.com/ip/api/enquiry?monthly_api_calls=5000" -ForegroundColor Yellow
            break
        }
    }
    
    if ($ipinfoLookup){
        if(!$ipinfoAPIKey){
            Write-Host "ipinfo API key required when using ipinfoLookup  Exiting." -ForegroundColor Red
            Write-Host "Go get one: https://ipinfo.io/signup" -ForegroundColor Yellow
            break
        }
    }
    
    if ($IPQSLookup){
        if(!$ipqsAPIKey){
            Write-Host "IPQS API key required when using IPQSLookup  Exiting." -ForegroundColor Red
            Write-Host "Go get one: https://www.ipqualityscore.com/create-account" -ForegroundColor Yellow
            break
        }
    }
}
Confirm-apikeys #function to ensure that API keys are provided if needed.
Function Update-Progress($currentCount, $totalCount, $activity, $status) {
    $percentComplete = ($currentCount / $totalCount) * 100
    if ($percentComplete -gt 100) {
        $percentComplete = 100
    }
    Write-Progress -Activity $activity -Status "$currentCount out of $totalCount $status have been processed" -PercentComplete $percentComplete
}
if (Get-Module -Name "M365CompromiseInfo") {
    Write-Host "Module M365CompromiseInfo is installed. Continuing..."
} else {
    Write-Host "Module M365CompromiseInfo is not installed." -ForegroundColor Yellow
    Write-Host " * Please install the M365CompromiseInfo.psd1 file"
    Write-Host " * By invoking import-module Path/To/Module/M365CompromiseInfo.psd1"
    Write-Host " * It is in the top level directory of the PowIRShell repository"
    Write-Host "Exiting"
    return
}


$Logevents = Get-AuditdataFrom365JSON -searchdir $searchdir
Write-Host There are: $Logevents.count Events -ForegroundColor Green
$tenPercent = "{0:N0}" -f ($Logevents.count/10)
Write-Host "TenPercent: $tenPercent Progress bar will update every $tenPercent events" -ForegroundColor Green
$increment = $tenPercent
$counter = 1


$badip = @()
if($badIPList){$badip = Get-Content $badIPList}
$iplist =  Get-UniqueIPs -auditevents $Logevents # this is not necessary if a badiplist is provided

if (-not $SkipMicrosoftAllowlist -and $iplist.Count -gt 0) {
    $msftRanges = Get-MicrosoftIPRanges
    if ($msftRanges.Count -gt 0) {
        $msftAllowlistedIPs = @()
        $filteredIplist = @()
        foreach ($ip in $iplist) {
            if (Test-IPInAnyCIDR -IPAddress $ip -CIDRRanges $msftRanges) {
                $msftAllowlistedIPs += $ip
            } else {
                $filteredIplist += $ip
            }
        }
        if ($msftAllowlistedIPs.Count -gt 0) {
            $msftAllowlistedIPs | Out-File $outputDir\MicrosoftAllowlistedIPs.txt -Encoding ascii -Force
            Write-Host "Excluded $($msftAllowlistedIPs.count) Microsoft-owned IP(s) from the lookup/gridview list -- see MicrosoftAllowlistedIPs.txt. Use -SkipMicrosoftAllowlist to disable this." -ForegroundColor Cyan
        }
        $iplist = $filteredIplist
    }
}



#debugging to ensure that $iplist is an array containing IP addresses only.
$iplist | out-file $outputdir\iplist.txt -Encoding ascii -Force
$suspectip = @()


    function Get-MailItemsAccessedInfo {
      <#
    .SYNOPSIS
        Retrieves "Folder" and "OperationProperties" information for the UAL MailItemsAccessed
        events.
    .INPUTS
        The "Folders" attribute of the UAL MailItemsAccessed events.
        for example:, $event.Folders (assuming MailItemsAccessed event)
    .OUTPUTS
        A PSObject with the following properties:
            - Id
            - Path
            - InternetMessageId
            - Subject (when present -- not every tenant/audit config populates this on
              every FolderItem, so treat a blank Subject as "unknown", not "no subject")
            - SizeInBytes
    #>
        param (
            [Parameter(Mandatory=$true)]
            [object]$MailItemsAccessedEvent
        )

        $result = @()

        $operationProperties = @{}
        foreach ($property in $MailItemsAccessedEvent.OperationProperties) {
            $operationProperties[$property.Name] = $property.Value
        }

        foreach ($folder in $MailItemsAccessedEvent.Folders) {
            foreach ($item in $folder.FolderItems) {
                $result += New-Object PSObject -Property @{
                    InternetMessageId = $item.InternetMessageId
                    Id = $folder.Id
                    Path = $folder.Path
                    MailAccessType = $operationProperties['MailAccessType']
                    IsThrottled = $operationProperties['IsThrottled']
                    Subject = $item.Subject
                    SizeInBytes = $item.SizeInBytes
                }
            }
        }

        return $result
    }

    function Get-MailboxRuleInfo {
      <#
    .SYNOPSIS
        Extracts the cmdlet parameters (rule name, forwarding/redirect targets, delete/move
        actions, etc.) from a mailbox-rule UAL event (New-InboxRule, Set-InboxRule, etc.).
    .INPUTS
        A UAL event whose Operation is a mailbox-rule cmdlet. The parameters passed to that
        cmdlet are recorded in the event's "Parameters" property as an array of Name/Value pairs.
    .OUTPUTS
        A PSObject summarizing the rule's key properties, plus every parameter passed, joined
        as a single string so nothing is missed even if Microsoft adds new parameters later.
    #>
        param (
            [Parameter(Mandatory=$true)]
            [object]$RuleEvent
        )

        $ruleParams = @{}
        foreach ($param in $RuleEvent.Parameters) {
            $ruleParams[$param.Name] = $param.Value
        }

        return [PSCustomObject]@{
            RuleName                     = $ruleParams['Name']
            ForwardTo                    = $ruleParams['ForwardTo']
            ForwardAsAttachmentTo        = $ruleParams['ForwardAsAttachmentTo']
            RedirectTo                   = $ruleParams['RedirectTo']
            DeleteMessage                = $ruleParams['DeleteMessage']
            MoveToFolder                 = $ruleParams['MoveToFolder']
            MarkAsRead                   = $ruleParams['MarkAsRead']
            StopProcessingRules          = $ruleParams['StopProcessingRules']
            AlwaysDeleteOutlookRulesBlob = $ruleParams['AlwaysDeleteOutlookRulesBlob']
            AllParameters                = (($RuleEvent.Parameters | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; ')
        }
    }

    function Get-EventIPAddress {
      <#
    .SYNOPSIS
        Resolves the source IP address for a UAL event, regardless of which field
        that record type happens to use.
    .DESCRIPTION
        Different UAL record types put the client/actor IP in different fields.
        Mail, file, and login-type events generally populate ClientIPAddress and/or
        ActorIPAddress, while admin/cmdlet-type records (e.g. New-InboxRule) instead
        use ClientIP, often as "1.2.3.4:port". Rather than repeating this fallback
        chain at every call site (which is what led to the New-InboxRule detection
        bug), this function centralizes it: it checks ClientIPAddress, then
        ActorIPAddress, then ClientIP, in that order, and returns the first one that
        Get-IPAddress can actually parse an IP out of.
    .INPUTS
        A single UAL event object (from Get-AuditdataFrom365JSON).
    .OUTPUTS
        The event's IP address as a string, or $null if none of the known fields
        contained a parseable IP.
    .EXAMPLE
        Get-EventIPAddress -UalEvent $evt
    #>
        param (
            [Parameter(Mandatory=$true)]
            [object]$UalEvent
        )
        $ip = Get-IPAddress -ipField $UalEvent.ClientIPAddress
        if ($ip) { return $ip }
        $ip = Get-IPAddress -ipField $UalEvent.ActorIPAddress
        if ($ip) { return $ip }
        $ip = Get-IPAddress -ipField $UalEvent.ClientIP
        if ($ip) { return $ip }
        return $null
    }

    function Get-LikelyBenignReason {
      <#
    .SYNOPSIS
        Flags UAL events that match a known, well-documented benign pattern,
        even though they came from a flagged IP.
    .DESCRIPTION
        The row this is attached to still ends up in the CSV -- nothing is
        hidden or removed -- this just adds a short explanation so you don't
        have to re-derive "oh, that's just WAC" every time it comes up.

        Currently recognizes one pattern: a file operation with Platform "Wac"
        (Office Online Server -- the doc was edited in-browser rather than
        with a desktop client). SharePoint/OneDrive records WAC's own backend
        IP as the "client" for these, not the end user's real IP, so the IP on
        this record doesn't tell you who was actually behind the browser. That
        distinction matters even though it's likely benign: a compromised
        account editing a file this way produces an identical-looking record,
        so this only ever adds a label -- it never changes FromFlaggedIP-style
        detection or removes the row. Check the account's sign-in events for
        the actual source if that matters for your investigation.
    .INPUTS
        A single UAL event object.
    .OUTPUTS
        A short explanation string if a known-benign pattern matched,
        otherwise $null.
    .EXAMPLE
        Get-LikelyBenignReason -UalEvent $evt
    #>
        param (
            [Parameter(Mandatory=$true)]
            [object]$UalEvent
        )
        if ($UalEvent.Platform -eq 'Wac') {
            return "Office Online (WAC) backend IP -- not the user's real client IP. Check sign-in events for this user/time instead."
        }
        return $null
    }

function Get-M365CompromiseResults {
    param (
        [array]$Logevents
        ,[array]$badip
        ,[string]$outputDir
    )
    $loginevents = @("UserLoggedIn", "UserLoginFailed")
    $fileEvents = @("FileAccessed","FileAccessedExtended","FileCheckedIn","FileCheckedOut","FileCopied","FileDownloaded","FileModified","FileModifiedExtended","FileMoved","FilePreviewed","FileRecycled","FileRenamed","FileSyncDownloadedFull","FileSyncUploadedFull","FileUploaded")
    # Mailbox rule cmdlets -- classic post-compromise persistence/exfil technique (auto-forward,
    # auto-delete, or hide incoming mail). Checked below on EVERY event, not just ones from IPs
    # already flagged malicious: a rule change is itself a strong indicator of compromise, and
    # gating it behind IP reputation would miss rules created from an IP your threat intel
    # lookups haven't (yet) flagged.
    $mailboxRuleOperations = @("New-InboxRule","Set-InboxRule","Remove-InboxRule","Enable-InboxRule","Disable-InboxRule","UpdateInboxRules")
    $maliciousFileops=@()
    $maliciousLogins=@()
    $maliciousMailItemsAccessed=@()
    $mailboxRuleActivity=@()
    [array]$maliciousActivities=@()
    Write-Host "Starting to check logs for malicious activity..." -ForegroundColor Green


    Foreach($evt in $Logevents){
        if($evt.Operation -in $mailboxRuleOperations){
            $ruleInfo = Get-MailboxRuleInfo -RuleEvent $evt
            $ipInBadList = (Get-EventIPAddress -UalEvent $evt) -in $badip
            $arrayitems = [PSCustomObject]@{
                'CreationTime'          = $evt.CreationTime
                'UserId'                = $evt.UserId
                'ClientIP'              = $evt.ClientIP
                'Operation'             = $evt.Operation
                'MailboxOwnerUPN'       = $evt.MailboxOwnerUPN
                'FromFlaggedIP'         = $ipInBadList
                'RuleName'              = $ruleInfo.RuleName
                'ForwardTo'             = $ruleInfo.ForwardTo
                'ForwardAsAttachmentTo' = $ruleInfo.ForwardAsAttachmentTo
                'RedirectTo'            = $ruleInfo.RedirectTo
                'DeleteMessage'         = $ruleInfo.DeleteMessage
                'MoveToFolder'          = $ruleInfo.MoveToFolder
                'MarkAsRead'            = $ruleInfo.MarkAsRead
                'StopProcessingRules'   = $ruleInfo.StopProcessingRules
                'AllParameters'         = $ruleInfo.AllParameters
            }
            $mailboxRuleActivity += $arrayitems
            Write-Host "Mailbox rule activity detected: $($evt.Operation) '$($ruleInfo.RuleName)' by $($evt.UserId)" -ForegroundColor Magenta
        }
        if((Get-EventIPAddress -UalEvent $evt) -in $badip){
            #Write-Host "Debug: IP IN BADIP: $($evt.ClientIPAddress)" -ForegroundColor Yellow
            $applicationName = Get-M365ApplicationNameFromAppID  -applicationID $evt.ApplicationId
            if($evt.Operation -in $loginevents ){
                foreach($extendedProperty in $evt.ExtendedProperties){
                    if ($extendedProperty.Name -eq "UserAgent") {
                        $userAgent = $extendedProperty.Value
                        $userAgent = $userAgent.replace(',','-')
                    }
                    if ($extendedProperty.Name -eq "RequestType") {
                        $requestType = $extendedProperty.Value
                    }
                    if ($extendedProperty.Name -eq "ResultStatusDetail") {
                        $ResultStatusDetail = $extendedProperty.Value
                    }
                    if ($extendedProperty.Name -eq "UserAuthenticationMethod") {
                        $userAuthenticationMethod = $extendedProperty.Value
                    }
                } #end foreach in extended property

                $arrayitems = [PSCustomObject]@{
                    'CreationTime' = $evt.CreationTime
                    'UserId' = $evt.UserId
                    'ActorIpAddress' = $evt.ActorIpAddress
                    'ClientIPAddress' = $evt.ClientIPAddress
                    'Operation' = $evt.Operation
                    'AzureADEventType' = $evt.AzureActiveDirectoryEventType
                    'ApplicationId' = $evt.ApplicationId
                    'ApplicationName' = $applicationName
                    'UserAgent' = $userAgent
                    'UserAuthMethod' = $userAuthenticationMethod
                    'RequestType' = $requestType
                    'ResultStatusDetail' = $ResultStatusDetail
                }
                $maliciousLogins += $arrayitems
            } # end if $evt.operation in $loginevents

            elseif($evt.Operation -in $fileEvents ){
                if($evt.userAgent){
                    $userAgent = $evt.UserAgent.replace(",","-")
                }
                $arrayitems= [PSCustomObject]@{
                    'CreationTime' = $evt.CreationTime
                    'UserId' = $evt.UserId
                    'ClientIPAddress' = $evt.ClientIPAddress
                    'Operation' = $evt.Operation
                    'AuthenticationType' = $evt.AuthenticationType
                    'ObjectId' = $evt.ObjectId
                    'Platform' = $evt.Platform
                    'SourceFileName' = $evt.SourceFileName
                    'DeviceDisplayName' = $evt.DeviceDisplayName
                    'UserAgent' = $userAgent
                    'LikelyBenignReason' = Get-LikelyBenignReason -UalEvent $evt
                }
                $maliciousFileops += $arrayitems
                Write-Verbose "Added object to maliciousFileops array: $arrayitems"
            } #end elseif $evt.operation in $fileEvents
            #region
            elseif($evt.Operation -eq "MailItemsAccessed" ){
                $mailitemsaccessedInfo = Get-MailItemsAccessedInfo -MailItemsAccessedEvent $evt
                if ($evt.ClientInfoString) {
                    $ClientInfoString = $evt.ClientInfoString.replace(',','-')
                }
                foreach($item in $mailitemsaccessedInfo){
                    $arrayitems = [PSCustomObject]@{
                        'CreationTime' = $evt.CreationTime
                        'UserId' = $evt.UserId
                        'ClientIPAddress' = $evt.ClientIPAddress
                        'Operation' = $evt.Operation
                        'ApplicationId' = $evt.AppID
                        'ApplicationName' = $applicationName
                        'ClientInfoString' = $ClientInfoString
                        'MailAccessType' = $item.MailAccessType
                        'IsThrottled' = $item.IsThrottled
                        'InternetMessageId' = $item.InternetMessageId
                        'Subject' = $item.Subject
                        'SizeInBytes' = $item.SizeInBytes
                        'Id' = $item.Id
                        'Path' = $item.Path
                    }
                    $maliciousMailItemsAccessed += $arrayitems
                } #end foreach $item in $mailitemsaccessedInfo
            }


            else{
                $arrayitems = [PSCustomObject]@{
                    'CreationTime' = $evt.CreationTime
                    'UserId' = $evt.UserId
                    'ActorIpAddress' = $evt.ActorIpAddress
                    'ClientIPAddress' = $evt.ClientIPAddress
                    'Operation' = $evt.Operation
                    'ApplicationId' = $evt.ApplicationId
                    'ApplicationName' = $applicationName
                }


                    $maliciousActivities += $arrayitems
 

            } #end else which populates $maliciousActivities
            #endregion
        }
        #Write-Host "Malicious activities: $maliciousActivities"
        $counter++
        if($counter % $increment -eq 0){
            Update-Progress -currentCount $counter -totalCount $Logevents.count -activity "Processing events" -status "events"
            $tenPercent = $tenPercent + $increment
        }

    } #end foreach $evt in $Logevents
    #$maliciousActivities | Export-Csv $outputDir\MaliciousActivities.csv -NoTypeInformation -Encoding UTF8 -Force
    Write-Host "Count of malicious logins: $($maliciousLogins.count)"
    Write-Host "Count of malicious fileops: $($maliciousFileops.count)"
    $likelyBenignFileopsCount = ($maliciousFileops | Where-Object { $_.LikelyBenignReason }).Count
    if ($likelyBenignFileopsCount -gt 0) {
        Write-Host "  -> $likelyBenignFileopsCount flagged as likely-benign -- see LikelyBenignReason column in MaliciousFileOps.csv" -ForegroundColor DarkYellow
    }
    Write-Host "Count of malicious activities: $($maliciousActivities.count)"
    Write-Host "Count of malicious mail items accessed: $($maliciousMailItemsAccessed.count)"
    Write-Host "Count of mailbox rule changes detected: $($mailboxRuleActivity.count)"
    try {
        if ($maliciouslogins.count -gt 0){
            $maliciousLogins | Export-Csv $outputDir\MaliciousLogons.csv -NoTypeInformation -Encoding UTF8 -Force
        }
    }
    catch{
        Write-Host "Could not export malicious logins to CSV file" -ForegroundColor Red
        Write-Host $error[0].Exception -ForegroundColor Red
    }
    try {
        if ($mailboxRuleActivity.count -gt 0){
            $mailboxRuleActivity | Export-Csv $outputDir\MailboxRuleActivity.csv -NoTypeInformation -Encoding UTF8 -Force
            Write-Host "Wrote mailbox rule activity to $outputDir\MailboxRuleActivity.csv -- review this even if FromFlaggedIP is False." -ForegroundColor Magenta
        }
    }
    catch{
        Write-Host "Could not export mailbox rule activity to CSV file" -ForegroundColor Red
        Write-Host $error[0].Exception -ForegroundColor Red
    }
    try {
        if ($maliciousFileops.count -gt 0){
            $maliciousFileops | Export-Csv $outputDir\MaliciousFileOps.csv -NoTypeInformation -Encoding UTF8 -Force
        } 
    }
    catch{
        Write-Host "Could not export malicious fileops to CSV file" -ForegroundColor Red
        Write-Host $error[0].Exception -ForegroundColor Red
    }
    try{
        if ($maliciousMailItemsAccessed.count -gt 0){
            $maliciousMailItemsAccessed | Export-Csv $outputDir\MaliciousMailItemsAccessed.csv -NoTypeInformation -Encoding UTF8 -Force
        }
    }
    catch{
        Write-Host "Could not export malicious mail items accessed to CSV file" -ForegroundColor Red
        Write-Host $error[0].Exception -ForegroundColor Red
    }
    try {
        if ($maliciousActivities.count -gt 0){
            $maliciousActivities | Export-Csv $outputDir\MaliciousActivities.csv -NoTypeInformation -Encoding UTF8 -Force
        } 
    }
    catch{
        Write-Host "Could not export malicious activities to CSV file" -ForegroundColor Red
        Write-Host $error[0].Exception -ForegroundColor Red
    }

    # --- Detection rule / parameter summary ---------------------------------
    # Documents exactly what criteria were used to flag IPs and events as
    # malicious in this run -- which lookups ran, the thresholds applied, and
    # the resulting bad-IP list -- for reproducibility and reporting.
    $ruleSummary = [ordered]@{
        'Run Timestamp'              = (Get-Date -Format 'u')
        'Search Directory'           = $searchdir
        'Output Directory'           = $outputDir
        'Total UAL Events Processed' = $Logevents.Count
        'ipinfoLookup Used'          = [bool]$ipinfoLookup
        'IPQSLookup Used'            = [bool]$IPQSLookup
        'ScamalyticsLookup Used'     = [bool]$ScamalyticsLookup
        'allLookups Used'            = [bool]$allLookups
        'BadIPList File Provided'    = [bool]$badIPList
        'BadIPList Path'             = $(if ($badIPList) { $badIPList } else { 'N/A' })
        'IPQS Fraud Score Threshold' = $(if ($IPQSLookup -or $allLookups) { $fraudScoreThreshold } else { 'N/A (IPQS not used)' })
        'IPQS Rule'                  = $(if ($IPQSLookup -or $allLookups) { "IP flagged malicious if fraud_score -ge $fraudScoreThreshold" } else { 'N/A (IPQS not used)' })
        'Scamalytics Rule'           = $(if ($ScamalyticsLookup -or $allLookups) { "IP flagged malicious if risk -ne 'low'" } else { 'N/A (Scamalytics not used)' })
        'Malicious IP Count'         = $badip.Count
        'Malicious IPs'              = ($badip -join '; ')
        'Malicious Logins Found'     = $maliciousLogins.Count
        'Malicious File Ops Found'   = $maliciousFileops.Count
        'Likely-Benign File Ops'     = ($maliciousFileops | Where-Object { $_.LikelyBenignReason }).Count
        'Malicious Mail Items Found' = $maliciousMailItemsAccessed.Count
        'Malicious Other Activities' = $maliciousActivities.Count
        'Mailbox Rule Operations Monitored' = ($mailboxRuleOperations -join ', ')
        'Mailbox Rule Changes Found' = $mailboxRuleActivity.Count
        'Mailbox Rule Rule'          = 'Every New/Set/Remove/Enable/Disable-InboxRule and UpdateInboxRules event is flagged, regardless of source IP reputation'
    }

    Write-Host ""
    Write-Host "===== Detection Rule Parameters =====" -ForegroundColor Cyan
    foreach ($key in $ruleSummary.Keys) {
        Write-Host ("  {0,-28}: {1}" -f $key, $ruleSummary[$key]) -ForegroundColor Yellow
    }
    Write-Host "======================================" -ForegroundColor Cyan

    # Also append the same summary to MaliciousActivities.csv, as a clearly
    # delimited, comment-prefixed block below the event rows. It's kept as
    # plain lines rather than extra CSV columns, since mixing per-event data
    # with run-level metadata in the same columns would be misleading -- most
    # CSV readers (Excel included) will just show these as trailing text rows.
    try {
        $csvPath = Join-Path $outputDir 'MaliciousActivities.csv'
        Add-Content -Path $csvPath -Value ""
        Add-Content -Path $csvPath -Value "# ===== Detection Rule Parameters ====="
        foreach ($key in $ruleSummary.Keys) {
            Add-Content -Path $csvPath -Value "# ${key}: $($ruleSummary[$key])"
        }
        Add-Content -Path $csvPath -Value "# ======================================"
    }
    catch {
        Write-Host "Could not append rule summary to MaliciousActivities.csv" -ForegroundColor Red
        Write-Host $error[0].Exception -ForegroundColor Red
    }

} #end function Get-M365CompromiseResults


if($badIPList){
    try{
        $badip = Get-Content $badIPList -ErrorAction Stop
        Write-Host "Bad IP list imported successfully" -ForegroundColor Green
        Write-Verbose "Debug:  $badip" #-ForegroundColor Yellow
    }
    catch{
        Write-Host "*** Could not import bad ip list" -ForegroundColor Red
        Write-Host $error[0].Exception -ForegroundColor Red
        Write-Host "Exiting"
        Exit-PSSession

    }
}
if($ScamalyticsLookup -and $IPQSLookup -and $ipinfoLookup){
    $allLookups = $true
}
if($allLookups){
            # Code to run when $allLookups is specified
            Write-Host 'Performing IPinfo, IPQS, and Scamalytics lookups...'
            Write-Host 'Use the gridview to select suspicious IPs' -ForegroundColor Yellow
            $suspectip = (Get-IPInfoLookup -ipListArray $iplist -ipinfoAPIKey $ipinfoAPIKey -outputDir $outputDir | Out-GridView -PassThru -Title "Select suspicious IPs").IP 
            $suspectip | out-file $outputDir\ipinfosuspects.txt
            Write-Host 'Performing Scamalytics lookup'
            $suspectip = (Get-Scamalytics_lookup -scamalyticsAPIKey $scamalyticsAPIKey -ipListArray $suspectip -outputDir $outputDir | Where-Object risk -ne "low").IP
            $suspectip | Out-File $outputDir\scamalyticssuspects.txt
            Write-Host 'Performing IPQS lookup'
            $suspectip = (Get-IPQSLookup -ipListArray $suspectip -ipqsAPIKey $ipqsAPIKey -outputDir $outputDir | Where-Object fraud_score -ge $fraudScoreThreshold).IP
            $suspectip | Out-File $outputDir\ipqssuspects.txt
            $badip = $suspectip
            Get-M365CompromiseResults -Logevents $Logevents -badip $badip -outputDir $outputDir
}

elseif ($badIPList) {
    Write-Host 'Using bad IP list to parse UAL for malicious activity...'
    Get-M365CompromiseResults -Logevents $Logevents -badip $badip -outputDir $outputDir 
}
elseif ($ipinfoLookup -and $IPQSLookup -and !$ScamalyticsLookup) {
    Write-Host 'Performing IPinfo and IPQS lookups...'
    $suspectip = (Get-IPInfoLookup -ipListArray $iplist -ipinfoAPIKey $ipinfoAPIKey -outputDir $outputDir | Out-GridView -PassThru -Title "Select suspicious IPs").IP 
    $suspectip = (Get-IPQSLookup -ipListArray $suspectip -ipqsAPIKey $ipqsAPIKey -outputDir $outputDir | Where-Object fraud_score -ge $fraudScoreThreshold).IP
    $badip = $suspectip
    Get-M365CompromiseResults -Logevents $Logevents -badip $badip -outputDir $outputDir
}
elseif ($ipinfoLookup -and $ScamalyticsLookup -and !$IPQSLookup) {
    Write-Host 'Performing IPinfo and Scamalytics lookups...'
    $suspectip = (Get-IPInfoLookup -ipListArray $iplist -ipinfoAPIKey $ipinfoAPIKey -outputDir $outputDir | Out-GridView -PassThru -Title "Select suspicious IPs").IP 
    $suspectip = (Get-Scamalytics_lookup -scamalyticsAPIKey $scamalyticsAPIKey -ipListArray $suspectip -outputDir $outputDir | Where-Object risk -ne "low").IP
    $badip = $suspectip
    Get-M365CompromiseResults -Logevents $Logevents -badip $badip -outputDir $outputDir
}
elseif ($ipinfoLookup -and !$ScamalyticsLookup -and !$IPQSLookup) {
    Write-Host "Performing IPinfo lookup..."
    $suspectip = (Get-IPInfoLookup -ipListArray $iplist -ipinfoAPIKey $ipinfoAPIKey -outputDir $outputDir | Out-GridView -PassThru -Title "Select suspicious IPs").IP 
    Write-Host "Done performing IPinfo lookup!"
    $badip = $suspectip
    Get-M365CompromiseResults -Logevents $Logevents -badip $badip -outputDir $outputDir
}
elseif ($IPQSLookup -and $ScamalyticsLookup -and !$ipinfoLookup) {
    Write-Host 'Performing Scamalytics and IPQS lookups...'
    $suspectip = (Get-Scamalytics_lookup -scamalyticsAPIKey $scamalyticsAPIKey -ipListArray $suspectip -outputDir $outputDir | Where-Object risk -ne "low").IP
    $suspectip = (Get-IPQSLookup -ipListArray $suspectip -ipqsAPIKey $ipqsAPIKey -outputDir $outputDir | Where-Object fraud_score -ge $fraudScoreThreshold).IP
    Write-Host 'Done performing Scamalytics and IPQS Lookup!' -ForegroundColor Green
    $badip = $suspectip
    Get-M365CompromiseResults -Logevents $Logevents -badip $badip -outputDir $outputDir
}
elseif ($ScamalyticsLookup -and !$IPQSLookup -and !$ipinfoLookup) {
    # Code to run when only $ScamalyticsLookup is specified
    Write-Host 'Performing Scamalytics lookup...'
    $suspectip = (Get-Scamalytics_lookup -scamalyticsAPIKey $scamalyticsAPIKey -ipListArray $iplist -outputDir $outputDir | Where-Object risk -ne "low").IP
    $badip = $suspectip
    Get-M365CompromiseResults -Logevents $Logevents -badip $badip -outputDir $outputDir
    Write-Host 'Done performing Scamalytics lookup!' -ForegroundColor Green
}
else {
    Write-Host 'No switches specified.  Exiting.' -ForegroundColor Red
    Write-Host "Please specify at least one of the following switches: ipinfoLookup, IPQSLookup, or ScamalyticsLookup, or provide a bad IP list with the badipList argurment" -ForegroundColor Yellow
    Exit-PSSession
}


if ($maliciousFileops){
    $maliciousFileops | Export-Csv $outputDir\MaliciousFileOps.csv -NoTypeInformation -Encoding UTF8 -Force
}
if ($maliciousLogins){
    $maliciousLogins | Export-Csv $outputDir\MaliciousLogons.csv -NoTypeInformation -Encoding UTF8 -Force
}
if ($maliciousActivities){

    $maliciousActivities | Export-Csv $outputDir\MaliciousActivities.csv -NoTypeInformation -Encoding UTF8 -Force
}

# if(!$maliciousFileops -and !$maliciousLogins -and !$maliciousActivities){
#     Write-Host "No malicious activity found in the UAL based on the Malicious IPs provided or threat intel performed" -ForegroundColor Green
# }
Write-Host "Done!" -ForegroundColor Green
[Console]::Beep()

}
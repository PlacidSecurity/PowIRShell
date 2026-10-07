---
external help file: Get-M365CompromiseInfo-help.xml
Module Name: M365CompromiseInfo
online version:
schema: 2.0.0
---

# Get-M365UnifiedAuditLog

## SYNOPSIS
Retrieves Microsoft 365 Unified Audit Log (UAL) events directly from your tenant
and writes them to JSON in the format Get-M365CompromiseInfo expects, so you don't
have to run a separate extraction tool (e.g. the Invictus Extractor Suite) first.

## SYNTAX

```
Get-M365UnifiedAuditLog [-StartDate] <DateTime> [-EndDate] <DateTime> [-OutputDir] <String>
 [[-UserIds] <String[]>] [[-Operations] <String[]>] [[-RecordType] <String>]
 [[-ResultSize] <Int32>] [[-MaxRecords] <Int32>] [-SaveRawRecords] [[-SliceHours] <Int32>]
 [-HighCompleteness] [<CommonParameters>]
```

## DESCRIPTION
Wraps Search-UnifiedAuditLog (Exchange Online / Purview) with paging via
-SessionCommand ReturnLargeSet, so results larger than a single 5,000-record page
are still retrieved. Each raw Search-UnifiedAuditLog record wraps the actual event
in a JSON-encoded AuditData property; this function expands AuditData for every
record and writes the expanded events, unmodified and in full, to a single-line
(compressed) JSON array file in -OutputDir -- the same on-disk shape produced by
the Invictus Extractor Suite, so -OutputDir can be passed straight into
Get-M365CompromiseInfo's -searchdir with no changes to the rest of the pipeline.

This function's only job is retrieval and storage: it does not return the
retrieved events to the pipeline. Use Get-AuditdataFrom365JSON or
Get-M365CompromiseInfo to read the output back for analysis.

-StartDate/-EndDate are treated as UTC, not local time. Requires the
ExchangeOnlineManagement module and an active Connect-ExchangeOnline session with
a role that can read audit logs (e.g. Compliance Administrator, Security Reader,
Global Reader, or View-Only Audit Logs). This function does not connect for you.

Every run also writes a SHA-256 manifest and a run log (query parameters, page and
record counts, duplicate/parse-failure counts, connected account and tenant,
module/PowerShell versions, and the module's git commit if available) to an
"_manifest" subfolder of -OutputDir. Get-AuditdataFrom365JSON's *.json ingest is
not recursive, so it never sees that subfolder. -SaveRawRecords output and any
AuditData parse failures are written there too, for the same reason.

Microsoft's Search-UnifiedAuditLog session paging is documented to return a
maximum of 50,000 records per SessionId. For windows likely to exceed that, use
-SliceHours to split the search into smaller per-slice sessions; a slice that
still hits the cap is halved and retried automatically.

## EXAMPLES

### Example 1
```powershell
PS C:\> Connect-ExchangeOnline -UserPrincipalName analyst@contoso.com
PS C:\> Get-M365UnifiedAuditLog -StartDate '09/01/2026' -EndDate '09/02/2026' -OutputDir C:\temp\365Comp\UAL
```

Simplest form: pulls one specific day's worth of events by explicit start/end date.

### Example 2
```powershell
PS C:\> Connect-ExchangeOnline -UserPrincipalName analyst@contoso.com
PS C:\> Get-M365UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -OutputDir C:\temp\365Comp\UAL
PS C:\> Get-M365CompromiseInfo -searchdir C:\temp\365Comp\UAL\ -outputDir C:\temp\365Comp\ -ipinfoLookup -ipinfoAPIKey '<IpInfoKeyHere>'
```

Pulls the last 7 days of UAL data, then hands it to Get-M365CompromiseInfo.

### Example 3
```powershell
PS C:\> Get-M365UnifiedAuditLog -StartDate '2026-09-01' -EndDate '2026-09-08' `
    -UserIds 'jdoe@contoso.com' -Operations UserLoggedIn,UserLoginFailed `
    -SliceHours 24 -SaveRawRecords -OutputDir C:\temp\365Comp\UAL
```

Narrows to logon events for one user over a week-long window, splitting the
search into 24-hour slices and also saving the unmodified wrapper records.

## PARAMETERS

### -StartDate
Start of the search window, treated as UTC. Passed to Search-UnifiedAuditLog as a
UTC value regardless of the Kind on the value you pass in.

```yaml
Type: DateTime
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -EndDate
End of the search window, treated as UTC. Passed to Search-UnifiedAuditLog as a
UTC value regardless of the Kind on the value you pass in.

```yaml
Type: DateTime
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -OutputDir
Directory to write the expanded JSON event file (and the _manifest subfolder) to.
Created if it doesn't exist. Pass this same directory as -searchdir to
Get-M365CompromiseInfo.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -UserIds
Optional. One or more UPNs to restrict the search to.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Operations
Optional. One or more Operation names to restrict the search to (e.g.
UserLoggedIn, MailItemsAccessed). Omit to retrieve all operations.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RecordType
Optional. Restrict to a specific UAL RecordType (e.g. ExchangeItem,
AzureActiveDirectoryStsLogon).

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 6
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ResultSize
Records per page passed to Search-UnifiedAuditLog. Default and Microsoft's max is
5000.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 7
Default value: 5000
Accept pipeline input: False
Accept wildcard characters: False
```

### -MaxRecords
Safety cap on total records retrieved per slice (the whole window, if -SliceHours
isn't used). Default 50000, Microsoft's documented ceiling for a single paged
session. A slice that hits this cap is automatically halved and retried.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 8
Default value: 50000
Accept pipeline input: False
Accept wildcard characters: False
```

### -SaveRawRecords
Also write the unmodified Search-UnifiedAuditLog records (AuditData still a JSON
string, plus the wrapper fields not present in the primary output) to
_manifest\<name>.raw.json.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -SliceHours
Split -StartDate..-EndDate into consecutive UTC slices of this many hours each,
each run as its own paged session. 0 (default) means one slice for the whole
window.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 9
Default value: 0
Accept pipeline input: False
Accept wildcard characters: False
```

### -HighCompleteness
Passed through to Search-UnifiedAuditLog's own -HighCompleteness switch (slower,
more complete search mode). Microsoft has announced plans to change this
parameter's behavior.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None. All parameters are explicit; the function calls Search-UnifiedAuditLog itself.
## OUTPUTS

### None to the pipeline. Writes a single compressed JSON array file to -OutputDir,
### plus a manifest/run log (and, optionally, raw records / parse failures) to an
### "_manifest" subfolder of -OutputDir.
## NOTES
Requires: ExchangeOnlineManagement module (Install-Module ExchangeOnlineManagement
-Scope CurrentUser) and an active Connect-ExchangeOnline session.

The run log's PowIRShellModuleVersion/GitCommit fields are best-effort: GitCommit
is left null if git isn't installed or this copy of the module isn't a git
checkout.

## RELATED LINKS

function Get-M365UnifiedAuditLog {
<#
.Synopsis
  Retrieves Microsoft 365 Unified Audit Log (UAL) events directly from your tenant and
  writes them to JSON files in the same format that Get-M365CompromiseInfo expects, so
  you don't have to run a separate tool (e.g. the Invictus Extractor Suite) first.

.Description
  Wraps Search-UnifiedAuditLog (Exchange Online / Purview) with paging via
  -SessionCommand ReturnLargeSet, so results larger than a single 5,000-record page are
  still retrieved. Each raw Search-UnifiedAuditLog record wraps the actual event in a
  JSON-encoded AuditData property; this function expands AuditData for every record and
  writes the expanded events, unmodified and in full, to a single-line (compressed) JSON
  array file in -OutputDir. That's the same on-disk shape produced by the Invictus
  Extractor Suite, so you can pass -OutputDir straight into Get-M365CompromiseInfo's
  -searchdir parameter with no changes to the rest of the pipeline. This function's only
  job is retrieval and storage -- it does not return the retrieved events to the pipeline
  (earlier versions did; that flooded the console with every event whenever the output
  wasn't captured to a variable, which isn't the point of a retrieval/storage script).
  Use Get-AuditdataFrom365JSON or Get-M365CompromiseInfo to read the output back later.

  -StartDate/-EndDate are treated as UTC, not local time: if you pass a value with no
  timezone (the normal case, e.g. a plain string or (Get-Date)), it's treated as already
  being UTC rather than being converted from local time. Pass a UTC time explicitly if
  you're not sure what your input already is.

  Requires the ExchangeOnlineManagement module and an active Connect-ExchangeOnline
  session with a role that can read audit logs (e.g. Compliance Administrator, Security
  Reader, Global Reader, or View-Only Audit Logs). This function does not connect for
  you -- run Connect-ExchangeOnline yourself first, so you control which account/MFA
  flow is used.

  Microsoft's Search-UnifiedAuditLog session paging is documented to return a maximum of
  50,000 records per SessionId. If you expect to hit that ceiling, use -SliceHours to
  split the window into smaller per-slice sessions (a slice that still hits the cap is
  halved and retried automatically); for very large or recurring extractions, Microsoft
  points to the Office 365 Management Activity API instead.

  Every run also writes a manifest and run log to an "_manifest" subfolder of -OutputDir
  (SHA-256 hash of the output file, the exact parameters used, record/page/duplicate
  counts, and the connected account/tenant). Get-AuditdataFrom365JSON's *.json ingest is
  not recursive, so it never sees that subfolder -- see the matching comment on that
  function in Get-M365info.psm1 if that ever changes. -SaveRawRecords and any AuditData
  parse failures are written there too, for the same reason.

.Parameter StartDate
  Start of the search window, treated as UTC (see Description). Passed to
  Search-UnifiedAuditLog as a UTC value regardless of the Kind on the value you pass in.

.Parameter EndDate
  End of the search window, treated as UTC (see Description). Passed to
  Search-UnifiedAuditLog as a UTC value regardless of the Kind on the value you pass in.

.Parameter OutputDir
  Directory to write the expanded JSON event file (and the _manifest subfolder) to.
  Created if it doesn't exist. Pass this same directory as -searchdir to
  Get-M365CompromiseInfo.

.Parameter UserIds
  Optional. One or more UPNs to restrict the search to.

.Parameter Operations
  Optional. One or more Operation names to restrict the search to (e.g. UserLoggedIn,
  MailItemsAccessed). Omit to retrieve all operations.

.Parameter RecordType
  Optional. Restrict to a specific UAL RecordType (e.g. ExchangeItem,
  AzureActiveDirectoryStsLogon). See Microsoft's Office 365 Management Activity API
  schema docs for the full list.

.Parameter ResultSize
  Records per page passed to Search-UnifiedAuditLog. Default and Microsoft's max is 5000.

.Parameter MaxRecords
  Safety cap on total records retrieved per slice (the whole window, if -SliceHours
  isn't used) in this call. Default 50000, which is Microsoft's documented ceiling for a
  single paged session. A slice that hits this cap is automatically halved and retried;
  see -SliceHours.

.Parameter SaveRawRecords
  Also write the unmodified Search-UnifiedAuditLog records (AuditData still a JSON
  string, plus the Identity/ResultIndex/ResultCount/etc. wrapper fields that are not
  present in the primary output) to _manifest\<name>.raw.json. Off by default.

.Parameter SliceHours
  Split -StartDate..-EndDate into consecutive UTC slices of this many hours each, each
  run as its own paged Search-UnifiedAuditLog session. 0 (default) means one slice for
  the whole window, matching this function's original behavior. Use this for windows
  that are likely to exceed the 50,000-record session cap.

.Parameter HighCompleteness
  Passed through to Search-UnifiedAuditLog's own -HighCompleteness switch (slower, more
  complete search mode). Microsoft has announced plans to change this parameter's
  behavior -- check current Search-UnifiedAuditLog documentation before relying on it.

.Example
  # Simplest form: pull one specific day's worth of events by explicit start/end date
  Connect-ExchangeOnline -UserPrincipalName analyst@contoso.com
  Get-M365UnifiedAuditLog -StartDate '09/01/2026' -EndDate '09/02/2026' -OutputDir C:\temp\365Comp\UAL

.Example
  Connect-ExchangeOnline -UserPrincipalName analyst@contoso.com
  Get-M365UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) `
      -OutputDir C:\temp\365Comp\UAL

  Get-M365CompromiseInfo -searchdir C:\temp\365Comp\UAL\ -outputDir C:\temp\365Comp\ `
      -ipinfoLookup -ipinfoAPIKey '<IpInfoKeyHere>'

.Example
  # Narrow to logon events for one user, and slice a wide window into 24-hour sessions
  Get-M365UnifiedAuditLog -StartDate '2026-09-01' -EndDate '2026-09-08' `
      -UserIds 'jdoe@contoso.com' -Operations UserLoggedIn,UserLoginFailed `
      -SliceHours 24 -SaveRawRecords -OutputDir C:\temp\365Comp\UAL

.Inputs
  None. All parameters are explicit; the function calls Search-UnifiedAuditLog itself.

.Outputs
  None to the pipeline. Writes a single compressed JSON array file to -OutputDir, plus a
  manifest/run log (and, optionally, raw records / parse failures) to an "_manifest"
  subfolder of -OutputDir.

.Notes
  Requires: ExchangeOnlineManagement module (Install-Module ExchangeOnlineManagement
  -Scope CurrentUser) and an active Connect-ExchangeOnline session.

  The run log's PowIRShellModuleVersion/GitCommit fields are best-effort: GitCommit is
  left null if git isn't installed or this copy of the module isn't a git checkout.
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [datetime]$StartDate,

        [Parameter(Mandatory = $true)]
        [datetime]$EndDate,

        [Parameter(Mandatory = $true)]
        [string]$OutputDir,

        [string[]]$UserIds,

        [string[]]$Operations,

        [string]$RecordType,

        [ValidateRange(1, 5000)]
        [int]$ResultSize = 5000,

        [int]$MaxRecords = 50000,

        [switch]$SaveRawRecords,

        [int]$SliceHours = 0,

        [switch]$HighCompleteness
    )

    $ErrorActionPreference = "Stop"
    $runStartUtc = (Get-Date).ToUniversalTime()

    # Internal helper, not exported: pages through Search-UnifiedAuditLog for one UTC
    # window, halving and retrying the window if the -MaxRecords cap is hit so a single
    # busy window doesn't silently truncate.
    function Get-AuditLogWindowRecords {
        param(
            [datetime]$WindowStartUtc,
            [datetime]$WindowEndUtc,
            [int]$Depth = 0
        )

        $sessionId = "M365UAL_" + (Get-Date -Format "yyyyMMddHHmmssfff") + "_$Depth"
        $windowRecords = New-Object System.Collections.Generic.List[object]
        $page = 0
        $reportedTotal = $null

        do {
            $page++
            $searchParams = @{
                StartDate      = $WindowStartUtc
                EndDate        = $WindowEndUtc
                ResultSize     = $ResultSize
                SessionId      = $sessionId
                SessionCommand = "ReturnLargeSet"
            }
            if ($UserIds)          { $searchParams["UserIds"] = $UserIds }
            if ($Operations)       { $searchParams["Operations"] = $Operations }
            if ($RecordType)       { $searchParams["RecordType"] = $RecordType }
            if ($HighCompleteness) { $searchParams["HighCompleteness"] = $true }

            Write-Verbose "Requesting page $page for window $WindowStartUtc to $WindowEndUtc (session $sessionId)..."
            $results = Search-UnifiedAuditLog @searchParams

            if (-not $results -or $results.Count -eq 0) { break }

            if ($null -eq $reportedTotal -and $results[0].PSObject.Properties['ResultCount']) {
                $reportedTotal = $results[0].ResultCount
            }

            foreach ($r in $results) { $windowRecords.Add($r) }
            Write-Host "  Retrieved $($windowRecords.Count) records so far for $WindowStartUtc to $WindowEndUtc..." -ForegroundColor Yellow

        } while ($results.Count -eq $ResultSize -and $windowRecords.Count -lt $MaxRecords)

        $hitCap = $windowRecords.Count -ge $MaxRecords
        $windowSpan = $WindowEndUtc - $WindowStartUtc

        if ($hitCap -and $windowSpan.TotalMinutes -gt 2 -and $Depth -lt 8) {
            $midpoint = $WindowStartUtc.AddTicks([int64]($windowSpan.Ticks / 2))
            Write-Host "  Window $WindowStartUtc to $WindowEndUtc hit the $MaxRecords cap -- subdividing and retrying." -ForegroundColor Yellow
            $firstHalf = Get-AuditLogWindowRecords -WindowStartUtc $WindowStartUtc -WindowEndUtc $midpoint -Depth ($Depth + 1)
            $secondHalf = Get-AuditLogWindowRecords -WindowStartUtc $midpoint -WindowEndUtc $WindowEndUtc -Depth ($Depth + 1)
            $combinedRecords = New-Object System.Collections.Generic.List[object]
            foreach ($r in $firstHalf.Records) { $combinedRecords.Add($r) }
            foreach ($r in $secondHalf.Records) { $combinedRecords.Add($r) }
            return [PSCustomObject]@{
                Records          = $combinedRecords
                ReportedTotal    = $null
                HitCapUnresolved = ($firstHalf.HitCapUnresolved -or $secondHalf.HitCapUnresolved)
                Pages            = $page + $firstHalf.Pages + $secondHalf.Pages
            }
        }

        if ($hitCap) {
            Write-Host "  Window $WindowStartUtc to $WindowEndUtc hit the $MaxRecords cap and could not be subdivided further." -ForegroundColor Red
        }

        return [PSCustomObject]@{
            Records          = $windowRecords
            ReportedTotal    = $reportedTotal
            HitCapUnresolved = $hitCap
            Pages            = $page
        }
    }

    if (-not (Get-Command Search-UnifiedAuditLog -ErrorAction SilentlyContinue)) {
        Write-Host "Search-UnifiedAuditLog isn't available. Install and import ExchangeOnlineManagement:" -ForegroundColor Red
        Write-Host "  Install-Module ExchangeOnlineManagement -Scope CurrentUser" -ForegroundColor Yellow
        Write-Host "  Connect-ExchangeOnline -UserPrincipalName <you@yourtenant.com>" -ForegroundColor Yellow
        return
    }

    $connectionInfo = $null
    try {
        $connectionInfo = Get-ConnectionInformation -ErrorAction Stop | Select-Object -First 1
    } catch {
        Write-Host "No active Exchange Online session found. Run Connect-ExchangeOnline first, then try again." -ForegroundColor Red
        return
    }

    if (-not (Test-Path $OutputDir)) {
        New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
    }

    # Items #1-#4/#6 (manifest, run log, raw records, parse failures) all live here so
    # Get-AuditdataFrom365JSON's non-recursive "Get-ChildItem -Filter *.json" ingest never
    # sees them -- see the matching comment on that function in Get-M365info.psm1.
    $manifestDir = Join-Path $OutputDir "_manifest"
    if (-not (Test-Path $manifestDir)) {
        New-Item -Path $manifestDir -ItemType Directory -Force | Out-Null
    }

    $inputStartDateRaw = $StartDate.ToString('o')
    $inputEndDateRaw = $EndDate.ToString('o')
    $startDateUtc = if ($StartDate.Kind -eq [System.DateTimeKind]::Utc) { $StartDate } else { [datetime]::SpecifyKind($StartDate, [System.DateTimeKind]::Utc) }
    $endDateUtc = if ($EndDate.Kind -eq [System.DateTimeKind]::Utc) { $EndDate } else { [datetime]::SpecifyKind($EndDate, [System.DateTimeKind]::Utc) }

    if ($StartDate.Kind -ne [System.DateTimeKind]::Utc -or $EndDate.Kind -ne [System.DateTimeKind]::Utc) {
        Write-Host "Note: -StartDate/-EndDate carried no timezone -- treating both as UTC, not local time." -ForegroundColor Cyan
    }
    Write-Host "Searching Unified Audit Log from $($startDateUtc.ToString('o')) to $($endDateUtc.ToString('o')) (UTC)..." -ForegroundColor Green

    $slices = New-Object System.Collections.Generic.List[hashtable]
    if ($SliceHours -gt 0) {
        $cursor = $startDateUtc
        while ($cursor -lt $endDateUtc) {
            $sliceEnd = $cursor.AddHours($SliceHours)
            if ($sliceEnd -gt $endDateUtc) { $sliceEnd = $endDateUtc }
            $slices.Add(@{ Start = $cursor; End = $sliceEnd })
            $cursor = $sliceEnd
        }
        Write-Host "Split into $($slices.Count) slice(s) of up to $SliceHours hour(s) each." -ForegroundColor Green
    } else {
        $slices.Add(@{ Start = $startDateUtc; End = $endDateUtc })
    }

    $allRecords = New-Object System.Collections.Generic.List[object]
    $sliceSummaries = New-Object System.Collections.Generic.List[object]
    $sliceNum = 0
    $totalPages = 0

    foreach ($slice in $slices) {
        $sliceNum++
        $sliceResult = Get-AuditLogWindowRecords -WindowStartUtc $slice.Start -WindowEndUtc $slice.End
        foreach ($r in $sliceResult.Records) { $allRecords.Add($r) }
        $totalPages += $sliceResult.Pages
        $sliceSummaries.Add([ordered]@{
            SliceIndex       = $sliceNum
            StartUtc         = $slice.Start.ToString('o')
            EndUtc           = $slice.End.ToString('o')
            RecordsRetrieved = $sliceResult.Records.Count
            ReportedTotal    = $sliceResult.ReportedTotal
            HitCapUnresolved = $sliceResult.HitCapUnresolved
        })
        Write-Host "Slice $sliceNum/$($slices.Count): $($sliceResult.Records.Count) records ($($slice.Start.ToString('o')) to $($slice.End.ToString('o')))." -ForegroundColor Yellow
    }

    if ($allRecords.Count -eq 0) {
        Write-Host "No events found for that search." -ForegroundColor Yellow
        return
    }

    $reportedTotalSum = 0
    $reportedTotalKnown = $true
    foreach ($s in $sliceSummaries) {
        if ($null -eq $s.ReportedTotal) { $reportedTotalKnown = $false } else { $reportedTotalSum += $s.ReportedTotal }
    }
    if ($reportedTotalKnown -and $reportedTotalSum -ne $allRecords.Count) {
        Write-Warning "Retrieved $($allRecords.Count) records but Microsoft reported $reportedTotalSum for the requested window(s) -- counts don't match."
    }

    $duplicateCount = 0
    $identityGroups = $allRecords | Group-Object -Property Identity
    foreach ($g in $identityGroups) {
        if ($g.Count -gt 1) { $duplicateCount += ($g.Count - 1) }
    }
    if ($duplicateCount -gt 0) {
        Write-Warning "Found $duplicateCount duplicate record(s) by Identity across pages/slices. All records are kept in the output; see the run log for the count."
    }

    Write-Host "Retrieved $($allRecords.Count) raw audit records. Expanding AuditData..." -ForegroundColor Green

    $parseFailures = New-Object System.Collections.Generic.List[object]
    $expandedEvents = foreach ($record in $allRecords) {
        try {
            $record.AuditData | ConvertFrom-Json
        } catch {
            $parseFailures.Add([ordered]@{
                Identity  = $record.Identity
                Error     = $_.Exception.Message
                AuditData = $record.AuditData
            })
        }
    }

    if ($parseFailures.Count -gt 0) {
        Write-Warning "$($parseFailures.Count) record(s) had AuditData that failed to parse and were omitted from the output. See _manifest\*.parsefailures.json."
    }

    $timestamp = Get-Date -Format 'yyyyMMddHHmmss'
    $outFile = Join-Path $OutputDir "UnifiedAuditLog_$timestamp.json"
    # -Compress keeps this a single line, matching the Invictus Extractor output format
    # that Get-AuditdataFrom365JSON expects (it reads each *.json file line by line).
    @($expandedEvents) | ConvertTo-Json -Depth 20 -Compress | Out-File -FilePath $outFile -Encoding utf8 -Force

    $earliestEvent = $null
    $latestEvent = $null
    foreach ($evt in $expandedEvents) {
        if ($evt.PSObject.Properties['CreationTime']) {
            try {
                $creationUtc = [datetime]::SpecifyKind([datetime]$evt.CreationTime, [System.DateTimeKind]::Utc)
                if ($null -eq $earliestEvent -or $creationUtc -lt $earliestEvent) { $earliestEvent = $creationUtc }
                if ($null -eq $latestEvent -or $creationUtc -gt $latestEvent) { $latestEvent = $creationUtc }
            } catch { }
        }
    }
    if ($earliestEvent -and ($earliestEvent -lt $startDateUtc -or $latestEvent -gt $endDateUtc)) {
        Write-Warning "Event CreationTime range ($($earliestEvent.ToString('o')) to $($latestEvent.ToString('o'))) falls outside the requested UTC window ($($startDateUtc.ToString('o')) to $($endDateUtc.ToString('o')))."
    }

    $rawFile = $null
    if ($SaveRawRecords) {
        $rawFile = Join-Path $manifestDir "UnifiedAuditLog_$timestamp.raw.json"
        @($allRecords) | ConvertTo-Json -Depth 20 -Compress | Out-File -FilePath $rawFile -Encoding utf8 -Force
    }

    $parseFailuresFile = $null
    if ($parseFailures.Count -gt 0) {
        $parseFailuresFile = Join-Path $manifestDir "UnifiedAuditLog_$timestamp.parsefailures.json"
        @($parseFailures) | ConvertTo-Json -Depth 10 -Compress | Out-File -FilePath $parseFailuresFile -Encoding utf8 -Force
    }

    $outputHash = (Get-FileHash -Path $outFile -Algorithm SHA256).Hash
    $outputBytes = (Get-Item $outFile).Length
    $runEndUtc = (Get-Date).ToUniversalTime()

    $manifestRows = New-Object System.Collections.Generic.List[object]
    $manifestRows.Add([PSCustomObject]@{
        File       = (Split-Path $outFile -Leaf)
        SHA256     = $outputHash
        Bytes      = $outputBytes
        WrittenUtc = $runEndUtc.ToString('o')
    })

    if ($rawFile) {
        $manifestRows.Add([PSCustomObject]@{
            File       = (Split-Path $rawFile -Leaf)
            SHA256     = (Get-FileHash -Path $rawFile -Algorithm SHA256).Hash
            Bytes      = (Get-Item $rawFile).Length
            WrittenUtc = $runEndUtc.ToString('o')
        })
    }

    if ($parseFailuresFile) {
        $manifestRows.Add([PSCustomObject]@{
            File       = (Split-Path $parseFailuresFile -Leaf)
            SHA256     = (Get-FileHash -Path $parseFailuresFile -Algorithm SHA256).Hash
            Bytes      = (Get-Item $parseFailuresFile).Length
            WrittenUtc = $runEndUtc.ToString('o')
        })
    }

    $powIRShellModule = Get-Module -Name M365CompromiseInfo | Select-Object -First 1
    $gitCommit = $null
    try {
        if ($powIRShellModule -and $powIRShellModule.ModuleBase) {
            $gitCommit = git -C $powIRShellModule.ModuleBase rev-parse HEAD 2>$null
        }
    } catch { }

    $exoModule = Get-Module -Name ExchangeOnlineManagement | Select-Object -First 1

    $runLog = [ordered]@{
        RunStartUtc                   = $runStartUtc.ToString('o')
        RunEndUtc                     = $runEndUtc.ToString('o')
        RequestedStartDateRaw         = $inputStartDateRaw
        RequestedEndDateRaw           = $inputEndDateRaw
        RequestedStartDateUtc         = $startDateUtc.ToString('o')
        RequestedEndDateUtc           = $endDateUtc.ToString('o')
        EarliestEventCreationTimeUtc  = $(if ($earliestEvent) { $earliestEvent.ToString('o') } else { $null })
        LatestEventCreationTimeUtc    = $(if ($latestEvent) { $latestEvent.ToString('o') } else { $null })
        UserIds                       = $UserIds
        Operations                    = $Operations
        RecordType                    = $RecordType
        ResultSize                    = $ResultSize
        MaxRecords                    = $MaxRecords
        SliceHours                    = $SliceHours
        HighCompleteness               = [bool]$HighCompleteness
        Slices                        = $sliceSummaries
        PagesRetrieved                 = $totalPages
        RawRecordsRetrieved            = $allRecords.Count
        ReportedTotal                  = $(if ($reportedTotalKnown) { $reportedTotalSum } else { $null })
        DuplicateRecords               = $duplicateCount
        EventsExpanded                 = $expandedEvents.Count
        ParseFailures                  = $parseFailures.Count
        MaxRecordsCapHitUnresolved     = ($sliceSummaries | Where-Object { $_.HitCapUnresolved }).Count -gt 0
        ConnectedAccount                = $connectionInfo.UserPrincipalName
        TenantId                        = $connectionInfo.TenantId
        ExchangeOnlineManagementVersion = $(if ($exoModule) { $exoModule.Version.ToString() } else { $null })
        PowIRShellModuleVersion          = $(if ($powIRShellModule) { $powIRShellModule.Version.ToString() } else { $null })
        GitCommit                       = $gitCommit
        PowerShellVersion               = $PSVersionTable.PSVersion.ToString()
        MachineName                     = [System.Environment]::MachineName
        OutputFile                      = (Split-Path $outFile -Leaf)
        OutputFileSHA256                = $outputHash
        RawRecordsFile                  = $(if ($rawFile) { (Split-Path $rawFile -Leaf) } else { $null })
        ParseFailuresFile               = $(if ($parseFailuresFile) { (Split-Path $parseFailuresFile -Leaf) } else { $null })
    }

    $runLogFile = Join-Path $manifestDir "UnifiedAuditLog_$timestamp.runlog.json"
    $runLog | ConvertTo-Json -Depth 10 | Out-File -FilePath $runLogFile -Encoding utf8 -Force

    $manifestRows.Add([PSCustomObject]@{
        File       = (Split-Path $runLogFile -Leaf)
        SHA256     = (Get-FileHash -Path $runLogFile -Algorithm SHA256).Hash
        Bytes      = (Get-Item $runLogFile).Length
        WrittenUtc = $runEndUtc.ToString('o')
    })

    $manifestCsvPath = Join-Path $manifestDir "manifest.csv"
    $manifestRows | Export-Csv -Path $manifestCsvPath -Append -NoTypeInformation -Encoding utf8

    Write-Host "Wrote $($expandedEvents.Count) events to $outFile" -ForegroundColor Green
    Write-Host "Manifest and run log written to $manifestDir" -ForegroundColor Cyan
    Write-Host "Pass -searchdir $OutputDir\ to Get-M365CompromiseInfo to analyze these events." -ForegroundColor Cyan
}

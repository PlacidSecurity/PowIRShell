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
  session whose account has the Audit Logs or View-Only Audit Logs role in Exchange
  Online. By default those roles are in the Compliance Management and Organization
  Management role groups. This function does not connect for you -- run
  Connect-ExchangeOnline yourself first, so you control which account/MFA flow is used.

  Import the module and call this function by name. Running this .ps1 file by path only
  defines the function, so it stops with an error rather than appearing to succeed.

  Every collection starts with read-only preflight checks (session, cmdlet availability,
  a one-record test search, audit ingestion, and role assignment where the account can
  read it); the results go in the run log. Use -PreflightOnly to run just those checks.
  A rejected test search stops the run, unless ingestion is off. Ingestion being off only
  warns and the collection is still attempted, because logs from before it was turned off
  may still be searchable -- and it may be a finding in itself.
  Preflight can't detect an account limited to administrative units: such an account gets
  successful but partial results, so that check is always reported as not verified.

  A search the service rejects is a failure, not an empty result. The run stops, records
  already retrieved are saved to _manifest\<name>.partial.json (where
  Get-M365CompromiseInfo won't ingest them as if they were complete), the run log records
  Status = Failed, and the function throws. A search that genuinely returns nothing writes
  a run log with Status = CompletedNoEvents and no event file.

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

.Parameter PreflightOnly
  Run only the read-only preflight checks and return the results. Needs no other
  parameters and writes no files. Doesn't throw on a failed check: read the Overall
  property (Ready, ReadyWithWarnings or NotReady).

.Example
  # Check that the connected account can search the audit log, before a real pull
  Connect-ExchangeOnline -UserPrincipalName analyst@contoso.com
  Get-M365UnifiedAuditLog -PreflightOnly

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
  None to the pipeline for a collection. Writes a single compressed JSON array file to
  -OutputDir, plus a manifest/run log (and, optionally, raw records / parse failures) to
  an "_manifest" subfolder of -OutputDir. With -PreflightOnly, returns one object with
  Overall, ConnectedAccount, TenantId and Checks properties and writes no files.

.Notes
  Requires: ExchangeOnlineManagement module (Install-Module ExchangeOnlineManagement
  -Scope CurrentUser) and an active Connect-ExchangeOnline session.

  The run log's PowIRShellModuleVersion/GitCommit fields are best-effort: GitCommit is
  left null if git isn't installed or this copy of the module isn't a git checkout.
#>
    [CmdletBinding(DefaultParameterSetName = 'Collect')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Collect', Position = 0)]
        [datetime]$StartDate,

        [Parameter(Mandatory = $true, ParameterSetName = 'Collect', Position = 1)]
        [datetime]$EndDate,

        [Parameter(Mandatory = $true, ParameterSetName = 'Collect', Position = 2)]
        [string]$OutputDir,

        [Parameter(ParameterSetName = 'Collect', Position = 3)]
        [string[]]$UserIds,

        [Parameter(ParameterSetName = 'Collect', Position = 4)]
        [string[]]$Operations,

        [Parameter(ParameterSetName = 'Collect', Position = 5)]
        [string]$RecordType,

        [Parameter(ParameterSetName = 'Collect', Position = 6)]
        [ValidateRange(1, 5000)]
        [int]$ResultSize = 5000,

        [Parameter(ParameterSetName = 'Collect', Position = 7)]
        [int]$MaxRecords = 50000,

        [Parameter(ParameterSetName = 'Collect')]
        [switch]$SaveRawRecords,

        [Parameter(ParameterSetName = 'Collect', Position = 8)]
        [int]$SliceHours = 0,

        [Parameter(ParameterSetName = 'Collect')]
        [switch]$HighCompleteness,

        [Parameter(Mandatory = $true, ParameterSetName = 'Preflight')]
        [switch]$PreflightOnly
    )

    $ErrorActionPreference = "Stop"
    $runStartUtc = (Get-Date).ToUniversalTime()

    $searchWarnings = New-Object System.Collections.Generic.List[string]

    # Internal helper, not exported: one Search-UnifiedAuditLog call. The cmdlet reports a
    # rejected search as a warning and no records, which looks just like an empty result,
    # so warnings have to be captured and classified. A warning that doesn't look like a
    # failure (e.g. a deprecation notice) is kept for the run log but doesn't stop the run.
    function Invoke-AuditLogSearch {
        param([hashtable]$SearchParams)

        $capturedWarnings = $null
        try {
            $searchResults = @(Search-UnifiedAuditLog @SearchParams -ErrorAction Stop -WarningVariable capturedWarnings)
        } catch {
            return [PSCustomObject]@{ Results = @(); Failure = $_.Exception.Message; Warnings = @() }
        }

        $warningText = @($capturedWarnings | ForEach-Object { "$_" })
        $failureText = @($warningText | Where-Object { $_ -match 'fail|error|bad ?request|denied|unauthori[sz]ed|forbidden|time[d ]?-? ?out|throttl' })

        return [PSCustomObject]@{
            Results  = $searchResults
            Failure  = $(if ($failureText.Count -gt 0) { $failureText -join ' | ' } else { $null })
            Warnings = $warningText
        }
    }

    # Internal helper, not exported: read-only checks that the connected session can search
    # the audit log. Status is Pass, Warn, Fail, Unknown (this account can't read the
    # setting) or NotVerified (no check available here). Only Pass/Warn/Fail affect Overall.
    function Invoke-UalPreflight {
        $checks = New-Object System.Collections.Generic.List[object]
        $account = $null
        $tenant = $null
        $eopConnected = $false

        $addCheck = {
            param($Name, $Status, $Detail)
            $checks.Add([PSCustomObject]@{ Name = $Name; Status = $Status; Detail = $Detail })
        }

        $sessionOk = $false
        if (-not (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue)) {
            & $addCheck 'Session' 'Fail' 'ExchangeOnlineManagement v3 or later is not available. Run: Install-Module ExchangeOnlineManagement -Scope CurrentUser; then Connect-ExchangeOnline.'
        } else {
            $connections = @()
            try { $connections = @(Get-ConnectionInformation -ErrorAction Stop) } catch { $connections = @() }
            $eopConnected = @($connections | Where-Object { $_.IsEopSession }).Count -gt 0
            $exoSession = @($connections | Where-Object { $_.State -eq 'Connected' -and -not $_.IsEopSession }) | Select-Object -First 1
            if ($exoSession) {
                $sessionOk = $true
                $account = $exoSession.UserPrincipalName
                $tenant = $exoSession.TenantID
                & $addCheck 'Session' 'Pass' "Connected to Exchange Online as $account (tenant $tenant)."
            } else {
                & $addCheck 'Session' 'Fail' 'No active Exchange Online session. Run Connect-ExchangeOnline first (Connect-IPPSSession alone is not enough).'
            }
        }

        $cmdletOk = $false
        if ($sessionOk) {
            if (Get-Command Search-UnifiedAuditLog -ErrorAction SilentlyContinue) {
                $cmdletOk = $true
                & $addCheck 'Cmdlet' 'Pass' 'Search-UnifiedAuditLog is available in this session.'
            } else {
                & $addCheck 'Cmdlet' 'Fail' "Search-UnifiedAuditLog is not available in this session. The account probably lacks the Audit Logs or View-Only Audit Logs role in Exchange Online, or the session was opened with a -CommandName list that leaves it out."
            }
        }

        if ($cmdletOk) {
            $probeEndUtc = (Get-Date).ToUniversalTime()
            $probe = Invoke-AuditLogSearch -SearchParams @{ StartDate = $probeEndUtc.AddDays(-1); EndDate = $probeEndUtc; ResultSize = 1 }
            if ($probe.Failure) {
                & $addCheck 'TestSearch' 'Fail' "The audit search was rejected: $($probe.Failure)"
            } elseif ($probe.Results.Count -gt 0) {
                & $addCheck 'TestSearch' 'Pass' 'A one-record test search of the last 24 hours returned a record.'
            } else {
                & $addCheck 'TestSearch' 'Warn' 'Search accepted, but no records in the last 24 hours. That could be a quiet tenant, a limited scope, or logging being off, so it does not prove access.'
            }

            if ($eopConnected) {
                & $addCheck 'Ingestion' 'Unknown' 'A Security & Compliance session is also connected, and its Get-AdminAuditLogConfig always reports False. Check this from a window connected only to Exchange Online.'
            } elseif (Get-Command Get-AdminAuditLogConfig -ErrorAction SilentlyContinue) {
                try {
                    $ingestionEnabled = (Get-AdminAuditLogConfig -ErrorAction Stop).UnifiedAuditLogIngestionEnabled
                    if ($ingestionEnabled) {
                        & $addCheck 'Ingestion' 'Pass' 'UnifiedAuditLogIngestionEnabled is True.'
                    } else {
                        & $addCheck 'Ingestion' 'Warn' 'UnifiedAuditLogIngestionEnabled is False: no new events are being logged. Logs from before it was turned off may still be searchable. Record this as a possible finding before changing it.'
                    }
                } catch {
                    & $addCheck 'Ingestion' 'Unknown' "This account could not read the setting: $($_.Exception.Message)"
                }
            } else {
                & $addCheck 'Ingestion' 'Unknown' 'Get-AdminAuditLogConfig is not available to this account.'
            }

            if ($account -and (Get-Command Get-ManagementRoleEntry -ErrorAction SilentlyContinue) -and (Get-Command Get-ManagementRoleAssignment -ErrorAction SilentlyContinue)) {
                try {
                    $grantingRoles = @(Get-ManagementRoleEntry '*\Search-UnifiedAuditLog' -ErrorAction Stop | ForEach-Object { "$($_.Role)" } | Select-Object -Unique)
                    $heldRoles = @(Get-ManagementRoleAssignment -RoleAssignee $account -Delegating $false -Enabled $true -ErrorAction Stop |
                        ForEach-Object { "$($_.Role)" } | Where-Object { $grantingRoles -contains $_ } | Select-Object -Unique)
                    if ($heldRoles.Count -gt 0) {
                        & $addCheck 'Roles' 'Pass' "Roles granting the search: $($heldRoles -join ', ')."
                    } else {
                        & $addCheck 'Roles' 'Unknown' 'No granting role was found through this lookup. Rely on the test search result instead.'
                    }
                } catch {
                    & $addCheck 'Roles' 'Unknown' "This account could not read role assignments: $($_.Exception.Message)"
                }
            } else {
                & $addCheck 'Roles' 'Unknown' 'This account cannot read role assignments, which is normal for a view-only account.'
            }

            & $addCheck 'AdminUnitScope' 'NotVerified' 'Not checked. An admin restricted to administrative units gets successful but partial results and misses non-user and system logs. Confirm the account is unrestricted.'
        }

        $statuses = @($checks | ForEach-Object { $_.Status })
        $overall = if ($statuses -contains 'Fail') { 'NotReady' } elseif ($statuses -contains 'Warn') { 'ReadyWithWarnings' } else { 'Ready' }

        foreach ($check in $checks) {
            $checkColor = switch ($check.Status) { 'Pass' { 'Green' } 'Fail' { 'Red' } 'Warn' { 'Yellow' } default { 'Cyan' } }
            Write-Host ("  [{0}] {1}: {2}" -f $check.Status, $check.Name, $check.Detail) -ForegroundColor $checkColor
        }
        Write-Host "  Preflight result: $overall" -ForegroundColor $(if ($overall -eq 'NotReady') { 'Red' } elseif ($overall -eq 'Ready') { 'Green' } else { 'Yellow' })

        return [PSCustomObject]@{
            Overall          = $overall
            ConnectedAccount = $account
            TenantId         = $tenant
            Checks           = $checks.ToArray()
        }
    }

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
        $windowFailure = $null

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
            $searchOutcome = Invoke-AuditLogSearch -SearchParams $searchParams
            foreach ($w in $searchOutcome.Warnings) { $searchWarnings.Add($w) }
            $results = @($searchOutcome.Results)

            if ($searchOutcome.Failure) {
                $windowFailure = "Search failed for window $($WindowStartUtc.ToString('o')) to $($WindowEndUtc.ToString('o')) on page ${page}: $($searchOutcome.Failure)"
                foreach ($r in $results) { $windowRecords.Add($r) }
                break
            }

            if ($results.Count -eq 0) { break }

            if ($null -eq $reportedTotal -and $results[0].PSObject.Properties['ResultCount']) {
                $reportedTotal = $results[0].ResultCount
            }

            foreach ($r in $results) { $windowRecords.Add($r) }
            Write-Host "  Retrieved $($windowRecords.Count) records so far for $WindowStartUtc to $WindowEndUtc..." -ForegroundColor Yellow

        } while ($results.Count -eq $ResultSize -and $windowRecords.Count -lt $MaxRecords)

        $hitCap = $windowRecords.Count -ge $MaxRecords
        $windowSpan = $WindowEndUtc - $WindowStartUtc

        if ($windowFailure) {
            return [PSCustomObject]@{
                Records          = $windowRecords
                ReportedTotal    = $null
                HitCapUnresolved = $hitCap
                Pages            = $page
                Failure          = $windowFailure
            }
        }

        if ($hitCap -and $windowSpan.TotalMinutes -gt 2 -and $Depth -lt 8) {
            $midpoint = $WindowStartUtc.AddTicks([int64]($windowSpan.Ticks / 2))
            Write-Host "  Window $WindowStartUtc to $WindowEndUtc hit the $MaxRecords cap -- subdividing and retrying." -ForegroundColor Yellow
            $firstHalf = Get-AuditLogWindowRecords -WindowStartUtc $WindowStartUtc -WindowEndUtc $midpoint -Depth ($Depth + 1)
            $combinedRecords = New-Object System.Collections.Generic.List[object]
            foreach ($r in $firstHalf.Records) { $combinedRecords.Add($r) }
            if ($firstHalf.Failure) {
                return [PSCustomObject]@{
                    Records          = $combinedRecords
                    ReportedTotal    = $null
                    HitCapUnresolved = $firstHalf.HitCapUnresolved
                    Pages            = $page + $firstHalf.Pages
                    Failure          = $firstHalf.Failure
                }
            }
            $secondHalf = Get-AuditLogWindowRecords -WindowStartUtc $midpoint -WindowEndUtc $WindowEndUtc -Depth ($Depth + 1)
            foreach ($r in $secondHalf.Records) { $combinedRecords.Add($r) }
            return [PSCustomObject]@{
                Records          = $combinedRecords
                ReportedTotal    = $null
                HitCapUnresolved = ($firstHalf.HitCapUnresolved -or $secondHalf.HitCapUnresolved)
                Pages            = $page + $firstHalf.Pages + $secondHalf.Pages
                Failure          = $secondHalf.Failure
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
            Failure          = $null
        }
    }

    $powIRShellModule = Get-Module -Name M365CompromiseInfo | Select-Object -First 1
    if ($powIRShellModule) {
        Write-Host "PowIRShell module $($powIRShellModule.Version) loaded from $($powIRShellModule.ModuleBase)" -ForegroundColor Cyan
    } else {
        Write-Host "PowIRShell module not loaded (function was dot-sourced); version and path won't be recorded." -ForegroundColor Cyan
    }

    Write-Host "Running preflight checks..." -ForegroundColor Green
    $preflight = Invoke-UalPreflight

    if ($PSCmdlet.ParameterSetName -eq 'Preflight') {
        return $preflight
    }

    # With no usable session there's no tenant to document, so stop before creating folders.
    $preventingChecks = @($preflight.Checks | Where-Object { $_.Status -eq 'Fail' })
    $sessionBlocked = @($preventingChecks | Where-Object { $_.Name -in 'Session', 'Cmdlet' })
    if ($sessionBlocked.Count -gt 0) {
        throw "Cannot search the Unified Audit Log. $($sessionBlocked[0].Detail)"
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
    if ($endDateUtc -gt (Get-Date).ToUniversalTime()) {
        $futureEndMessage = "-EndDate $($endDateUtc.ToString('o')) is in the future. The service may reject this search."
        Write-Warning $futureEndMessage
        $searchWarnings.Add($futureEndMessage)
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
    $runFailure = $null

    # With ingestion off, a rejected test search doesn't rule out older logs, and an attacker
    # may be the one who turned it off. Try the real search; it fails loudly if rejected too.
    $ingestionOff = @($preflight.Checks | Where-Object { $_.Name -eq 'Ingestion' -and $_.Status -eq 'Warn' }).Count -gt 0
    if ($ingestionOff) {
        $preventingChecks = @($preventingChecks | Where-Object { $_.Name -ne 'TestSearch' })
    }

    if ($preventingChecks.Count -gt 0) {
        $runFailure = "Preflight failed. $($preventingChecks[0].Detail)"
        $slices.Clear()
    }

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
            Failure          = $sliceResult.Failure
        })
        Write-Host "Slice $sliceNum/$($slices.Count): $($sliceResult.Records.Count) records ($($slice.Start.ToString('o')) to $($slice.End.ToString('o')))." -ForegroundColor Yellow
        if ($sliceResult.Failure) {
            $runFailure = $sliceResult.Failure
            Write-Host "  $runFailure" -ForegroundColor Red
            break
        }
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
    $identityGroups = @($allRecords | Group-Object -Property Identity)
    foreach ($g in $identityGroups) {
        if ($g.Count -gt 1) { $duplicateCount += ($g.Count - 1) }
    }
    if ($duplicateCount -gt 0) {
        Write-Warning "Found $duplicateCount duplicate record(s) by Identity across pages/slices. All records are kept in the output; see the run log for the count."
    }

    if ($allRecords.Count -gt 0) {
        Write-Host "Retrieved $($allRecords.Count) raw audit records. Expanding AuditData..." -ForegroundColor Green
    }

    $parseFailures = New-Object System.Collections.Generic.List[object]
    $expandedEvents = @(foreach ($record in $allRecords) {
        try {
            $record.AuditData | ConvertFrom-Json
        } catch {
            $parseFailures.Add([ordered]@{
                Identity  = $record.Identity
                Error     = $_.Exception.Message
                AuditData = $record.AuditData
            })
        }
    })

    if ($parseFailures.Count -gt 0) {
        Write-Warning "$($parseFailures.Count) record(s) had AuditData that failed to parse and were omitted from the output. See _manifest\*.parsefailures.json."
    }

    $timestamp = Get-Date -Format 'yyyyMMddHHmmss'
    $outFile = $null
    if ($expandedEvents.Count -gt 0) {
        # A failed run's records go in _manifest so they can't be ingested as a complete set.
        $outFile = if ($runFailure) { Join-Path $manifestDir "UnifiedAuditLog_$timestamp.partial.json" } else { Join-Path $OutputDir "UnifiedAuditLog_$timestamp.json" }
        # -Compress keeps this a single line, matching the Invictus Extractor output format
        # that Get-AuditdataFrom365JSON expects (it reads each *.json file line by line).
        ConvertTo-Json -InputObject $expandedEvents -Depth 20 -Compress | Out-File -FilePath $outFile -Encoding utf8 -Force
    }

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
    if ($SaveRawRecords -and $allRecords.Count -gt 0) {
        $rawFile = Join-Path $manifestDir "UnifiedAuditLog_$timestamp.raw.json"
        ConvertTo-Json -InputObject @($allRecords) -Depth 20 -Compress | Out-File -FilePath $rawFile -Encoding utf8 -Force
    }

    $parseFailuresFile = $null
    if ($parseFailures.Count -gt 0) {
        $parseFailuresFile = Join-Path $manifestDir "UnifiedAuditLog_$timestamp.parsefailures.json"
        ConvertTo-Json -InputObject @($parseFailures) -Depth 10 -Compress | Out-File -FilePath $parseFailuresFile -Encoding utf8 -Force
    }

    $outputHash = $null
    $runEndUtc = (Get-Date).ToUniversalTime()

    $manifestRows = New-Object System.Collections.Generic.List[object]
    if ($outFile) {
        $outputHash = (Get-FileHash -Path $outFile -Algorithm SHA256).Hash
        $manifestRows.Add([PSCustomObject]@{
            File       = (Split-Path $outFile -Leaf)
            SHA256     = $outputHash
            Bytes      = (Get-Item $outFile).Length
            WrittenUtc = $runEndUtc.ToString('o')
        })
    }

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

    $capUnresolved = @($sliceSummaries | Where-Object { $_.HitCapUnresolved }).Count -gt 0
    $countMismatch = $reportedTotalKnown -and $reportedTotalSum -ne $allRecords.Count
    $runStatus = if ($runFailure) {
        'Failed'
    } elseif ($expandedEvents.Count -eq 0 -and $parseFailures.Count -eq 0) {
        'CompletedNoEvents'
    } elseif ($capUnresolved -or $countMismatch -or $parseFailures.Count -gt 0 -or $searchWarnings.Count -gt 0 -or $preflight.Overall -ne 'Ready') {
        'CompletedWithWarnings'
    } else {
        'Completed'
    }

    $gitCommit = $null
    try {
        if ($powIRShellModule -and $powIRShellModule.ModuleBase) {
            $gitCommit = git -C $powIRShellModule.ModuleBase rev-parse HEAD 2>$null
        }
    } catch { }

    $exoModule = Get-Module -Name ExchangeOnlineManagement | Select-Object -First 1

    $runLog = [ordered]@{
        Status                        = $runStatus
        FailureReason                 = $runFailure
        SearchWarnings                = $searchWarnings.ToArray()
        Preflight                     = $preflight
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
        MaxRecordsCapHitUnresolved     = $capUnresolved
        ConnectedAccount                = $preflight.ConnectedAccount
        TenantId                        = $preflight.TenantId
        ExchangeOnlineManagementVersion = $(if ($exoModule) { $exoModule.Version.ToString() } else { $null })
        PowIRShellModuleVersion          = $(if ($powIRShellModule) { $powIRShellModule.Version.ToString() } else { $null })
        PowIRShellModulePath             = $(if ($powIRShellModule) { $powIRShellModule.ModuleBase } else { $null })
        GitCommit                       = $gitCommit
        PowerShellVersion               = $PSVersionTable.PSVersion.ToString()
        MachineName                     = [System.Environment]::MachineName
        OutputFile                      = $(if ($outFile) { Split-Path $outFile -Leaf } else { $null })
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

    Write-Host "Manifest and run log written to $manifestDir" -ForegroundColor Cyan

    if ($runFailure) {
        $partialNote = if ($outFile) { " $($expandedEvents.Count) event(s) retrieved before the failure were saved to $outFile and are incomplete." } else { " No events were saved." }
        throw "Unified Audit Log collection failed. $runFailure$partialNote See $runLogFile"
    }

    if ($runStatus -eq 'CompletedNoEvents') {
        Write-Host "The search completed and returned no events, so no event file was written. Check the preflight results above before treating this as a clean result. Run log: $runLogFile" -ForegroundColor Yellow
        return
    }

    Write-Host "Wrote $($expandedEvents.Count) events to $outFile" -ForegroundColor Green
    Write-Host "Pass -searchdir $OutputDir\ to Get-M365CompromiseInfo to analyze these events." -ForegroundColor Cyan
}

# Running this file by path defines the function in a temporary scope and then discards it,
# and PowerShell silently ignores any parameters given to the script. Without this check that
# looks like a successful run that collected nothing. Importing the module or dot-sourcing
# this file both skip it.
if (-not $ExecutionContext.SessionState.Module -and $MyInvocation.InvocationName -ne '.') {
    throw "Get-M365UnifiedAuditLog.ps1 only defines a function, so running it by path collects nothing. From the PowIRShell folder, run: Import-Module .\M365CompromiseInfo.psd1 -Force ; then call Get-M365UnifiedAuditLog with your parameters."
}

# PowIRShell: recommended improvements for forensic defensibility

Source: Appendix C of Placid Security PS-SOP-DF-002 (M365 Evidence Acquisition SOP), October 2026.

## Context

PowIRShell is used to acquire and analyze Microsoft 365 Unified Audit Log (UAL) data for incident response, including work that may need to hold up in litigation. The SOP currently compensates for the gaps below with manual steps (hash manifests, query logs, transcripts, raw-JSON review). The goal of these changes is to move those controls into the tool so every export records its own integrity, completeness and provenance.

General requirements for all changes:

- Do not change the existing JSON output format that `Get-AuditdataFrom365JSON` reads (compressed JSON array, one file per run, `*.json` in a single directory). New outputs go in separate files.
- Keep backward compatibility with existing parameters and with Invictus Extractor Suite JSON input.
- Write all timestamps in logs as UTC ISO 8601 (`(Get-Date).ToUniversalTime().ToString('o')`).
- Never write API keys, client secrets or tokens to any log, transcript-friendly console output, or file.

Items are in suggested priority order.

---

## 1. Hash manifest and run log for every export

**Where:** `src/PrimaryModules/Get-M365UnifiedAuditLog.ps1`, after the JSON file is written.

**Current behavior:** Writes `UnifiedAuditLog_<timestamp>.json` and nothing else. No hash, no record of the query parameters.

**Change:**
- Compute SHA-256 of the JSON output and write it to a manifest (e.g. `UnifiedAuditLog_<timestamp>.sha256` or append to `manifest.csv` with columns File, SHA256, Bytes, WrittenUtc).
- Write a run log (e.g. `UnifiedAuditLog_<timestamp>.runlog.json`) containing: StartDate and EndDate as passed and as sent to Microsoft, UserIds, Operations, RecordType, ResultSize, MaxRecords, SessionId, pages retrieved, raw records retrieved, events expanded, parse failures, duplicates found, whether the MaxRecords cap was hit, connected account (`Get-ConnectionInformation` UserPrincipalName and TenantID), ExchangeOnlineManagement module version, PowerShell version, PowIRShell module version and git commit if available, machine name, run start and end UTC.

**Acceptance:** Every run produces JSON + manifest + run log. Re-hashing the JSON matches the manifest.

**Status (2026-10-07):** Done. `_manifest\manifest.csv` (File/SHA256/Bytes/WrittenUtc) and `_manifest\<name>.runlog.json` are written every run.

## 2. Optional raw-record export

**Where:** `Get-M365UnifiedAuditLog.ps1`.

**Current behavior:** Only the expanded `AuditData` objects are written. The `Search-UnifiedAuditLog` wrapper fields (RecordType, CreationDate, UserIds, Operations, Identity, ResultIndex, ResultCount, etc.) are discarded.

**Change:** Add a `-SaveRawRecords` switch that writes the unmodified `$allRecords` to a separate file (e.g. `UnifiedAuditLog_<timestamp>.raw.json`, not matching the `*.json` filter used by the analysis input; consider a `.rawjson` extension or a `raw\` subfolder) and includes it in the manifest.

**Acceptance:** Raw file contains every record retrieved, field-for-field as returned, and does not interfere with `Get-M365CompromiseInfo -searchdir`.

**Status (2026-10-07):** Done. `-SaveRawRecords` writes `_manifest\<name>.raw.json`; kept out of `-OutputDir` itself (not just a non-matching extension) since `Get-AuditdataFrom365JSON`'s `*.json` ingest isn't recursive -- see the cross-reference comments added in both files.

## 3. Visible handling of AuditData parse failures

**Where:** `Get-M365UnifiedAuditLog.ps1`, the `foreach ($record in $allRecords)` expansion loop.

**Current behavior:** A record whose `AuditData` fails `ConvertFrom-Json` is reported only via `Write-Verbose` and silently omitted from output.

**Change:** Count failures and report the count with `Write-Warning` (normal verbosity). Write failed records (Identity plus raw AuditData string) to `UnifiedAuditLog_<timestamp>.parsefailures.json`. Include the count in the run log.

**Acceptance:** Events written + parse failures = raw records retrieved, and the run log states both numbers.

**Status (2026-10-07):** Done. Failures are counted, `Write-Warning`'d, written to `_manifest\<name>.parsefailures.json`, and included in the run log.

## 4. Paging completeness and duplicate detection

**Where:** `Get-M365UnifiedAuditLog.ps1`, the `do { ... } while (...)` paging loop.

**Current behavior:** Loop ends when a page returns fewer than `ResultSize` records or the `MaxRecords` cap is reached. There is no comparison with Microsoft's reported total, and duplicate records (possible with `ReturnLargeSet`) are not detected.

**Change:**
- Capture `ResultCount` from the first record of the first page (Microsoft's reported total for the session) and compare it with records retrieved. Warn on mismatch and record both in the run log.
- Detect duplicates by record `Identity` (and/or AuditData `Id`). Report the count. Keep the master output unchanged (all records as retrieved); optionally write a de-duplicated copy as a separate file.

**Acceptance:** Run log shows ReportedTotal, Retrieved, Duplicates. A mismatch produces a visible warning.

**Status (2026-10-07):** Done for mismatch warning + duplicate count in the run log. Not done: a de-duplicated copy as a separate file -- the doc calls that optional, so it was left out; say if you want it added.

## 5. Built-in time slicing and HighCompleteness

**Where:** `Get-M365UnifiedAuditLog.ps1` parameters and main logic.

**Current behavior:** One `Search-UnifiedAuditLog` session for the whole window, capped at 50,000 records (Microsoft's documented session limit). The SOP works around this with an external per-day loop.

**Change:**
- Add `-SliceHours <int>` (e.g. default off, or 24). When set, split the window into consecutive slices, run a separate paged session per slice, and write one JSON file per slice (or one combined file plus per-slice counts in the run log). If any slice hits the cap, automatically subdivide it (e.g. halve the slice) and retry, logging what happened.
- Add a `-HighCompleteness` switch passed through to `Search-UnifiedAuditLog` (slower, more complete search mode). Note in help that Microsoft has announced plans to change this parameter's behavior.

**Acceptance:** A window that exceeds 50,000 records is fully retrieved without manual re-runs, and per-slice counts appear in the run log.

**Status (2026-10-07):** Done. `-SliceHours` splits the window; a slice that still hits `-MaxRecords` is halved and retried automatically (up to 8 levels deep). `-HighCompleteness` passes through to `Search-UnifiedAuditLog`. This is the most structurally novel part of this change and the one most worth testing by hand against a real tenant before relying on it -- no PowerShell interpreter was available to run it during development.

## 6. Explicit UTC handling for dates

**Where:** `Get-M365UnifiedAuditLog.ps1`, `StartDate` / `EndDate` parameters.

**Current behavior:** Parameters are `[datetime]`, so PowerShell may interpret input as local time before it reaches Microsoft, shifting the window by the local UTC offset.

**Change:** Treat input as UTC (e.g. convert with `[datetime]::SpecifyKind(..., 'Utc')` when Kind is Unspecified, or accept `[datetimeoffset]`). Record in the run log both the value as typed and the UTC value sent. After acquisition, record the earliest and latest event `CreationTime` and warn if they fall outside the requested window.

**Acceptance:** Same input produces the same UTC window on machines in different time zones; run log shows requested window and observed event range.

**Status (2026-10-07):** Done. `-StartDate`/`-EndDate` are explicitly marked UTC via `[datetime]::SpecifyKind`; the console also prints the UTC window being searched (not just the run log), and a mismatch between the requested window and the observed event CreationTime range produces a warning.

## 7. Keep secrets off the command line

**Where:** `Get-M365CompromiseInfo.psm1` (`-ipinfoAPIKey`, `-ipqsAPIKey`, `-scamalyticsAPIKey`), `src/PrimaryModules/Get-emailInfoFromInternetMessageID.ps1` (`-ClientSecret`).

**Current behavior:** Keys and the Graph client secret are plain-text string parameters, so they end up in PSReadLine history and transcripts. `Get-DehashedLookup` already defaults to `$env:DEHASHED_API_KEY`; use that as the model.

**Change:**
- Default each API key parameter to an environment variable (e.g. `$env:IPINFO_API_KEY`, `$env:IPQS_API_KEY`, `$env:SCAMALYTICS_API_KEY`).
- For `Get-emailInformation`, accept the secret as `[securestring]` or from `$env:GRAPH_CLIENT_SECRET`, and add certificate-based authentication (`-CertificateThumbprint`) as the preferred option.
- Make sure no key or secret is ever echoed to the console or written to output files.

**Acceptance:** All lookups and Graph calls work with no secret typed on the command line.

**Status (2026-10-05):** `Get-emailInformation` no longer writes the access token to verbose output. The secret is still a plain-text `-ClientSecret` parameter; `[securestring]`/environment-variable input and certificate auth are still open.

## 8. Scamalytics account parameter and help-text cleanup

**Where:** `src/SupportingModules/Get-IPAddressInfo.psm1`, `Get-Scamalytics_lookup` (around the line building `$scamalyticsurl`); help examples in `Get-emailInfoFromInternetMessageID.ps1`.

**Current behavior:** The Scamalytics API URL has a fixed account name in the path: `https://api11.scamalytics.com/greycastlesecurity/?key=...`. Help examples reference a `greycastlesandbox.onmicrosoft.com` tenant.

**Change:** Add a `-scamalyticsUser` parameter (default from `$env:SCAMALYTICS_USER`) and build the URL from it; consider making the API host configurable too. Replace example tenant names with neutral ones (e.g. `contoso.onmicrosoft.com`).

**Acceptance:** Scamalytics lookups run under Placid Security's own account with no hard-coded account name in the code.

**Status (2026-10-05):** The help example in `Get-emailInfoFromInternetMessageID.ps1` now uses `contoso.onmicrosoft.com`. The Scamalytics change is still open.

## 9. Record the Microsoft endpoint data used for the IP allowlist

**Where:** `Get-IPAddressInfo.psm1`, `Get-MicrosoftIPRanges` (calls `https://endpoints.office.com/endpoints/worldwide?clientrequestid=...`).

**Current behavior:** Endpoint data is fetched live each run; excluded IPs are written to `MicrosoftAllowlistedIPs.txt`, but the endpoint data version used is not saved.

**Change:** Also call `https://endpoints.office.com/version/worldwide?clientrequestid=...` and record the version (and fetch time UTC) in `MicrosoftAllowlistedIPs.txt` header and in the Detection Rule Parameters summary. Optionally save the fetched endpoint JSON to the output directory.

**Acceptance:** A later reviewer can tell exactly which Microsoft endpoint list version drove the allowlist.

## 10. Full detail for UpdateInboxRules events

**Where:** `src/PrimaryModules/Get-M365CompromiseInfo.psm1`, `Get-MailboxRuleInfo` (reads `$RuleEvent.Parameters`), and the mailbox rule loop that uses `$mailboxRuleOperations`.

**Current behavior:** `UpdateInboxRules` events (rules changed from Outlook or EWS) are included in `MailboxRuleActivity.csv`, but their rule details live in `OperationProperties`, not `Parameters`, so RuleName, ForwardTo, RedirectTo, DeleteMessage and related columns are blank and `AllParameters` is likely empty.

**Change:** In `Get-MailboxRuleInfo`, when `Operation -eq 'UpdateInboxRules'` (or `Parameters` is empty), read `OperationProperties` instead, the same way `Get-MailItemsAccessedInfo` already does for MailItemsAccessed. Map at least RuleName, RuleId, RuleOperation, RuleActions, RuleCondition, RuleState and Provider where present, and include all OperationProperties name/value pairs in the `AllParameters` column. Test against real UpdateInboxRules samples, since property names vary.

**Acceptance:** UpdateInboxRules rows in `MailboxRuleActivity.csv` show the rule name and actions.

## 11. Mailbox forwarding and transport rules in the rule activity output

**Where:** `Get-M365CompromiseInfo.psm1`, `$mailboxRuleOperations` and the rule activity loop.

**Current behavior:** Only New/Set/Remove/Enable/Disable-InboxRule and UpdateInboxRules are captured. Forwarding set directly on a mailbox (`Set-Mailbox -ForwardingSmtpAddress / -ForwardingAddress / -DeliverToMailboxAndForward`) and tenant-wide transport rules (`New-TransportRule`, `Set-TransportRule`, `Remove-TransportRule`, `Enable-TransportRule`, `Disable-TransportRule`) are not included.

**Change:**
- Include `Set-Mailbox` events only when their `Parameters` contain ForwardingSmtpAddress, ForwardingAddress or DeliverToMailboxAndForward; extract those values.
- Include transport rule operations; extract rule name and actions (e.g. RedirectMessageTo, BlindCopyTo, CopyTo, DeleteMessage) plus all parameters.
- Either add a `ChangeType` column (InboxRule, MailboxForwarding, TransportRule) to `MailboxRuleActivity.csv` or write separate CSVs. Keep the `FromFlaggedIP` column and the "not filtered by IP reputation" behavior.
- Update the Detection Rule Parameters summary to list the operations monitored.

**Acceptance:** A test UAL containing a `Set-Mailbox -ForwardingSmtpAddress` event and a `New-TransportRule` with a redirect action produces rows for both.

## 12. Consider the Purview Audit Search Graph API

**Where:** New function, e.g. `Get-M365AuditLogGraph`.

**Current state:** Acquisition depends on `Search-UnifiedAuditLog`. Microsoft points to the Audit Search Graph API (`security/auditLog/queries`) for programmatic and large-volume access.

**Change:** Evaluate an alternative acquisition function using the Graph API that writes the same JSON format plus the manifest and run log from item 1. Keep `Get-M365UnifiedAuditLog` as the default until the Graph path is validated.

**Acceptance:** For the same tenant and window, both functions produce matching event counts (within documented differences), and `Get-M365CompromiseInfo` analyzes either output unchanged.

---

## Test expectations

- Add or extend Pester tests where practical: manifest hash matches file, run log fields present, parse-failure accounting, duplicate detection, UTC window conversion, UpdateInboxRules parsing, Set-Mailbox and transport rule capture.
- Add sample events to `Test_data` for UpdateInboxRules, Set-Mailbox forwarding and New-TransportRule (sanitized).
- Re-run against the existing `Test_data\M365Output` set and confirm existing CSV outputs are unchanged apart from new columns.

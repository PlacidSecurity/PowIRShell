function Get-DehashedLookup {
  <#
  .Synopsis
    *API KEY REQUIRED* This script checks a list of email addresses against DeHashed
    (https://dehashed.com/), and returns whether each one turns up in a known breach.
  .Description
    Dehashed.com is a breach/credential exposure search engine, useful for checking
    whether a client's user accounts have been caught in a known breach as part of
    a compromise investigation or a proactive assessment. This function has two
    optional input parameters, $EmailListPath and $emailListArray. If $EmailListPath
    is specified, the function reads email addresses from a text file, one per line.
    If $emailListArray is specified, it uses an array of addresses passed in directly.
    The function queries the DeHashed v2 API once per email address and, by default,
    returns one row per email: whether it was found, how many records, and which
    breach source(s). Pass -Detail to instead get one row per individual breach
    record, with full field detail (username, password/hash, name, phone, IP, etc.).
    Results are written to dehashedresults.csv (or dehasheddetail.csv with -Detail)
    in the directory specified by outputdir. Errors are logged to dehashed_errors.txt
    in the same directory.
  .Parameter EmailListPath
    Path to a text file list of email addresses separated by a carriage return.
    This function can also be used in other scripts by passing an array of email
    addresses as the $emailListArray parameter.
  .Parameter emailListArray
    An array of email addresses passed into the function.
  .Parameter dehashedAPIKey
    API key for DeHashed https://dehashed.com/. Defaults to $env:DEHASHED_API_KEY
    if set, so it doesn't have to be typed on the command line every time.
  .Parameter outputdir
    Path to the directory where the output and error log files will be written.
  .Parameter Detail
    Switch. Return one row per individual breach record (full field detail) instead
    of one row per email address (summary).
  .Inputs
    Either a text file containing a list of email addresses, or an array of email
    addresses.
  .Outputs
    Outputs are written to the directory specified with the outputdir parameter:
    1. A CSV file with the lookup results -- dehashedresults.csv (summary) or
       dehasheddetail.csv (-Detail), and:
    2. An error log file named dehashed_errors.txt
  #>
  [CmdletBinding()]
  param (
    [string]$dehashedAPIKey = $env:DEHASHED_API_KEY,
    [Parameter(Mandatory = $true)]
    [string]$outputdir,
    [string]$EmailListPath,
    [array]$emailListArray,
    [switch]$Detail
  )

  if (-not $dehashedAPIKey) {
    throw "No DeHashed API key provided. Pass -dehashedAPIKey or set `$env:DEHASHED_API_KEY."
  }

  if ($emailListArray) {
    $emails = $emailListArray
  }
  elseif ($EmailListPath) {
    $emails = Get-Content $EmailListPath
  }
  else {
    throw "No email addresses specified"
  }

  # de-dupe, case-insensitive, preserve order -- a client roster often has repeats
  $seen = @{}
  $uniqueEmails = @()
  foreach ($e in $emails) {
    $trimmed = ([string]$e).Trim()
    if ($trimmed -and -not $seen.ContainsKey($trimmed.ToLowerInvariant())) {
      $seen[$trimmed.ToLowerInvariant()] = $true
      $uniqueEmails += $trimmed
    }
  }
  $emails = $uniqueEmails

  # Filter out blank/malformed entries so one bad line doesn't derail the whole batch
  $emailRegex = '^[^@\s]+@[^@\s]+\.[^@\s]+$'
  $validEmails = @()
  $failures = @()
  foreach ($e in $emails) {
    if ($e -match $emailRegex) {
      $validEmails += $e
    }
    else {
      $failures += [PSCustomObject]@{ Item = $e; Reason = "invalid email format, skipped" }
    }
  }
  if ($failures.Count -gt 0) {
    Write-Host "Skipped $($failures.Count) invalid/unparseable entr$(if ($failures.Count -eq 1) { 'y' } else { 'ies' }) from the input list" -ForegroundColor Yellow
  }
  $emails = $validEmails

  Write-Host "There are $($emails.Count) email address(es) to check" -ForegroundColor Green
  $lookupfailure = 0
  $hits = 0
  $dehashedUrl = "https://api.dehashed.com/v2/search"
  $exportarray = @()
  $lastBalance = $null

  # Fields pulled out of each raw record for -Detail mode
  $detailFields = @(
    "database_name", "username", "name", "phone", "ip_address",
    "address", "company", "domain", "password", "hashed_password",
    "hash_type", "vin"
  )

  foreach ($email in $emails) {
    Write-Verbose "Checking $email"

    $headers = @{
      "Dehashed-Api-Key" = $dehashedAPIKey
      "Accept"           = "application/json"
    }
    $bodyJson = @{
      query    = 'email:"' + $email + '"'
      page     = 1
      size     = 10000
      wildcard = $false
      regex    = $false
      de_dupe  = $true
    } | ConvertTo-Json

    try {
      $result = Invoke-RestMethod -Uri $dehashedUrl -Method Post -Headers $headers -ContentType "application/json" -Body $bodyJson
    }
    catch {
      # DeHashed rate-limits aggressively (HTTP 429); give it one retry before logging a failure
      $statusCode = $null
      try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
      if ($statusCode -eq 429) {
        Write-Host "Rate limited on $email, waiting 5s and retrying once..." -ForegroundColor Yellow
        Start-Sleep -Seconds 5
        try {
          $result = Invoke-RestMethod -Uri $dehashedUrl -Method Post -Headers $headers -ContentType "application/json" -Body $bodyJson
        }
        catch {
          $errorMessage = "There was an error retrieving information for " + "$email $($_.Exception.Message)"
          Write-Error $errorMessage
          $errorMessage | Out-File -Append $outputdir\dehashed_errors.txt -Encoding UTF8
          $lookupfailure++
          $failures += [PSCustomObject]@{ Item = $email; Reason = "rate limited, retry failed: $($_.Exception.Message)" }
          continue
        }
      }
      else {
        $errorMessage = "There was an error retrieving information for " + "$email $($_.Exception.Message)"
        Write-Error $errorMessage
        $errorMessage | Out-File -Append $outputdir\dehashed_errors.txt -Encoding UTF8
        $lookupfailure++
        $failures += [PSCustomObject]@{ Item = $email; Reason = $_.Exception.Message }
        continue
      }
    }

    if ($null -ne $result.balance) { $lastBalance = $result.balance }
    $entries = @()
    if ($result.entries) { $entries = @($result.entries) }
    if ($entries.Count -gt 0) { $hits++ }

    if ($Detail) {
      if ($entries.Count -eq 0) {
        $row = [ordered]@{ email_searched = $email; found = "no" }
        foreach ($f in $detailFields) { $row[$f] = "" }
        $exportarray += [PSCustomObject]$row
      }
      else {
        foreach ($entry in $entries) {
          $row = [ordered]@{ email_searched = $email; found = "yes" }
          foreach ($f in $detailFields) {
            $val = $entry.$f
            if ($val -is [array]) { $val = ($val -join "; ") }
            $row[$f] = $val
          }
          $exportarray += [PSCustomObject]$row
        }
      }
    }
    else {
      $databases = @()
      foreach ($entry in $entries) {
        $db = $entry.database_name
        if ($db -is [array]) { $db = ($db -join "; ") }
        if ($db) { $databases += $db }
      }
      $databases = $databases | Sort-Object -Unique
      $arrayItems = [PSCustomObject]@{
        "email"        = $email
        "found"        = if ($entries.Count -gt 0) { "yes" } else { "no" }
        "breach_count" = $entries.Count
        "databases"    = ($databases -join "; ")
      }
      $exportarray += $arrayItems
    }
  }

  Write-Host "There were $lookupfailure lookup failures out of $($emails.Count)" -ForegroundColor Yellow
  Write-Host "$hits of $($emails.Count) email address(es) had at least one breach hit" -ForegroundColor Green
  if ($null -ne $lastBalance) {
    Write-Host "DeHashed credits remaining: $lastBalance" -ForegroundColor Green
  }
  if ($failures.Count -gt 0) {
    Write-Host "Failed/skipped items ($($failures.Count)):" -ForegroundColor Red
    $failures | ForEach-Object { Write-Host "  $($_.Item): $($_.Reason)" -ForegroundColor Red }
  }

  $outFile = if ($Detail) { "dehasheddetail.csv" } else { "dehashedresults.csv" }
  $exportarray | Export-Csv -Path $outputdir\$outFile -NoTypeInformation -Encoding UTF8
  Write-Host "Results written to $outputdir\$outFile" -ForegroundColor Green
  return $exportarray
}

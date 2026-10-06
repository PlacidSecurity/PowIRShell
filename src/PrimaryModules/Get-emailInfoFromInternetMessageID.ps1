
function Get-emailInformation{
<#
.SYNOPSIS
    Uses a CSV file with InternetMessageId to get email information from Microsoft Graph API, and optionally export
    each matching message as a full .eml file.  It can be useful when you have a list of InternetMessageId attributes
    from the M365 MailItemsAccessed audit event, and want to know what emails were accessed.  This is an ancillary
    script to the M365compromiseInfo script.
.DESCRIPTION
The script uses a CSV file with InternetMessageId to get email information from Microsoft Graph API.
The CSV file requires a field with a header InternetMessageID, with the ID in the format:
<BL3PR01MB6835B5EE5557113C20F3805ECA559@BL3PR01MB6835.prod.exchangelabs.com>. If you used the Get-M365CompromiseInfo function
in this module, the output file named 'MaliciousMailItemsAccessed.csv' is formatted properly to use as input.

This function requires an app registration in Entra ID with the application permission Mail.Read, with admin consent,
and a client secret for the registered app. If the tenant scopes app mailbox access (Application Access Policy or
RBAC for Applications), the target mailbox must be in scope.

Search behavior:
- Each ID is searched in the mailbox's normal folders (/messages, which includes Deleted Items).
- If not found there, it is searched in Recoverable Items\Deletions (soft-deleted items).
- Graph cannot reach the online archive mailbox or Recoverable Items\Purges; use Purview eDiscovery for those.
- Every input ID gets an output row; Status is Found, NotFound, or Error.

Output (in -outputpath):
- emaildetails.csv : one row per matching message (or per not-found/error ID).
- eml\*.eml        : with -ExportEml, the full MIME of each message (headers, body, attachments).
  The SHA-256 of each file and the UTC collection time are recorded in the CSV. Note that Exchange generates the MIME
  at request time, so the .eml is not byte-identical to the message as originally received, and a re-export may hash
  differently.
.PARAMETER TenantId
    The TenantId of the Entra ID tenant.
.PARAMETER ClientId
    The ClientId of the registered app.
.PARAMETER ClientSecret
    The ClientSecret of the registered app.
.PARAMETER pathtoCSV
    The path to the CSV file with the InternetMessageId.  The CSV file requires a field with a header InternetMessageID.
.PARAMETER outputpath
    The folder for the output files.
.PARAMETER UserId
    The account for the mailbox you want to query.
.PARAMETER ExportEml
    Also download each matching message as a .eml file into <outputpath>\eml.
.EXAMPLE
    Get-emailInformation -TenantId "12345678-1234-1234-1234-123456789012" -ClientId "12345678-1234-1234-1234-123456789012"
    -ClientSecret "<secret>" -pathtoCSV "C:\temp\maliciousMailItemsAccessed.csv" -outputpath "C:\temp"
    -UserId "victimuser@contoso.onmicrosoft.com" -ExportEml
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$TenantId,
    [Parameter(Mandatory=$true)]
    [string]$ClientId,
    [Parameter(Mandatory=$true)]
    [string]$ClientSecret,
    [Parameter(Mandatory=$true)]
    $pathtoCSV,
    [Parameter(Mandatory=$true)]
    $outputpath,
    [Parameter(Mandatory=$true)]
    $UserId,
    [switch]$ExportEml
)
$dataFromCSV = Import-Csv $pathtoCSV
$graphBase   = "https://graph.microsoft.com/v1.0/users/$([uri]::EscapeDataString($UserId))"
$messageSelect = @(
    'id','internetMessageId','subject','receivedDateTime','sentDateTime','createdDateTime','lastModifiedDateTime',
    'from','sender','replyTo','toRecipients','ccRecipients','bccRecipients','importance','hasAttachments',
    'isRead','isDraft','categories','parentFolderId','conversationId','internetMessageHeaders'
) -join ','
$folderNameCache = @{}

function Get-GraphApiAccessToken {
    param (
        [Parameter(Mandatory=$true)][string]$TenantId,
        [Parameter(Mandatory=$true)][string]$ClientId,
        [Parameter(Mandatory=$true)][string]$ClientSecret
    )
    $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $tokenRequest = @{
        client_id     = $ClientId
        scope         = "https://graph.microsoft.com/.default"
        client_secret = $ClientSecret
        grant_type    = "client_credentials"
    }
    try {
        # Invoke-RestMethod avoids the Internet Explorer parsing dependency of Invoke-WebRequest in Windows PowerShell 5.1
        $tokenResponse = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $tokenRequest -ContentType "application/x-www-form-urlencoded"
    } catch {
        throw "Token generation failed: $_"
    }
    if (-not $tokenResponse.access_token) { throw "Token generation failed: No access token in response" }
    Write-Host "Token generated successfully" -ForegroundColor Yellow
    return [pscustomobject]@{
        Token   = $tokenResponse.access_token
        Expires = (Get-Date).AddSeconds([int]$tokenResponse.expires_in - 300)
    }
}

function Invoke-GraphGet {
    # GET with basic retry on 429 / 503 / 504, honoring Retry-After. -OutFile streams the response to disk.
    param ([string]$Uri, [string]$AccessToken, [string]$OutFile)
    $headers = @{ "Authorization" = "Bearer $AccessToken" }
    $irmArgs = @{ Uri = $Uri; Headers = $headers; Method = 'Get' }
    if ($OutFile) { $irmArgs.OutFile = $OutFile }
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        try {
            return Invoke-RestMethod @irmArgs
        } catch {
            $resp = $_.Exception.Response
            $code = if ($resp) { [int]$resp.StatusCode } else { 0 }
            if ($code -notin 429, 503, 504 -or $attempt -eq 5) { throw }
            $wait = 10
            try {
                if ($resp.Headers.RetryAfter.Delta) { $wait = [int]$resp.Headers.RetryAfter.Delta.TotalSeconds }  # PowerShell 7
                elseif ($resp.Headers['Retry-After']) { $wait = [int]$resp.Headers['Retry-After'] }              # Windows PowerShell 5.1
            } catch {}
            Write-Warning "Graph returned $code; retrying in $wait seconds (attempt $attempt)"
            Start-Sleep -Seconds $wait
        }
    }
}

function ConvertTo-UtcString ($value) {
    # PowerShell 7 turns Graph ISO-8601 strings into culture-formatted [datetime]; keep output unambiguous UTC
    if ($value -is [datetime]) { return $value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
    return $value
}

function Join-Addresses ($recipients) {
    # Don't use $x.toRecipients.emailAddress.address -- with 2+ recipients, '.address' binds to the
    # built-in Array.Address() method instead of enumerating, and the CSV gets a method signature.
    return (@($recipients | ForEach-Object { $_.emailAddress.address }) -join "; ")
}

function Get-HeaderValue ($headers, [string]$name) {
    return (@($headers | Where-Object { $_.name -eq $name } | ForEach-Object { $_.value }) -join " | ")
}

function Get-FolderName ([string]$AccessToken, [string]$FolderId) {
    if (-not $FolderId) { return $null }
    if (-not $folderNameCache.ContainsKey($FolderId)) {
        try {
            $folder = Invoke-GraphGet -Uri "$graphBase/mailFolders/$([uri]::EscapeDataString($FolderId))?`$select=displayName" -AccessToken $AccessToken
            $folderNameCache[$FolderId] = $folder.displayName
        } catch {
            $folderNameCache[$FolderId] = "(unresolved)"
        }
    }
    return $folderNameCache[$FolderId]
}

function Get-SafeFileName ([string]$InternetMessageId, [string]$GraphId) {
    # Readable part from the Message-ID, plus a short hash of the Graph ID so two copies of one message don't collide
    $base = $InternetMessageId.Trim().Trim('<', '>')
    foreach ($c in [IO.Path]::GetInvalidFileNameChars()) { $base = $base.Replace([string]$c, '_') }
    if ($base.Length -gt 120) { $base = $base.Substring(0, 120) }
    $sha = [Security.Cryptography.SHA256]::Create()
    $idHash = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($GraphId))[0..3] | ForEach-Object { $_.ToString('x2') })
    return "$base`_$idHash.eml"
}

function Get-EmailAttachmentNames {
    param (
        [Parameter(Mandatory=$true)][string]$AccessToken,
        [Parameter(Mandatory=$true)][string]$idFromMessage
    )
    # $select keeps Graph from returning base64 contentBytes for every attachment
    $uri = "$graphBase/messages/$([uri]::EscapeDataString($idFromMessage))/attachments?`$select=name,contentType,size,lastModifiedDateTime"
    Write-Verbose "URI: $uri"
    $result = @()
    while ($uri) {
        $response = Invoke-GraphGet -Uri $uri -AccessToken $AccessToken
        foreach ($attachmentinfo in $response.value) {
            $result += [pscustomobject]@{
                Timestamp   = $attachmentinfo.lastModifiedDateTime
                Name        = $attachmentinfo.name
                ContentType = $attachmentinfo.contentType
            }
        }
        $uri = $response.'@odata.nextLink'
    }
    return $result
}

function Find-Messages {
    # Returns @{ Location = ...; Messages = @(...) } -- normal folders first, then Recoverable Items\Deletions
    param ([string]$AccessToken, [string]$InternetMessageId)
    # Escape single quotes for OData, then URL-encode so '+', '/', '=', '#', '&' survive the trip
    $odataValue = $InternetMessageId.Trim().Replace("'", "''")
    $query = "`$filter=$([uri]::EscapeDataString("internetMessageId eq '$odataValue'"))&`$select=$messageSelect"
    $scopes = [ordered]@{
        "Mailbox"                      = "$graphBase/messages?$query"
        "RecoverableItems\Deletions"   = "$graphBase/mailFolders/recoverableitemsdeletions/messages?$query"
    }
    foreach ($location in $scopes.Keys) {
        Write-Verbose "URI: $($scopes[$location])"
        $response = Invoke-GraphGet -Uri $scopes[$location] -AccessToken $AccessToken
        if (@($response.value).Count -gt 0) {
            return @{ Location = $location; Messages = @($response.value) }
        }
    }
    return @{ Location = $null; Messages = @() }
}

function Get-EmailDetails {
    param (
        [Parameter(Mandatory=$true)][string]$AccessToken,
        [Parameter(Mandatory=$true)][string]$InternetMessageId
    )
    $found = Find-Messages -AccessToken $AccessToken -InternetMessageId $InternetMessageId
    $result = @()
    foreach ($message in $found.Messages) {
        $attachments = @()
        if ($message.hasAttachments) {
            $attachments = Get-EmailAttachmentNames -AccessToken $AccessToken -idFromMessage $message.id
        }

        $emlFile = $null; $emlSha256 = $null; $collectedUtc = $null
        if ($ExportEml) {
            $emlFile = Join-Path $emlDir (Get-SafeFileName $InternetMessageId $message.id)
            try {
                Invoke-GraphGet -Uri "$graphBase/messages/$([uri]::EscapeDataString($message.id))/`$value" -AccessToken $AccessToken -OutFile $emlFile | Out-Null
                $collectedUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                $emlSha256 = (Get-FileHash -Path $emlFile -Algorithm SHA256).Hash
            } catch {
                Write-Warning "EML export failed for $InternetMessageId : $_"
                $emlFile = "EXPORT FAILED: $_"
            }
        }

        $hdrs = $message.internetMessageHeaders
        $result += [pscustomobject][ordered]@{
            InternetMessageId   = $InternetMessageId
            Status              = "Found"
            Location            = $found.Location
            Folder              = Get-FolderName $AccessToken $message.parentFolderId
            Timestamp           = ConvertTo-UtcString $message.receivedDateTime
            SentDateTime        = ConvertTo-UtcString $message.sentDateTime
            CreatedDateTime     = ConvertTo-UtcString $message.createdDateTime
            LastModifiedDateTime = ConvertTo-UtcString $message.lastModifiedDateTime
            Subject             = $message.subject
            Senders             = $message.from.emailAddress.address
            SenderMailbox       = $message.sender.emailAddress.address   # differs from Senders for send-on-behalf / send-as
            ReplyTo             = Join-Addresses $message.replyTo
            Recipients          = Join-Addresses $message.toRecipients
            CcRecipients        = Join-Addresses $message.ccRecipients
            BccRecipients       = Join-Addresses $message.bccRecipients
            Attachments         = (@($attachments.Name) -join "; ")
            AttachmentType      = (@($attachments.ContentType) -join "; ")
            Importance          = $message.importance
            IsRead              = $message.isRead
            IsDraft             = $message.isDraft
            Categories          = (@($message.categories) -join "; ")
            ReturnPath          = Get-HeaderValue $hdrs 'Return-Path'
            OriginatingIP       = Get-HeaderValue $hdrs 'X-Originating-IP'
            AuthenticationResults = Get-HeaderValue $hdrs 'Authentication-Results'
            ConversationId      = $message.conversationId
            ID                  = $message.id
            EmlFile             = $emlFile
            EmlSha256           = $emlSha256
            CollectedUtc        = $collectedUtc
        }
    }
    return $result
}

function New-StatusRow ($InternetMessageId, $Status, $Note) {
    [pscustomobject][ordered]@{
        InternetMessageId = $InternetMessageId; Status = $Status; Location = $null; Folder = $null; Timestamp = $null
        SentDateTime = $null; CreatedDateTime = $null; LastModifiedDateTime = $null; Subject = $Note; Senders = $null
        SenderMailbox = $null; ReplyTo = $null; Recipients = $null; CcRecipients = $null; BccRecipients = $null
        Attachments = $null; AttachmentType = $null; Importance = $null; IsRead = $null; IsDraft = $null; Categories = $null
        ReturnPath = $null; OriginatingIP = $null; AuthenticationResults = $null; ConversationId = $null; ID = $null
        EmlFile = $null; EmlSha256 = $null; CollectedUtc = $null
    }
}

$outFile = Join-Path $outputpath "emaildetails.csv"
$emlDir  = Join-Path $outputpath "eml"
if ($ExportEml -and -not (Test-Path $emlDir)) { New-Item -ItemType Directory -Path $emlDir | Out-Null }
$tokenInfo = Get-GraphApiAccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret

foreach ($item in $dataFromCSV.InternetMessageId) {
    if ([string]::IsNullOrWhiteSpace($item)) { continue }
    if ((Get-Date) -ge $tokenInfo.Expires) {
        $tokenInfo = Get-GraphApiAccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
    }
    try {
        $emailDetails = Get-EmailDetails -AccessToken $tokenInfo.Token -InternetMessageId $item
        if (-not $emailDetails) {
            Write-Host "Not found: $item" -ForegroundColor DarkYellow
            $emailDetails = New-StatusRow $item "NotFound" $null
        }
    } catch {
        Write-Warning "Lookup failed for $item : $_"
        $emailDetails = New-StatusRow $item "Error" "$_"
    }
    $emailDetails | Export-Csv -Path $outFile -Append -NoTypeInformation -Force
}
Write-Host "Results written to $outFile" -ForegroundColor Green
if ($ExportEml) { Write-Host "EML files written to $emlDir" -ForegroundColor Green }
}

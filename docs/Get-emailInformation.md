---
external help file: Get-M365CompromiseInfo-help.xml
Module Name: M365CompromiseInfo
online version:
schema: 2.0.0
---

# Get-emailInformation

## SYNOPSIS
Looks up emails by InternetMessageId through Microsoft Graph, writes their details to a CSV, and optionally exports
each one as a full .eml file. Use it to find out what was in the emails listed in M365 MailItemsAccessed audit events.
It is a companion to Get-M365CompromiseInfo.

## SYNTAX

```
Get-emailInformation [-TenantId] <String> [-ClientId] <String> [-ClientSecret] <String> [-pathtoCSV] <Object>
 [-outputpath] <Object> [-UserId] <Object> [-ExportEml] [<CommonParameters>]
```

## DESCRIPTION
Reads a CSV with an InternetMessageId column, with IDs in the format
\<BL3PR01MB6835B5EE5557113C20F3805ECA559@BL3PR01MB6835.prod.exchangelabs.com\>.
The MaliciousMailItemsAccessed.csv file produced by Get-M365CompromiseInfo can be used as input as-is.

Each ID is searched for in the mailbox's normal folders (including Deleted Items). If it is not found there, it is
searched for in Recoverable Items\Deletions. Graph cannot reach the online archive mailbox or Recoverable Items\Purges;
use Purview eDiscovery for those.

Every input ID gets at least one row in emaildetails.csv, with a Status of Found, NotFound, or Error. An ID can produce
more than one Found row if the same message exists in more than one folder.

With -ExportEml, each matching message is also saved as a .eml file (full MIME: headers, body, and attachments) in
\<outputpath\>\eml, and its SHA-256 hash and UTC collection time are recorded in the CSV. Exchange generates the MIME
when it is requested, so the .eml is not byte-identical to the message as originally received, and exporting the same
message again may produce a different hash. Record the hash at collection time.

Requirements:
- An app registration in Entra ID with the Mail.Read application permission and admin consent, and a client secret.
- If the tenant limits which mailboxes apps can read (Application Access Policy or RBAC for Applications), the target
  mailbox must be in scope.
- Windows PowerShell 5.1 or PowerShell 7.

Throttled requests (HTTP 429, 503, 504) are retried automatically, honoring Retry-After.

## EXAMPLES

### Example 1
```powershell
PS C:\> Get-emailInformation -TenantId "12345678-1234-1234-1234-123456789012" -ClientId "12345678-1234-1234-1234-123456789012" -ClientSecret "<secret>" -pathtoCSV "C:\temp\365Comp\MaliciousMailItemsAccessed.csv" -outputpath "C:\temp\365Comp" -UserId "victimuser@contoso.onmicrosoft.com"
```

Looks up every InternetMessageId in MaliciousMailItemsAccessed.csv in the victim's mailbox and writes
C:\temp\365Comp\emaildetails.csv.

### Example 2
```powershell
PS C:\> Get-emailInformation -TenantId "12345678-1234-1234-1234-123456789012" -ClientId "12345678-1234-1234-1234-123456789012" -ClientSecret "<secret>" -pathtoCSV "C:\temp\365Comp\MaliciousMailItemsAccessed.csv" -outputpath "C:\temp\365Comp" -UserId "victimuser@contoso.onmicrosoft.com" -ExportEml
```

Same as Example 1, and also saves each matching email to C:\temp\365Comp\eml\ as a .eml file, with its SHA-256 hash in
the CSV.

## PARAMETERS

### -TenantId
The tenant ID (GUID) of the Entra ID tenant.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ClientId
The application (client) ID of the app registration.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ClientSecret
A client secret for the app registration.

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

### -pathtoCSV
Path to the input CSV. It must have a column with the header InternetMessageId.

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: True
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -outputpath
Folder for the output. emaildetails.csv is written here (appended to if it already exists), and .eml files go in an
eml subfolder.

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: True
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -UserId
UPN or object ID of the mailbox to search.

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: True
Position: 6
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExportEml
Also save each matching email as a .eml file in \<outputpath\>\eml, and record its SHA-256 hash and UTC collection
time in the CSV.

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

### CSV file
A CSV with an InternetMessageId column, such as MaliciousMailItemsAccessed.csv from Get-M365CompromiseInfo.

## OUTPUTS

### emaildetails.csv
One row per matching email, or per ID that was not found or failed. Columns:

| Column | Meaning |
|---|---|
| InternetMessageId | The ID from the input CSV |
| Status | Found, NotFound, or Error (for Error, the message is in Subject) |
| Location | Mailbox (normal folders) or RecoverableItems\Deletions |
| Folder | Display name of the folder the email is in |
| Timestamp | Received time (UTC) |
| SentDateTime, CreatedDateTime, LastModifiedDateTime | UTC. A recent LastModifiedDateTime on an old email can indicate it was moved or changed. |
| Subject | Subject line |
| Senders | The From address |
| SenderMailbox | The mailbox that actually sent it. Differs from Senders for send-on-behalf or send-as. |
| ReplyTo | Reply-To addresses |
| Recipients, CcRecipients, BccRecipients | Semicolon-separated. Bcc is only populated on the sender's copy. |
| Attachments, AttachmentType | Attachment names and content types, semicolon-separated |
| Importance, IsRead, IsDraft, Categories | Message flags |
| ReturnPath, OriginatingIP, AuthenticationResults | From the Return-Path, X-Originating-IP and Authentication-Results headers (SPF/DKIM/DMARC) |
| ConversationId | Use to find the rest of the thread |
| ID | Graph message ID (changes if the email is moved) |
| EmlFile, EmlSha256, CollectedUtc | With -ExportEml: path, SHA-256 hash and UTC time of the exported .eml |

### eml\\*.eml
With -ExportEml, one .eml file per matching email, named from the InternetMessageId plus a short hash of the Graph ID.

## NOTES
The ID column and the .eml export use the Graph message ID at the time of the run. If the email is moved afterward,
that ID will no longer work; look it up again by InternetMessageId.

## RELATED LINKS
[Get-M365CompromiseInfo](Get-M365CompromiseInfo.md)

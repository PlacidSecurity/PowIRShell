---
external help file: Get-M365CompromiseInfo-help.xml
Module Name: M365CompromiseInfo
online version:
schema: 2.0.0
---

# Get-AuditdataFrom365JSON

## SYNOPSIS
This function retrieves the audit data from the JSON files in the specified directory.
It has been tested with output from Get-M365UnifiedAuditLog (included in this module)
and with the Invictus Extractor suite, since both produce the same on-disk format:
https://github.com/invictus-ir/Microsoft-Extractor-Suite

## SYNTAX

```
Get-AuditdataFrom365JSON [[-searchdir] <String>] [<CommonParameters>]
```

## DESCRIPTION
This function retrieves the audit data from the JSON files in the specified directory, and returns an array of audit events.
It's a supporting function for the Get-M365ComplianceInfo script.

## EXAMPLES

### Example 1
```powershell
PS C:\> {{ Add example code here }}
```

{{ Add example description here }}

## PARAMETERS

### -searchdir
\[Parameter(Mandatory = $true)\]

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### This scripts takes a single parameter, the path to the directory containing the JSON files. It does not recursively search
### through subdirectories, so ensure that files of interest are in a single directory.
## OUTPUTS

### An array of audit events is returned.
## NOTES

## RELATED LINKS

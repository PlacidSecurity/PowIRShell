---
external help file: Get-M365CompromiseInfo-help.xml
Module Name: M365CompromiseInfo
online version:
schema: 2.0.0
---

# Get-EntraOAuthGrantInventory

## SYNOPSIS
Read-only inventory of OAuth2 delegated permission grants and application
(app-role) permission assignments in a Microsoft Entra ID tenant, with risk
flagging and JSON / XML / CSV output. Built for hunting illicit consent
grants (MITRE T1528) and over-permissioned apps.

## SYNTAX

```
Get-EntraOAuthGrantInventory [[-OutputDir] <String>] [[-Format] <String[]>] [-RiskyOnly]
 [-IncludeAuditLog] [[-Days] <Int32>] [[-TargetAppId] <String>] [<CommonParameters>]
```

## DESCRIPTION
Uses native Microsoft Graph PowerShell cmdlets only (no third-party scripts):
  - Get-MgOauth2PermissionGrant (tenant-wide delegated grants)
  - Get-MgServicePrincipalOauth2PermissionGrant (per-app drilldown, -TargetAppId)
  - Get-MgServicePrincipalAppRoleAssignment (application permissions held by apps)
  - Get-MgServicePrincipal / Get-MgUser (GUID -> name resolution)
  - Get-MgAuditLogDirectoryAudit (optional consent-event correlation)

All calls are READ-only. Least-privilege delegated scopes: Directory.Read.All,
Application.Read.All (+ AuditLog.Read.All if -IncludeAuditLog).

This talks to Microsoft Graph / Entra ID, not the M365 Unified Audit Log the rest
of this module works from -- it does not take a -searchdir and isn't wired into
Get-M365CompromiseInfo's pipeline. Run it standalone, or as a companion check
during a BEC investigation: illicit OAuth consent grants are a well-known way an
attacker keeps mailbox/data access after a password reset, so it's worth running
against the affected user -- and the tenant broadly -- alongside the UAL-based
checks.

## EXAMPLES

### Example 1
```powershell
PS C:\> Get-EntraOAuthGrantInventory -Format All -IncludeAuditLog -Verbose
```

Pulls the full inventory, cross-referenced against the directory audit log, and
writes JSON, XML, and CSV output.

### Example 2
```powershell
PS C:\> Get-EntraOAuthGrantInventory -RiskyOnly -Format Json
```

Emits only Medium/High-risk grants and assignments, as JSON.

### Example 3
```powershell
PS C:\> Get-EntraOAuthGrantInventory -TargetAppId 00000000-0000-0000-0000-000000000000
```

Drills into a single application by its AppId (client ID).

## PARAMETERS

### -OutputDir
Directory for output files. Default: current directory.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: (Get-Location).Path
Accept pipeline input: False
Accept wildcard characters: False
```

### -Format
One or more of Json, Xml, Csv, All. Default: Json.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: Json
Accept pipeline input: False
Accept wildcard characters: False
```

### -RiskyOnly
Emit only Medium/High-risk findings.

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

### -IncludeAuditLog
Also pull recent consent / grant events from the directory audit log.

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

### -Days
Lookback window for -IncludeAuditLog. Default: 30.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: 30
Accept pipeline input: False
Accept wildcard characters: False
```

### -TargetAppId
Drill into a single app by its AppId (client ID). Uses
Get-MgServicePrincipalOauth2PermissionGrant for that SP specifically.

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None. This function takes no pipeline input; all parameters are named/positional.
## OUTPUTS

### A report object (also written to disk as JSON/XML/CSV) containing counts, delegated
### grants, application permission assignments, and (optionally) correlated audit events.
## NOTES
Requires these Microsoft Graph PowerShell modules, checked at runtime rather than via
a module-level #Requires, so importing the rest of PowIRShell doesn't depend on the
Graph SDK being installed:
  Microsoft.Graph.Authentication   >= 2.15.0
  Microsoft.Graph.Applications     >= 2.15.0
  Microsoft.Graph.Identity.SignIns >= 2.15.0
  Microsoft.Graph.Users            >= 2.15.0

## RELATED LINKS

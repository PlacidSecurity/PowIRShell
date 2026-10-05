function Get-EntraOAuthGrantInventory {
<#
.SYNOPSIS
    Read-only inventory of OAuth2 delegated permission grants and application
    (app-role) permission assignments in a Microsoft Entra ID tenant, with risk
    flagging and JSON / XML / CSV output. Built for hunting illicit consent
    grants (MITRE T1528) and over-permissioned apps.

.DESCRIPTION
    Uses native Microsoft Graph PowerShell cmdlets only (no third-party scripts):
      - Get-MgOauth2PermissionGrant               (tenant-wide delegated grants)
      - Get-MgServicePrincipalOauth2PermissionGrant (per-app drilldown, -TargetAppId)
      - Get-MgServicePrincipalAppRoleAssignment    (application permissions held by apps)
      - Get-MgServicePrincipal / Get-MgUser        (GUID -> name resolution)
      - Get-MgAuditLogDirectoryAudit               (optional consent-event correlation)

    All calls are READ-only. Least-privilege delegated scopes:
      Directory.Read.All, Application.Read.All  (+ AuditLog.Read.All if -IncludeAuditLog)

.PARAMETER OutputDir
    Directory for output files. Default: current directory.

.PARAMETER Format
    One or more of Json, Xml, Csv, All. Default: Json.

.PARAMETER RiskyOnly
    Emit only Medium/High-risk findings.

.PARAMETER IncludeAuditLog
    Also pull recent consent / grant events from the directory audit log.

.PARAMETER Days
    Lookback window for -IncludeAuditLog. Default: 30.

.PARAMETER TargetAppId
    Drill into a single app by its AppId (client ID). Uses
    Get-MgServicePrincipalOauth2PermissionGrant for that SP specifically.

.NOTES
    This talks to Microsoft Graph / Entra ID (OAuth2 permission grants and app-role
    assignments), not the M365 Unified Audit Log the rest of this module works from --
    it does not take a -searchdir and isn't wired into Get-M365CompromiseInfo's
    pipeline. Run it standalone, or as a companion check during a BEC investigation:
    illicit OAuth consent grants are a well-known way an attacker keeps mailbox/data
    access after a password reset (MITRE T1528), so it's worth running against the
    affected user -- and the tenant broadly -- alongside the UAL-based checks.

    Requires these Microsoft Graph PowerShell modules, checked at runtime below rather
    than via a file-level #Requires, so importing the rest of PowIRShell doesn't depend
    on the Graph SDK being installed:
      Microsoft.Graph.Authentication   >= 2.15.0
      Microsoft.Graph.Applications     >= 2.15.0
      Microsoft.Graph.Identity.SignIns >= 2.15.0
      Microsoft.Graph.Users            >= 2.15.0

.EXAMPLE
    Get-EntraOAuthGrantInventory -Format All -IncludeAuditLog -Verbose

.EXAMPLE
    Get-EntraOAuthGrantInventory -RiskyOnly -Format Json

.EXAMPLE
    Get-EntraOAuthGrantInventory -TargetAppId 00000000-0000-0000-0000-000000000000
#>
[CmdletBinding()]
param(
    [string]   $OutputDir = (Get-Location).Path,
    [ValidateSet('Json','Xml','Csv','All')]
    [string[]] $Format = @('Json'),
    [switch]   $RiskyOnly,
    [switch]   $IncludeAuditLog,
    [int]      $Days = 30,
    [string]   $TargetAppId
)

# ---------------------------------------------------------------------------
# Runtime dependency check -- intentionally not a file-level #Requires, so
# that Import-Module on the rest of PowIRShell doesn't force the Graph SDK
# (large, version-sensitive) on everyone, only on people who call this.
# ---------------------------------------------------------------------------
$requiredGraphModules = @(
    @{ Name = 'Microsoft.Graph.Authentication';   MinimumVersion = '2.15.0' }
    @{ Name = 'Microsoft.Graph.Applications';      MinimumVersion = '2.15.0' }
    @{ Name = 'Microsoft.Graph.Identity.SignIns';  MinimumVersion = '2.15.0' }
    @{ Name = 'Microsoft.Graph.Users';             MinimumVersion = '2.15.0' }
)
$missingGraphModules = foreach ($req in $requiredGraphModules) {
    $available = Get-Module -ListAvailable -Name $req.Name |
        Where-Object { $_.Version -ge [version]$req.MinimumVersion }
    if (-not $available) { "$($req.Name) >= $($req.MinimumVersion)" }
}
if ($missingGraphModules) {
    throw ("Get-EntraOAuthGrantInventory requires these Microsoft Graph PowerShell " +
        "modules, which are not installed (or not at the required version): " +
        "$($missingGraphModules -join ', '). Install with: Install-Module " +
        "Microsoft.Graph.Authentication, Microsoft.Graph.Applications, " +
        "Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Users -Scope CurrentUser")
}

# ---------------------------------------------------------------------------
# Risk model
# ---------------------------------------------------------------------------
# Explicit high-risk (write / admin / full-access / persistence-enabling) scopes.
$HighRiskScopes = @(
    'Directory.ReadWrite.All','RoleManagement.ReadWrite.Directory',
    'Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All',
    'Mail.ReadWrite','Mail.Send','MailboxSettings.ReadWrite',
    'Files.ReadWrite.All','Sites.ReadWrite.All','Sites.FullControl.All',
    'User.ReadWrite.All','Group.ReadWrite.All','GroupMember.ReadWrite.All',
    'full_access_as_app','Exchange.ManageAsApp',
    'Policy.ReadWrite.ConditionalAccess','Policy.ReadWrite.ApplicationConfiguration',
    'PrivilegedAccess.ReadWrite.AzureAD','DeviceManagementConfiguration.ReadWrite.All'
) | Sort-Object -Unique

# Broad-read / persistence scopes worth a second look.
$MediumRiskScopes = @(
    'Mail.Read','Mail.Read.Shared','Mail.ReadBasic.All',
    'Files.Read.All','Sites.Read.All','Directory.Read.All',
    'User.Read.All','Group.Read.All','People.Read.All',
    'Contacts.Read','Notes.Read.All','Chat.Read.All',
    'ChannelMessage.Read.All','offline_access'
) | Sort-Object -Unique

function Get-ScopeRisk {
    param([string]$Scope)
    if ([string]::IsNullOrWhiteSpace($Scope)) { return 'Low' }
    if ($HighRiskScopes -contains $Scope)   { return 'High' }
    # Pattern catch-all for high-impact permissions not in the explicit list.
    if ($Scope -match '(ReadWrite\.All$)|(FullControl)|(RoleManagement\.ReadWrite)|(\.ReadWrite\.Directory$)|(ManageAsApp)') { return 'High' }
    if ($MediumRiskScopes -contains $Scope) { return 'Medium' }
    if ($Scope -match '(Read\.All$)|(Read\.Shared$)') { return 'Medium' }
    return 'Low'
}

function Get-MaxRisk {
    param([string[]]$Levels)
    if ($Levels -contains 'High')   { return 'High' }
    if ($Levels -contains 'Medium') { return 'Medium' }
    return 'Low'
}

# ---------------------------------------------------------------------------
# Connect
# ---------------------------------------------------------------------------
$scopes = @('Directory.Read.All','Application.Read.All')
if ($IncludeAuditLog) { $scopes += 'AuditLog.Read.All' }

if (-not (Get-MgContext)) {
    Write-Verbose "Connecting to Microsoft Graph..."
    Connect-MgGraph -Scopes $scopes -NoWelcome
}
$ctx = Get-MgContext
if (-not $ctx) { throw "Not connected to Microsoft Graph." }
$homeTenant = $ctx.TenantId
Write-Verbose "Connected to tenant $homeTenant as $($ctx.Account)."

# ---------------------------------------------------------------------------
# Cache service principals + build lookups (one pass)
# ---------------------------------------------------------------------------
Write-Verbose "Caching service principals..."
$spProps = 'Id','AppId','DisplayName','AppOwnerOrganizationId','PublisherName',
           'VerifiedPublisher','SignInAudience','ServicePrincipalType','AppRoles',
           'Tags','AccountEnabled'
$allSps = Get-MgServicePrincipal -All -Property $spProps

$spById      = @{}   # SP objectId -> SP
$appRoleById = @{}   # "<resourceSpId>|<appRoleId>" -> role value (e.g. Mail.Read)
foreach ($sp in $allSps) {
    $spById[$sp.Id] = $sp
    foreach ($role in $sp.AppRoles) {
        $appRoleById["$($sp.Id)|$($role.Id)"] = $role.Value
    }
}

$userCache = @{}
function Resolve-User {
    param([string]$UserId)
    if ([string]::IsNullOrWhiteSpace($UserId)) { return $null }
    if ($userCache.ContainsKey($UserId)) { return $userCache[$UserId] }
    try {
        $u = Get-MgUser -UserId $UserId -Property 'UserPrincipalName','DisplayName' -ErrorAction Stop
        $val = $u.UserPrincipalName
    } catch { $val = $UserId }
    $userCache[$UserId] = $val
    return $val
}

function Resolve-Sp {
    param([string]$SpId)
    if ($spById.ContainsKey($SpId)) { return $spById[$SpId].DisplayName }
    return $SpId
}

function Test-ExternalApp {
    param($Sp)
    if (-not $Sp) { return $null }
    if ([string]::IsNullOrWhiteSpace($Sp.AppOwnerOrganizationId)) { return $true }
    return ($Sp.AppOwnerOrganizationId -ne $homeTenant)
}

function Test-Unverified {
    param($Sp)
    if (-not $Sp) { return $true }
    return [string]::IsNullOrWhiteSpace($Sp.VerifiedPublisher.DisplayName)
}

# ---------------------------------------------------------------------------
# 1) Delegated permission grants
# ---------------------------------------------------------------------------
Write-Verbose "Collecting delegated (OAuth2) permission grants..."
if ($TargetAppId) {
    $targetSp = $allSps | Where-Object AppId -eq $TargetAppId
    if (-not $targetSp) { throw "No service principal found for AppId $TargetAppId." }
    $rawGrants = Get-MgServicePrincipalOauth2PermissionGrant -ServicePrincipalId $targetSp.Id -All
} else {
    $rawGrants = Get-MgOauth2PermissionGrant -All
}

$delegated = foreach ($g in $rawGrants) {
    $clientSp = $spById[$g.ClientId]
    $scopeArr = @()
    if ($g.Scope) { $scopeArr = $g.Scope.Trim() -split '\s+' }
    $scopeDetail = foreach ($s in $scopeArr) {
        [pscustomobject]@{ Scope = $s; Risk = (Get-ScopeRisk $s) }
    }
    $riskLevel = Get-MaxRisk ($scopeDetail.Risk)
    $tenantWide = ($g.ConsentType -eq 'AllPrincipals')
    $unverified = Test-Unverified $clientSp
    $external   = Test-ExternalApp $clientSp

    # Bump: tenant-wide consent to anything non-Low is High.
    if ($tenantWide -and $riskLevel -eq 'Medium') { $riskLevel = 'High' }

    [pscustomobject]@{
        GrantType          = 'Delegated'
        GrantId            = $g.Id
        ClientAppName      = (Resolve-Sp $g.ClientId)
        ClientAppId        = $clientSp.AppId
        ClientSpId         = $g.ClientId
        ResourceApi        = (Resolve-Sp $g.ResourceId)
        ConsentType        = $g.ConsentType
        TenantWide         = $tenantWide
        PrincipalUpn       = if ($g.PrincipalId) { Resolve-User $g.PrincipalId } else { '(all users)' }
        Scopes             = ($scopeArr -join ' ')
        ScopesDetail       = @($scopeDetail)
        UnverifiedPublisher= $unverified
        ExternalApp        = $external
        PublisherName      = $clientSp.PublisherName
        SignInAudience     = $clientSp.SignInAudience
        RiskLevel          = $riskLevel
    }
}

# ---------------------------------------------------------------------------
# 2) Application permissions (app-role assignments held by apps)
# ---------------------------------------------------------------------------
$appRoleAssignments = @()
if (-not $TargetAppId) {
    Write-Verbose "Collecting application (app-role) permission assignments..."
    $i = 0
    foreach ($sp in $allSps) {
        $i++
        if ($sp.ServicePrincipalType -eq 'ManagedIdentity') { continue }
        Write-Progress -Activity 'App-role assignments' -Status $sp.DisplayName -PercentComplete (($i / $allSps.Count) * 100)
        $assigns = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All -ErrorAction SilentlyContinue
        foreach ($a in $assigns) {
            $permValue = $appRoleById["$($a.ResourceId)|$($a.AppRoleId)"]
            if (-not $permValue) { $permValue = $a.AppRoleId }  # fall back to GUID
            $risk = Get-ScopeRisk $permValue
            $appRoleAssignments += [pscustomobject]@{
                GrantType           = 'Application'
                AssignmentId        = $a.Id
                ClientAppName       = $sp.DisplayName
                ClientAppId         = $sp.AppId
                ClientSpId          = $sp.Id
                ResourceApi         = (Resolve-Sp $a.ResourceId)
                Permission          = $permValue
                CreatedDateTime     = $a.CreatedDateTime
                UnverifiedPublisher = (Test-Unverified $sp)
                ExternalApp         = (Test-ExternalApp $sp)
                PublisherName       = $sp.PublisherName
                RiskLevel           = $risk
            }
        }
    }
    Write-Progress -Activity 'App-role assignments' -Completed
}

# ---------------------------------------------------------------------------
# 3) Optional: audit-log correlation
# ---------------------------------------------------------------------------
$auditEvents = @()
if ($IncludeAuditLog) {
    Write-Verbose "Pulling consent / grant events from the last $Days days..."
    $since = (Get-Date).AddDays(-$Days).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $activities = @(
        'Consent to application',
        'Add delegated permission grant',
        'Add app role assignment grant to user',
        'Add app role assignment to service principal'
    )
    try {
        Import-Module Microsoft.Graph.Reports -ErrorAction Stop
        $raw = Get-MgAuditLogDirectoryAudit -Filter "activityDateTime ge $since" -All -ErrorAction Stop
        $auditEvents = $raw |
            Where-Object { $activities -contains $_.ActivityDisplayName } |
            ForEach-Object {
                [pscustomobject]@{
                    When        = $_.ActivityDateTime
                    Activity    = $_.ActivityDisplayName
                    Result      = $_.Result
                    InitiatedBy = $_.InitiatedBy.User.UserPrincipalName
                    Target      = ($_.TargetResources | ForEach-Object DisplayName) -join '; '
                }
            }
    } catch {
        Write-Warning "Audit-log pull failed (needs AuditLog.Read.All + Entra ID P1/P2): $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# Filter + assemble
# ---------------------------------------------------------------------------
if ($RiskyOnly) {
    $delegated          = $delegated          | Where-Object RiskLevel -in 'Medium','High'
    $appRoleAssignments = $appRoleAssignments | Where-Object RiskLevel -in 'Medium','High'
}

$report = [ordered]@{
    GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
    Tenant       = $homeTenant
    RunAs        = $ctx.Account
    Scopes       = $ctx.Scopes
    Counts       = [ordered]@{
        ServicePrincipals      = $allSps.Count
        DelegatedGrants        = @($delegated).Count
        TenantWideGrants       = @($delegated | Where-Object TenantWide).Count
        AppRoleAssignments     = @($appRoleAssignments).Count
        HighRisk               = @(@($delegated) + @($appRoleAssignments) | Where-Object RiskLevel -eq 'High').Count
        UnverifiedPublisherApps= @(@($delegated) + @($appRoleAssignments) | Where-Object UnverifiedPublisher | Select-Object -Unique ClientAppId).Count
        ExternalApps           = @(@($delegated) + @($appRoleAssignments) | Where-Object ExternalApp | Select-Object -Unique ClientAppId).Count
    }
    DelegatedGrants     = @($delegated)
    AppRoleAssignments  = @($appRoleAssignments)
    AuditEvents         = @($auditEvents)
}

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$base  = Join-Path $OutputDir "EntraOAuthInventory-$stamp"
$want  = if ($Format -contains 'All') { @('Json','Xml','Csv') } else { $Format }

if ($want -contains 'Json') {
    $report | ConvertTo-Json -Depth 8 | Out-File "$base.json" -Encoding utf8
    Write-Host "JSON : $base.json"
}
if ($want -contains 'Xml') {
    ($report | ConvertTo-Xml -Depth 8 -As String -NoTypeInformation) | Out-File "$base.xml" -Encoding utf8
    Write-Host "XML  : $base.xml"
    # For a PowerShell-rehydratable export instead, use:
    #   $report | Export-Clixml "$base.clixml"
}
if ($want -contains 'Csv') {
    $report.DelegatedGrants    | Select-Object * -ExcludeProperty ScopesDetail | Export-Csv "$base-delegated.csv"    -NoTypeInformation
    $report.AppRoleAssignments | Export-Csv "$base-approles.csv" -NoTypeInformation
    if ($auditEvents) { $report.AuditEvents | Export-Csv "$base-audit.csv" -NoTypeInformation }
    Write-Host "CSV  : $base-delegated.csv (+ -approles.csv$(if($auditEvents){', -audit.csv'}))"
}

# ---------------------------------------------------------------------------
# Console summary
# ---------------------------------------------------------------------------
Write-Host "`n==== Entra OAuth Grant Inventory ====" -ForegroundColor Cyan
Write-Host "Tenant: $homeTenant   Generated: $($report.GeneratedUtc)"
$report.Counts.GetEnumerator() | ForEach-Object { "{0,-24}: {1}" -f $_.Key, $_.Value } | Write-Host

Write-Host "`nTop risky grants:" -ForegroundColor Yellow
@(@($delegated) + @($appRoleAssignments)) |
    Where-Object RiskLevel -eq 'High' |
    Sort-Object ClientAppName |
    Select-Object RiskLevel, GrantType,
        @{n='App';e={$_.ClientAppName}},
        @{n='Perms';e={ if ($_.Scopes) { $_.Scopes } else { $_.Permission } }},
        @{n='Flags';e={ (@(
            if ($_.TenantWide)          {'tenant-wide'}
            if ($_.UnverifiedPublisher) {'unverified'}
            if ($_.ExternalApp)         {'external'}
        )) -join ',' }} |
    Format-Table -AutoSize -Wrap
}

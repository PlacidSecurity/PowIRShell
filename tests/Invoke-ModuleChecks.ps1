<#
.SYNOPSIS
    Pre-merge checks for the PowIRShell module. Run by GitHub Actions on every pull request and push to main,
    and can be run locally before pushing: .\tests\Invoke-ModuleChecks.ps1
.DESCRIPTION
    1. Encoding: every .ps1/.psm1/.psd1 file tracked in the repo has at most one byte-order mark, and any file with
       non-ASCII characters has a BOM (otherwise Windows PowerShell 5.1 reads it as ANSI and mangles them).
    2. Manifest: Test-ModuleManifest passes, the module imports, and the expected public commands are exported.
    3. Static analysis (skipped with -SkipAnalyzer): PSScriptAnalyzer over the module source. Error-severity findings
       and the security rules listed in $failRules fail the run; other warnings are reported only.
    Exits 1 if any check fails.
.PARAMETER AnalyzerVersion
    PSScriptAnalyzer version to install if it is not already present. Pinned so results don't change underneath you.
.PARAMETER SkipAnalyzer
    Run only the encoding and manifest checks (used for the Windows PowerShell 5.1 pass).
#>
[CmdletBinding()]
param(
    [string]$AnalyzerVersion = '1.24.0',
    [switch]$SkipAnalyzer
)

$ErrorActionPreference = 'Stop'
$repoRoot  = Split-Path -Parent $PSScriptRoot
$manifest  = Join-Path $repoRoot 'M365CompromiseInfo.psd1'
$inActions = [bool]$env:GITHUB_ACTIONS
$failures  = New-Object System.Collections.Generic.List[string]

# Public commands that must be exported. Add new ones here when you add them to the module.
$expectedCommands = @(
    'Get-M365CompromiseInfo',
    'Get-M365UnifiedAuditLog',
    'Get-emailInformation',
    'Get-EntraOAuthGrantInventory',
    'Get-DehashedLookup',
    'Get-AuditdataFrom365JSON'
)

# Security-relevant analyzer rules that fail the run even though PSScriptAnalyzer rates some of them as warnings.
$failRules = @(
    'PSAvoidUsingInvokeExpression',
    'PSAvoidUsingPlainTextForPassword',
    'PSAvoidUsingConvertToSecureStringWithPlainText',
    'PSAvoidUsingUsernameAndPasswordParams',
    'PSAvoidUsingComputerNameHardcoded',
    'PSAvoidUsingAllowUnencryptedAuthentication',
    'PSUseBOMForUnicodeEncodedFile'
)

function Add-Failure ([string]$Message, [string]$File, [int]$Line) {
    $failures.Add($Message)
    if ($inActions) {
        # Shows the failure inline on the pull request's "Files changed" tab
        $rel = if ($File) { $File.Substring($repoRoot.Length).TrimStart('\', '/') -replace '\\', '/' } else { $null }
        $loc = if ($rel) { " file=$rel" + $(if ($Line) { ",line=$Line" } else { '' }) } else { '' }
        Write-Output "::error$loc::$Message"
    } else {
        Write-Output "  FAIL: $Message"
    }
}

function Write-Section ([string]$Title) { Write-Output ''; Write-Output "== $Title" }

Write-Output "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"

# ---------------------------------------------------------------------------------------------------------------
Write-Section 'Encoding'
$scriptFiles = @(Get-ChildItem -Path $repoRoot -Recurse -File -Include *.ps1, *.psm1, *.psd1 |
    Where-Object { $_.FullName -notmatch '[\\/](\.git|temp)[\\/]' })
foreach ($file in $scriptFiles) {
    $bytes = [IO.File]::ReadAllBytes($file.FullName)
    $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) -or
              ($bytes.Length -ge 2 -and (($bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) -or ($bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF)))
    # ReadAllText strips one BOM; a second one survives as U+FEFF and breaks parsing (this is what broke the manifest)
    $text = [IO.File]::ReadAllText($file.FullName)
    if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) {
        Add-Failure "$($file.Name) has more than one byte-order mark" $file.FullName 1
    }
    if (-not $hasBom -and ($bytes | Where-Object { $_ -gt 0x7F } | Select-Object -First 1)) {
        Add-Failure "$($file.Name) has non-ASCII characters but no BOM; Windows PowerShell 5.1 will misread them. Replace them with ASCII or save as UTF-8 with BOM." $file.FullName 0
    }
}
Write-Output "  Checked $($scriptFiles.Count) files"

# ---------------------------------------------------------------------------------------------------------------
Write-Section 'Manifest and import'
try {
    $null = Test-ModuleManifest -Path $manifest -ErrorAction Stop
    Write-Output '  Test-ModuleManifest passed'
    $module = Import-Module $manifest -Force -PassThru -ErrorAction Stop
    $exported = @($module.ExportedCommands.Keys)
    Write-Output "  Imported $($module.Name) $($module.Version): $($exported.Count) commands exported"
    foreach ($cmd in $expectedCommands) {
        if ($exported -notcontains $cmd) { Add-Failure "Expected command '$cmd' is not exported by the module" $manifest 0 }
    }
    Remove-Module $module.Name -Force
} catch {
    Add-Failure "Module manifest/import failed: $($_.Exception.Message)" $manifest 0
}

# ---------------------------------------------------------------------------------------------------------------
if (-not $SkipAnalyzer) {
    Write-Section "PSScriptAnalyzer $AnalyzerVersion"
    if (-not (Get-Module -ListAvailable PSScriptAnalyzer | Where-Object { $_.Version -eq [version]$AnalyzerVersion })) {
        Write-Output "  Installing PSScriptAnalyzer $AnalyzerVersion from PSGallery"
        Install-Module PSScriptAnalyzer -RequiredVersion $AnalyzerVersion -Repository PSGallery -Scope CurrentUser -Force -AllowClobber
    }
    $psa = Import-Module PSScriptAnalyzer -RequiredVersion $AnalyzerVersion -PassThru

    # Supply-chain check: the analyzer assembly should carry a valid Microsoft Authenticode signature
    if ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows) {
        $dll = Get-ChildItem -Path $psa.ModuleBase -Recurse -Filter 'Microsoft.Windows.PowerShell.ScriptAnalyzer.dll' | Select-Object -First 1
        $sig = if ($dll) { Get-AuthenticodeSignature $dll.FullName } else { $null }
        if (-not $sig -or $sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
            Add-Failure "PSScriptAnalyzer signature check failed ($(if ($sig) { $sig.Status } else { 'assembly not found' }))" $null 0
        } else {
            Write-Output "  Signature: $($sig.Status), $($sig.SignerCertificate.Subject)"
        }
    }

    $targets = @($manifest) + @(Get-ChildItem -Path (Join-Path $repoRoot 'src') -Recurse -File -Include *.ps1, *.psm1 | ForEach-Object FullName)
    $results = foreach ($t in $targets) { Invoke-ScriptAnalyzer -Path $t -Severity Error, Warning }
    $blocking = @($results | Where-Object { $_.Severity -eq 'Error' -or $failRules -contains $_.RuleName })
    $info     = @($results | Where-Object { $blocking -notcontains $_ })

    foreach ($r in $blocking) {
        Add-Failure "$($r.RuleName): $($r.Message)" $r.ScriptPath $r.Line
    }
    Write-Output "  $($blocking.Count) blocking finding(s), $($info.Count) non-blocking warning(s)"
    $info | Group-Object RuleName | Sort-Object Count -Descending | ForEach-Object {
        Write-Output ("    {0,4}  {1}" -f $_.Count, $_.Name)
    }
}

# ---------------------------------------------------------------------------------------------------------------
Write-Output ''
if ($failures.Count -gt 0) {
    Write-Output "FAILED: $($failures.Count) problem(s)"
    exit 1
}
Write-Output 'All checks passed'
exit 0

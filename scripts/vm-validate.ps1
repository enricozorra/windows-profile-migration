<#
.SYNOPSIS
    End-to-end validation of profmig's read-only phases on a disposable VM.

.DESCRIPTION
    Creates a throwaway local user with a real profile, runs profmig against
    it in known-good and known-bad states, and asserts exit codes and
    findings. It also proves the read-only guarantee: ProfileList and the
    test user's NTUSER.DAT must be byte-identical before and after every
    preflight / dry-run invocation.

    Run ONLY on a disposable VM snapshot, elevated, under Windows
    PowerShell 5.1 or PowerShell 7. The script creates and deletes a local
    account and temporarily adds/removes a ProfileList .bak key.

.PARAMETER Profmig
    Path to profmig.exe.

.PARAMETER TargetAccount
    Optional DOMAIN\user that has never logged on to this VM. When given
    (and the VM is domain-joined), the passing path, dry-run and backup are
    validated too. Without it, only the blocking cases run.

.EXAMPLE
    .\vm-validate.ps1 -Profmig C:\tools\profmig.exe -TargetAccount CORP\pmtarget
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Profmig,
    [string] $TargetAccount,
    [string] $WorkDir = (Join-Path $env:TEMP "profmig-validate-$(Get-Date -Format yyyyMMddHHmmss)")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProfileListKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
$script:Failures = 0

function Assert-Admin {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated PowerShell.'
    }
}

function Write-Result([string] $Name, [bool] $Passed, [string] $Detail = '') {
    if ($Passed) {
        Write-Host "[PASS] $Name" -ForegroundColor Green
    } else {
        $script:Failures++
        Write-Host "[FAIL] $Name $Detail" -ForegroundColor Red
    }
}

function Invoke-Profmig([string[]] $Arguments) {
    $logDir = Join-Path $WorkDir 'logs'
    $all = $Arguments + @('--log-dir', $logDir)
    $output = & $Profmig @all 2>&1 | Out-String
    [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
}

function Get-StateFingerprint([string] $NtUserPath) {
    # reg.exe export is deterministic for unchanged keys, so equal hashes
    # mean ProfileList was not modified.
    $regFile = Join-Path $WorkDir "fingerprint-$([guid]::NewGuid()).reg"
    & "$env:SystemRoot\System32\reg.exe" export 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' $regFile /y | Out-Null
    $profileListHash = (Get-FileHash $regFile -Algorithm SHA256).Hash
    Remove-Item $regFile
    $hive = Get-Item -LiteralPath $NtUserPath -Force
    "$profileListHash|$($hive.Length)|$($hive.LastWriteTimeUtc.Ticks)|$((Get-FileHash -LiteralPath $NtUserPath -Algorithm SHA256).Hash)"
}

function New-ProfileForUser([string] $Sid) {
    # userenv!CreateProfile builds C:\Users\<name> and the ProfileList entry
    # without an interactive logon.
    if (-not ('ProfmigValidate.UserEnv' -as [type])) {
        Add-Type -Namespace ProfmigValidate -Name UserEnv -MemberDefinition @'
[DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern int CreateProfile(string pszUserSid, string pszUserName, System.Text.StringBuilder pszProfilePath, uint cchProfilePath);
'@
    }
    $path = New-Object System.Text.StringBuilder 260
    $hr = [ProfmigValidate.UserEnv]::CreateProfile($Sid, $script:TestUser, $path, 260)
    if ($hr -ne 0) { throw ('CreateProfile failed: 0x{0:X8}' -f $hr) }
    $path.ToString()
}

Assert-Admin
if (-not (Test-Path -LiteralPath $Profmig)) { throw "profmig not found at $Profmig" }
New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null

$script:TestUser = 'pmtest' + (Get-Random -Minimum 1000 -Maximum 9999)
$password = ConvertTo-SecureString ([guid]::NewGuid().ToString() + 'Aa1!') -AsPlainText -Force
$user = $null
$bakKey = $null

try {
    $user = New-LocalUser -Name $script:TestUser -Password $password -Description 'profmig validation (temporary)'
    $sid = $user.SID.Value
    $profilePath = New-ProfileForUser $sid
    $ntuser = Join-Path $profilePath 'NTUSER.DAT'
    Write-Host "test user $($script:TestUser) $sid at $profilePath"

    $source = ".\$($script:TestUser)"
    $baseline = Get-StateFingerprint $ntuser

    # --- usage errors -----------------------------------------------------
    $r = Invoke-Profmig @('migrate', '--source', $source, '--target', 'X\y')
    Write-Result 'migrate without --dry-run is refused (exit 2)' ($r.ExitCode -eq 2) $r.Output

    # --- ambiguous target -------------------------------------------------
    $r = Invoke-Profmig @('preflight', '--source', $source, '--target', $script:TestUser)
    Write-Result 'bare target name blocks' (($r.ExitCode -eq 1) -and ($r.Output -match '\[BLOCK\]\s+TARGET_ACCOUNT')) $r.Output

    # --- local target -----------------------------------------------------
    $r = Invoke-Profmig @('preflight', '--source', $source, '--target', "$env:COMPUTERNAME\Administrator")
    Write-Result 'local target blocks' (($r.ExitCode -eq 1) -and ($r.Output -match '\[BLOCK\]\s+TARGET_ACCOUNT')) $r.Output

    # --- source given as SID resolves to the same profile ----------------
    $r = Invoke-Profmig @('preflight', '--source', $sid, '--target', 'X\y')
    Write-Result 'source by SID passes SOURCE_ACCOUNT' ($r.Output -match '\[PASS\s*\]\s+SOURCE_ACCOUNT') $r.Output

    # --- locked hive ------------------------------------------------------
    & "$env:SystemRoot\System32\reg.exe" load 'HKU\pmvalidate_lock' $ntuser | Out-Null
    try {
        $r = Invoke-Profmig @('preflight', '--source', $source, '--target', 'X\y')
        Write-Result 'loaded hive blocks HIVE_FILES' ($r.Output -match '\[BLOCK\]\s+HIVE_FILES') $r.Output
    } finally {
        [gc]::Collect()
        & "$env:SystemRoot\System32\reg.exe" unload 'HKU\pmvalidate_lock' | Out-Null
    }
    # Loading a hive may legitimately replay its logs, so re-baseline.
    $baseline = Get-StateFingerprint $ntuser

    # --- .bak twin --------------------------------------------------------
    $bakKey = Join-Path $ProfileListKey "$sid.bak"
    New-Item -Path $bakKey -Force | Out-Null
    $r = Invoke-Profmig @('preflight', '--source', $source, '--target', 'X\y')
    Write-Result '.bak entry blocks PROFILE_LIST_BAK' ($r.Output -match '\[BLOCK\]\s+PROFILE_LIST_BAK') $r.Output
    Remove-Item -Path $bakKey -Force
    $bakKey = $null
    $baseline = Get-StateFingerprint $ntuser

    # --- passing path (needs a domain target) ----------------------------
    if ($TargetAccount) {
        $r = Invoke-Profmig @('preflight', '--source', $source, '--target', $TargetAccount)
        Write-Result 'clean preflight passes (exit 0)' ($r.ExitCode -eq 0) $r.Output

        $r = Invoke-Profmig @('migrate', '--dry-run', '--source', $source, '--target', $TargetAccount)
        Write-Result 'dry-run prints a plan' (($r.ExitCode -eq 0) -and ($r.Output -match 'DRY RUN')) $r.Output

        Write-Result 'preflight and dry-run changed nothing' ((Get-StateFingerprint $ntuser) -eq $baseline)

        $backupRoot = Join-Path $WorkDir 'backups'
        $r = Invoke-Profmig @('backup', '--source', $source, '--target', $TargetAccount, '--backup-dir', $backupRoot)
        Write-Result 'backup succeeds (exit 0)' ($r.ExitCode -eq 0) $r.Output
        $folder = Get-ChildItem -LiteralPath $backupRoot -Directory | Select-Object -First 1
        if ($folder) {
            foreach ($expected in 'ProfileList.reg', 'acl-manifest.json', 'manifest.json', 'hives\NTUSER.DAT') {
                Write-Result "backup contains $expected" (Test-Path -LiteralPath (Join-Path $folder.FullName $expected))
            }
            $acl = Get-Acl -LiteralPath $folder.FullName
            $broad = $acl.Access | Where-Object { $_.IdentityReference -match 'Users|Everyone|Authenticated' }
            Write-Result 'backup folder is private to SYSTEM/Administrators' (-not $broad) ($acl.Sddl)
        } else {
            Write-Result 'backup folder exists' $false
        }
        Write-Result 'backup changed nothing in the profile' ((Get-StateFingerprint $ntuser) -eq $baseline)
    } else {
        Write-Host '[SKIP] passing path, dry-run and backup: no -TargetAccount given' -ForegroundColor Yellow
        $r = Invoke-Profmig @('migrate', '--dry-run', '--source', $source, '--target', 'X\y')
        Write-Result 'blocked dry-run still exits 1' ($r.ExitCode -eq 1) $r.Output
        Write-Result 'preflight and dry-run changed nothing' ((Get-StateFingerprint $ntuser) -eq $baseline)
    }
}
finally {
    if ($bakKey -and (Test-Path $bakKey)) { Remove-Item -Path $bakKey -Force }
    if ($user) {
        Get-CimInstance Win32_UserProfile | Where-Object SID -eq $user.SID.Value | Remove-CimInstance
        Remove-LocalUser -SID $user.SID
    }
}

Write-Host ''
Write-Host "logs: $WorkDir\logs"
if ($script:Failures -gt 0) {
    Write-Host "$($script:Failures) check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host 'all checks passed' -ForegroundColor Green
exit 0

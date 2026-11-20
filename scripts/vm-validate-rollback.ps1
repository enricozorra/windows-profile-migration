<#
.SYNOPSIS
    End-to-end validation of `status` and `rollback` on a disposable VM.

.DESCRIPTION
    The execution phase does not exist yet, so this script fakes what an
    interrupted migration leaves behind (journals, working copies, a
    ProfileList entry, a mounted hive copy) and checks that `status`
    describes it and `rollback` removes exactly what it should:

      A  interrupted preparation: copy (with a junction into the source
         profile) and a mounted hive copy -> both removed, junction target
         untouched, second rollback has nothing to do
      B  committed and used by the target -> refused, then removed with
         --discard-target-changes
      C  working copy without our marker -> refused, folder untouched
      D  ProfileList entry without our marker -> refused, entry untouched
      E  torn last journal line and an orphaned copy -> reported by status
      F  finalized migration -> refused
      G  migration locked by another process -> error, nothing changed

    Throughout, the source profile's ProfileList entry, hive and folder
    must stay byte-identical. Run ONLY on a disposable VM snapshot, elevated.

.EXAMPLE
    .\vm-validate-rollback.ps1 -WindowsProfileMigration C:\tools\windows-profile-migration.exe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $WindowsProfileMigration,
    [string] $WorkDir = (Join-Path $env:TEMP "windows-profile-migration-rollback-$(Get-Date -Format yyyyMMddHHmmss)")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProfileListKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
$Marker = '.windows-profile-migration'
$StagingSuffix = '.windows-profile-migration-staging'
$script:Failures = 0
$script:Cleanup = New-Object System.Collections.Generic.List[scriptblock]

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

function Invoke-Tool([string[]] $Arguments) {
    # Windows PowerShell 5.1 turns redirected native stderr into error
    # records; the exit code is what the checks assert on.
    $ErrorActionPreference = 'Continue'
    $output = & $WindowsProfileMigration @Arguments 2>&1 | Out-String
    [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
}

function New-Record([string] $Event, [System.Collections.Specialized.OrderedDictionary] $Fields, [string] $Ts) {
    if (-not $Ts) { $Ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'") }
    $record = [ordered]@{ ts = $Ts; event = $Event }
    if ($Fields) { foreach ($key in $Fields.Keys) { $record[$key] = [string]$Fields[$key] } }
    $record | ConvertTo-Json -Compress
}

function New-Journal([string] $Id, [string[]] $Lines) {
    $dir = Join-Path $script:MigrationsRoot $Id
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    # UTF-8 without BOM, one record per line, as the tool writes it.
    [IO.File]::WriteAllText((Join-Path $dir 'journal.log'), (($Lines -join "`n") + "`n"), (New-Object Text.UTF8Encoding($false)))
    $dir
}

function Get-StartedRecord([string] $Id, [string] $TargetSid, [string] $TargetPath) {
    New-Record 'started' ([ordered]@{
        id = $Id; version = 'test'
        source_sid = $script:SourceSid; source_name = "$env:COMPUTERNAME\$($script:TestUser)"; source_path = $script:SourcePath
        target_sid = $TargetSid; target_name = 'TEST\target'; target_path = $TargetPath
        staging_path = "$TargetPath$StagingSuffix"
    })
}

function Get-ArtifactRecord([string] $Event, [string] $Kind, [string] $Value) {
    New-Record $Event ([ordered]@{ kind = $Kind; value = $Value })
}

function New-OurFolder([string] $Path, [string] $Id) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $Path $Marker) -Value $Id -NoNewline
    Set-Content -LiteralPath (Join-Path $Path 'copied.txt') -Value 'copied data'
    $script:Cleanup.Add({ if (Test-Path -LiteralPath $Path) { cmd /c rmdir /s /q "$Path" } }.GetNewClosure())
}

function New-FakeTargetSid {
    'S-1-5-21-1111111111-2222222222-3333333333-' + (Get-Random -Minimum 10000 -Maximum 99999)
}

function New-ProfileListEntry([string] $Sid, [string] $Path, [string] $MarkerValue) {
    $key = Join-Path $ProfileListKey $Sid
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name ProfileImagePath -PropertyType ExpandString -Value $Path | Out-Null
    if ($MarkerValue) {
        New-ItemProperty -Path $key -Name WindowsProfileMigrationSourceSid -PropertyType String -Value $MarkerValue | Out-Null
    }
    $script:Cleanup.Add({ if (Test-Path $key) { Remove-Item -Path $key -Force } }.GetNewClosure())
    $key
}

function Get-SourceFingerprint {
    $regFile = Join-Path $WorkDir "fp-$([guid]::NewGuid()).reg"
    & "$env:SystemRoot\System32\reg.exe" export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($script:SourceSid)" $regFile /y | Out-Null
    $entryHash = (Get-FileHash $regFile -Algorithm SHA256).Hash
    Remove-Item $regFile
    $hiveHash = (Get-FileHash -LiteralPath (Join-Path $script:SourcePath 'NTUSER.DAT') -Algorithm SHA256).Hash
    $files = @(Get-ChildItem -LiteralPath $script:SourcePath -Recurse -Force -ErrorAction SilentlyContinue -Attributes !ReparsePoint).Count
    "$entryHash|$hiveHash|$files"
}

function New-ProfileForUser([string] $Sid, [string] $Name) {
    if (-not ('WindowsProfileMigrationValidate.UserEnv' -as [type])) {
        Add-Type -Namespace WindowsProfileMigrationValidate -Name UserEnv -MemberDefinition @'
[DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern int CreateProfile(string pszUserSid, string pszUserName, System.Text.StringBuilder pszProfilePath, uint cchProfilePath);
'@
    }
    $path = New-Object System.Text.StringBuilder 260
    $hr = [WindowsProfileMigrationValidate.UserEnv]::CreateProfile($Sid, $Name, $path, 260)
    if ($hr -ne 0) { throw ('CreateProfile failed: 0x{0:X8}' -f $hr) }
    $path.ToString()
}

Assert-Admin
if (-not (Test-Path -LiteralPath $WindowsProfileMigration)) { throw "not found: $WindowsProfileMigration" }
New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
$previousHome = $env:WINDOWS_PROFILE_MIGRATION_HOME
$env:WINDOWS_PROFILE_MIGRATION_HOME = $WorkDir
$script:MigrationsRoot = Join-Path $WorkDir 'migrations'

$script:TestUser = 'pmrb' + (Get-Random -Minimum 1000 -Maximum 9999)
$password = ConvertTo-SecureString ([guid]::NewGuid().ToString() + 'Aa1!') -AsPlainText -Force
$user = $null
$mount = $null
$lockHandle = $null

try {
    $user = New-LocalUser -Name $script:TestUser -Password $password -Description 'windows-profile-migration rollback test'
    $script:SourceSid = $user.SID.Value
    $script:SourcePath = New-ProfileForUser $script:SourceSid $script:TestUser
    New-Item -ItemType Directory -Path (Join-Path $script:SourcePath 'Documents') -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $script:SourcePath 'Documents\keep.txt') -Value 'must survive'
    Write-Host "source $($script:TestUser) $($script:SourceSid) at $($script:SourcePath)"
    $baseline = Get-SourceFingerprint
    $usersRoot = Split-Path $script:SourcePath

    # --- A: interrupted preparation ------------------------------------
    $idA = 'testA-' + (Get-Random)
    $stagingA = Join-Path $usersRoot "pmrbA$(Get-Random)$StagingSuffix"
    New-OurFolder $stagingA $idA
    # A junction into the source profile: deleting the copy must not follow it.
    cmd /c mklink /J "$stagingA\Documents" "$($script:SourcePath)\Documents" | Out-Null
    $hiveCopy = Join-Path $WorkDir 'hivecopy.dat'
    Copy-Item -LiteralPath (Join-Path $script:SourcePath 'NTUSER.DAT') $hiveCopy
    $mount = 'windows-profile-migration_rbtest_' + (Get-Random)
    & "$env:SystemRoot\System32\reg.exe" load "HKU\$mount" $hiveCopy | Out-Null
    New-Journal $idA @(
        (Get-StartedRecord $idA (New-FakeTargetSid) ($stagingA -replace [regex]::Escape($StagingSuffix), '')),
        (Get-ArtifactRecord 'intent' 'staging_dir' $stagingA),
        (Get-ArtifactRecord 'created' 'staging_dir' $stagingA),
        (Get-ArtifactRecord 'intent' 'hive_mount' $mount),
        (Get-ArtifactRecord 'created' 'hive_mount' $mount)
    ) | Out-Null

    $r = Invoke-Tool @('status')
    Write-Result 'A: status reports the unfinished migration (exit 1)' (($r.ExitCode -eq 1) -and ($r.Output -match [regex]::Escape($idA)) -and ($r.Output -match 'phase: preparing')) $r.Output
    $r = Invoke-Tool @('rollback', '--migration', $idA)
    Write-Result 'A: rollback succeeds (exit 0)' ($r.ExitCode -eq 0) $r.Output
    Write-Result 'A: working copy removed' (-not (Test-Path -LiteralPath $stagingA))
    Write-Result 'A: hive copy unmounted' (-not (Test-Path "Registry::HKEY_USERS\$mount"))
    if (-not (Test-Path "Registry::HKEY_USERS\$mount")) { $mount = $null }
    Write-Result 'A: junction target in the source profile untouched' (Test-Path -LiteralPath (Join-Path $script:SourcePath 'Documents\keep.txt'))
    $journalA = Get-Content -LiteralPath (Join-Path $script:MigrationsRoot "$idA\journal.log")
    Write-Result 'A: journal records the rollback' (($journalA -match '"event":"removed"').Count -eq 2 -and ($journalA[-1] -match 'rollback_done'))
    $r = Invoke-Tool @('rollback', '--migration', $idA)
    Write-Result 'A: second rollback has nothing to do (exit 0)' (($r.ExitCode -eq 0) -and ($r.Output -match 'Nothing left to undo')) $r.Output

    # --- B: committed and used by the target ---------------------------
    $idB = 'testB-' + (Get-Random)
    $sidB = New-FakeTargetSid
    $targetB = Join-Path $usersRoot "pmrbB$(Get-Random)"
    New-OurFolder $targetB $idB
    Set-Content -LiteralPath (Join-Path $targetB 'NTUSER.DAT') -Value 'written by the target after the commit'
    $keyB = New-ProfileListEntry $sidB $targetB $script:SourceSid
    New-Journal $idB @(
        (Get-StartedRecord $idB $sidB $targetB),
        (Get-ArtifactRecord 'created' 'target_dir' $targetB),
        (Get-ArtifactRecord 'created' 'profile_list_entry' $sidB),
        (New-Record 'committed' $null '2020-01-01T00:00:00.000Z')
    ) | Out-Null
    $r = Invoke-Tool @('rollback', '--migration', $idB)
    Write-Result 'B: rollback refused after the target used the profile (exit 1)' (($r.ExitCode -eq 1) -and ($r.Output -match 'discard-target-changes')) $r.Output
    Write-Result 'B: nothing removed while refused' ((Test-Path -LiteralPath $targetB) -and (Test-Path $keyB))
    $r = Invoke-Tool @('rollback', '--migration', $idB, '--discard-target-changes')
    Write-Result 'B: rollback with --discard-target-changes succeeds' ($r.ExitCode -eq 0) $r.Output
    Write-Result 'B: ProfileList entry and folder removed' ((-not (Test-Path -LiteralPath $targetB)) -and (-not (Test-Path $keyB)))

    # --- C: working copy without our marker ----------------------------
    $idC = 'testC-' + (Get-Random)
    $stagingC = Join-Path $usersRoot "pmrbC$(Get-Random)$StagingSuffix"
    New-Item -ItemType Directory -Path $stagingC | Out-Null
    Set-Content -LiteralPath (Join-Path $stagingC 'someone-elses.txt') -Value 'not ours'
    $script:Cleanup.Add({ if (Test-Path -LiteralPath $stagingC) { cmd /c rmdir /s /q "$stagingC" } }.GetNewClosure())
    New-Journal $idC @(
        (Get-StartedRecord $idC (New-FakeTargetSid) ($stagingC -replace [regex]::Escape($StagingSuffix), '')),
        (Get-ArtifactRecord 'created' 'staging_dir' $stagingC)
    ) | Out-Null
    $r = Invoke-Tool @('rollback', '--migration', $idC)
    Write-Result 'C: unmarked folder refuses the rollback (exit 1)' (($r.ExitCode -eq 1) -and ($r.Output -match 'never deleted')) $r.Output
    Write-Result 'C: unmarked folder untouched' (Test-Path -LiteralPath (Join-Path $stagingC 'someone-elses.txt'))

    # --- D: ProfileList entry without our marker -----------------------
    $idD = 'testD-' + (Get-Random)
    $sidD = New-FakeTargetSid
    $keyD = New-ProfileListEntry $sidD 'C:\Users\not-ours' $null
    New-Journal $idD @(
        (Get-StartedRecord $idD $sidD 'C:\Users\not-ours'),
        (Get-ArtifactRecord 'created' 'profile_list_entry' $sidD)
    ) | Out-Null
    $r = Invoke-Tool @('rollback', '--migration', $idD)
    Write-Result 'D: unmarked ProfileList entry refuses the rollback (exit 1)' ($r.ExitCode -eq 1) $r.Output
    Write-Result 'D: unmarked ProfileList entry untouched' (Test-Path $keyD)

    # --- E: torn journal line and an orphaned copy ---------------------
    $idE = 'testE-' + (Get-Random)
    $dirE = New-Journal $idE @((Get-StartedRecord $idE (New-FakeTargetSid) 'C:\Users\pmrbE'))
    [IO.File]::AppendAllText((Join-Path $dirE 'journal.log'), '{"ts":"2026-01-01T00:00:00.000Z","event":"inte')
    $orphan = Join-Path $usersRoot "pmrbOrphan$(Get-Random)$StagingSuffix"
    New-OurFolder $orphan 'no-journal'
    $r = Invoke-Tool @('status')
    Write-Result 'E: torn last line is reported' ($r.Output -match 'incomplete last record') $r.Output
    Write-Result 'E: orphaned copy is reported' ($r.Output -match [regex]::Escape($orphan)) $r.Output
    Write-Result 'E: orphaned copy is left alone' (Test-Path -LiteralPath $orphan)

    # --- F: finalized migration ----------------------------------------
    $idF = 'testF-' + (Get-Random)
    New-Journal $idF @(
        (Get-StartedRecord $idF (New-FakeTargetSid) 'C:\Users\pmrbF'),
        (New-Record 'committed' $null),
        (New-Record 'finalized' $null)
    ) | Out-Null
    $r = Invoke-Tool @('rollback', '--migration', $idF)
    Write-Result 'F: finalized migration cannot be rolled back (exit 1)' (($r.ExitCode -eq 1) -and ($r.Output -match 'finalized')) $r.Output

    # --- G: locked by another process ----------------------------------
    $idG = 'testG-' + (Get-Random)
    $stagingG = Join-Path $usersRoot "pmrbG$(Get-Random)$StagingSuffix"
    New-OurFolder $stagingG $idG
    $dirG = New-Journal $idG @(
        (Get-StartedRecord $idG (New-FakeTargetSid) ($stagingG -replace [regex]::Escape($StagingSuffix), '')),
        (Get-ArtifactRecord 'created' 'staging_dir' $stagingG)
    )
    $lockHandle = [IO.File]::Open((Join-Path $dirG 'lock'), 'OpenOrCreate', 'ReadWrite', 'None')
    $r = Invoke-Tool @('rollback', '--migration', $idG)
    Write-Result 'G: locked migration is not touched (exit 3)' (($r.ExitCode -eq 3) -and ($r.Output -match 'cannot lock')) $r.Output
    Write-Result 'G: working copy still there' (Test-Path -LiteralPath $stagingG)
    $lockHandle.Dispose()
    $lockHandle = $null
    $r = Invoke-Tool @('rollback', '--migration', $idG)
    Write-Result 'G: rollback succeeds once the lock is released' (($r.ExitCode -eq 0) -and -not (Test-Path -LiteralPath $stagingG)) $r.Output

    # --- the source profile ---------------------------------------------
    Write-Result 'source profile is byte-identical after every scenario' ((Get-SourceFingerprint) -eq $baseline)
    $r = Invoke-Tool @('rollback', '--migration', '..\x')
    Write-Result 'a path-like migration id is rejected (exit 3)' ($r.ExitCode -eq 3) $r.Output
}
finally {
    if ($lockHandle) { $lockHandle.Dispose() }
    if ($mount) {
        [gc]::Collect()
        & "$env:SystemRoot\System32\reg.exe" unload "HKU\$mount" | Out-Null
    }
    foreach ($step in $script:Cleanup) { & $step }
    if ($user) {
        Get-CimInstance Win32_UserProfile | Where-Object SID -eq $user.SID.Value | Remove-CimInstance
        Remove-LocalUser -SID $user.SID
    }
    $env:WINDOWS_PROFILE_MIGRATION_HOME = $previousHome
}

Write-Host ''
Write-Host "work dir and logs: $WorkDir"
if ($script:Failures -gt 0) {
    Write-Host "$($script:Failures) check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host 'all checks passed' -ForegroundColor Green
exit 0

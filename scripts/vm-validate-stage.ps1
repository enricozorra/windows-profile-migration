<#
.SYNOPSIS
    End-to-end validation of `migrate --stage-only` on a disposable VM.

.DESCRIPTION
    Creates a temporary local user with a real profile, fills it with the
    cases a faithful copy has to get right, and checks that:

      S1  the working copy is built and verified (exit 0) next to the target
          folder, with our marker, and `status` reports it as preparing
      S2  content, alternate data streams, attributes, timestamps, ACLs,
          a sparse file, long and Unicode paths arrive unchanged
      S3  a junction into the profile is retargeted to the target folder,
          a junction elsewhere and a relative symlink are kept as they were
      S4  `rollback` removes the copy and leaves the source alone
      S5  a copy that cannot be completed (a source file held open by
          another process) is removed automatically, exit 3

    Optionally (-RealSource) the same build/verify/rollback cycle runs on an
    existing profile. Throughout, the source profiles must stay unchanged.
    Run ONLY on a disposable VM snapshot, elevated.

.EXAMPLE
    .\vm-validate-stage.ps1 -WindowsProfileMigration C:\pmtest\windows-profile-migration.exe -TargetAccount INFO95\enrico.zorra -RealSource .\Test
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $WindowsProfileMigration,
    [Parameter(Mandatory)] [string] $TargetAccount,
    [string] $RealSource,
    [string] $WorkDir = (Join-Path $env:TEMP "windows-profile-migration-stage-$(Get-Date -Format yyyyMMddHHmmss)")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Marker = '.windows-profile-migration'
$StagingSuffix = '.windows-profile-migration-staging'
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

function Invoke-Tool([string[]] $Arguments) {
    # Windows PowerShell 5.1 turns redirected native stderr into error
    # records; the exit code is what the checks assert on.
    $ErrorActionPreference = 'Continue'
    $output = & $WindowsProfileMigration @Arguments 2>&1 | Out-String
    [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
}

function Get-MigrationId([string] $Output) {
    if ($Output -match '(?m)^migration (\S+)') { return $Matches[1] }
    $null
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

# Every non-link file's relative path, size, hash and ACL, plus the
# ProfileList entry: any change to the source shows up as a different string.
function Get-TreeFingerprint([string] $Root, [string] $Sid, [switch] $Quick) {
    $regFile = Join-Path $WorkDir "fp-$([guid]::NewGuid()).reg"
    & "$env:SystemRoot\System32\reg.exe" export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$Sid" $regFile /y | Out-Null
    $lines = @((Get-FileHash $regFile -Algorithm SHA256).Hash)
    Remove-Item $regFile
    $items = Get-ChildItem -LiteralPath $Root -Recurse -Force -Attributes !ReparsePoint -ErrorAction SilentlyContinue
    foreach ($item in $items) {
        $relative = $item.FullName.Substring($Root.Length)
        if ($Quick -or $item.PSIsContainer) {
            $lines += "$relative|$($item.LastWriteTimeUtc.Ticks)"
        } else {
            $lines += "$relative|$($item.Length)|$((Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash)|$($item.LastWriteTimeUtc.Ticks)"
        }
    }
    ($lines | Sort-Object) -join "`n"
}

# fsutil for junctions: Windows PowerShell 5.1 cannot read the target of
# the legacy ones, whose ACL denies listing to Everyone. fsutil does not
# decode symbolic links, which Get-Item reads fine.
function Get-LinkTarget([string] $Path) {
    $line = & fsutil reparsepoint query $Path | Select-String -Pattern '^Print Name:\s*(.*)$'
    if ($line) { return $line.Matches[0].Groups[1].Value.Trim() }
    @((Get-Item -LiteralPath $Path -Force).Target)[0]
}

function Get-Sddl([string] $Path) {
    (Get-Acl -LiteralPath $Path).Sddl
}

Assert-Admin
if (-not (Test-Path -LiteralPath $WindowsProfileMigration)) { throw "not found: $WindowsProfileMigration" }
New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
$previousHome = $env:WINDOWS_PROFILE_MIGRATION_HOME
$env:WINDOWS_PROFILE_MIGRATION_HOME = $WorkDir

$testUser = 'pmst' + (Get-Random -Minimum 1000 -Maximum 9999)
$password = ConvertTo-SecureString ([guid]::NewGuid().ToString() + 'Aa1!') -AsPlainText -Force
$user = $null
$holder = $null
$staging = $null

try {
    $user = New-LocalUser -Name $testUser -Password $password -Description 'windows-profile-migration stage test'
    $sid = $user.SID.Value
    $source = New-ProfileForUser $sid $testUser
    Write-Host "source $testUser $sid at $source"

    # --- the cases a faithful copy has to get right ---------------------
    $docs = Join-Path $source 'Documents'
    New-Item -ItemType Directory -Path $docs -Force | Out-Null
    Set-Content -LiteralPath "$docs\plain.txt" -Value 'plain content'
    $bytes = New-Object byte[] (3MB + 17)
    (New-Object Random 42).NextBytes($bytes)
    [IO.File]::WriteAllBytes("$docs\random.bin", $bytes)
    New-Item -ItemType File -Path "$docs\empty.txt" | Out-Null
    New-Item -ItemType Directory -Path "$docs\empty folder" | Out-Null
    Set-Content -LiteralPath "$docs\with-stream.txt" -Value 'main'
    Set-Content -LiteralPath "$docs\with-stream.txt" -Stream 'Zone.Identifier' -Value "[ZoneTransfer]`r`nZoneId=3"
    Set-Content -LiteralPath "$docs\hidden-readonly.txt" -Value 'flags'
    (Get-Item -LiteralPath "$docs\hidden-readonly.txt").Attributes = 'Hidden, ReadOnly'
    Set-Content -LiteralPath "$docs\explicit-acl.txt" -Value 'acl'
    & icacls "$docs\explicit-acl.txt" /inheritance:d /grant 'Everyone:(R)' | Out-Null
    # Built from code points: Windows PowerShell 5.1 reads a script without
    # a BOM as ANSI.
    $unicodeName = "citt$([char]0xE0) $([char]0x2713).txt"
    Set-Content -LiteralPath "$docs\$unicodeName" -Value 'unicode'
    $sparse = "$docs\sparse.bin"
    [IO.File]::WriteAllBytes($sparse, [byte[]](1..16))
    & fsutil sparse setflag $sparse | Out-Null
    $fs = [IO.File]::OpenWrite($sparse); $fs.SetLength(64MB); $fs.Dispose()
    & fsutil sparse setrange $sparse 1048576 33554432 | Out-Null
    $deep = $docs
    while ($deep.Length -lt 300) { $deep = Join-Path $deep 'a-rather-long-folder-name' }
    [IO.Directory]::CreateDirectory("\\?\$deep") | Out-Null
    [IO.File]::WriteAllText("\\?\$deep\deep.txt", 'beyond MAX_PATH')
    $old = (Get-Date '2015-06-01T10:00:00Z').ToUniversalTime()
    (Get-Item -LiteralPath "$docs\plain.txt").LastWriteTimeUtc = $old
    (Get-Item -LiteralPath "$docs\plain.txt").CreationTimeUtc = $old.AddDays(-1)
    cmd /c mklink /J "$source\Docs-junction" "$docs" | Out-Null
    cmd /c mklink /J "$source\Outside-junction" "$env:SystemRoot\Temp" | Out-Null
    Push-Location $docs
    cmd /c mklink "relative-link.txt" "plain.txt" | Out-Null
    Pop-Location

    $baseline = Get-TreeFingerprint $source $sid

    # --- S1: build and verify --------------------------------------------
    $r = Invoke-Tool @('migrate', '--stage-only', '--source', ".\$testUser", '--target', $TargetAccount)
    $id = Get-MigrationId $r.Output
    Write-Result 'S1: working copy built and verified (exit 0)' (($r.ExitCode -eq 0) -and ($r.Output -match 'verified: all')) $r.Output
    if ($r.ExitCode -ne 0) { throw 'stage failed; the remaining checks need the copy' }
    if ($r.Output -match '(?m)^Working copy ready: (.+)$') { $staging = $Matches[1].Trim() }
    $targetPath = $staging.Substring(0, $staging.Length - $StagingSuffix.Length)
    Write-Host "copy at $staging (target $targetPath), migration $id"
    Write-Result 'S1: copy carries the marker of its migration' ((Get-Content -LiteralPath "$staging\$Marker" -Raw).Trim() -eq $id)
    Write-Result 'S1: the target folder itself was not created' (-not (Test-Path -LiteralPath $targetPath))
    $s = Invoke-Tool @('status')
    Write-Result 'S1: status reports the migration as preparing' (($s.Output -match [regex]::Escape($id)) -and ($s.Output -match 'phase: preparing')) $s.Output

    # --- S2: content and metadata ------------------------------------------
    $copyDocs = "$staging\Documents"
    foreach ($name in @('plain.txt', 'random.bin', 'empty.txt', 'with-stream.txt', 'hidden-readonly.txt', 'explicit-acl.txt', $unicodeName, 'sparse.bin')) {
        $a = Get-FileHash -LiteralPath "$docs\$name" -Algorithm SHA256
        $b = Get-FileHash -LiteralPath "$copyDocs\$name" -Algorithm SHA256
        Write-Result "S2: $name has the same content" ($a.Hash -eq $b.Hash)
    }
    Write-Result 'S2: empty folder copied' (Test-Path -LiteralPath "$copyDocs\empty folder" -PathType Container)
    $stream = Get-Content -LiteralPath "$copyDocs\with-stream.txt" -Stream 'Zone.Identifier' -Raw -ErrorAction SilentlyContinue
    Write-Result 'S2: alternate data stream copied' ($stream -match 'ZoneId=3')
    $attrs = (Get-Item -LiteralPath "$copyDocs\hidden-readonly.txt" -Force).Attributes
    Write-Result 'S2: hidden and read-only attributes kept' (($attrs -band [IO.FileAttributes]::Hidden) -and ($attrs -band [IO.FileAttributes]::ReadOnly)) "$attrs"
    $src = Get-Item -LiteralPath "$docs\plain.txt"; $dst = Get-Item -LiteralPath "$copyDocs\plain.txt"
    Write-Result 'S2: timestamps kept' (($src.LastWriteTimeUtc -eq $dst.LastWriteTimeUtc) -and ($src.CreationTimeUtc -eq $dst.CreationTimeUtc))
    Write-Result 'S2: explicit ACL kept' ((Get-Sddl "$docs\explicit-acl.txt") -eq (Get-Sddl "$copyDocs\explicit-acl.txt"))
    Write-Result 'S2: profile folder ACL kept' ((Get-Sddl $source) -eq (Get-Sddl $staging))
    Write-Result 'S2: owner is still the source user (rewritten later)' ((Get-Acl -LiteralPath "$copyDocs\plain.txt").Owner -eq (Get-Acl -LiteralPath "$docs\plain.txt").Owner)
    $sparseFlag = (& fsutil sparse queryflag "$copyDocs\sparse.bin" | Out-String)
    Write-Result 'S2: sparse file stays sparse' ($sparseFlag -match 'is set|impostato|SET') $sparseFlag
    $deepCopy = "\\?\" + $deep.Replace($source, $staging) + '\deep.txt'
    Write-Result 'S2: file beyond MAX_PATH copied' ([IO.File]::ReadAllText($deepCopy) -eq 'beyond MAX_PATH')

    # --- S3: links -----------------------------------------------------------
    Write-Result 'S3: junction into the profile retargeted to the target folder' ((Get-LinkTarget "$staging\Docs-junction") -eq "$targetPath\Documents") (Get-LinkTarget "$staging\Docs-junction")
    Write-Result 'S3: junction elsewhere kept' ((Get-LinkTarget "$staging\Outside-junction") -eq "$env:SystemRoot\Temp") (Get-LinkTarget "$staging\Outside-junction")
    Write-Result 'S3: relative symlink kept' ((Get-LinkTarget "$copyDocs\relative-link.txt") -eq 'plain.txt') (Get-LinkTarget "$copyDocs\relative-link.txt")
    $appData = "$staging\Application Data"
    if (Test-Path -LiteralPath "$source\Application Data") {
        Write-Result 'S3: legacy Application Data junction retargeted' ((Get-LinkTarget $appData) -eq "$targetPath\AppData\Roaming") (Get-LinkTarget $appData)
    }
    Write-Result 'S3: source unchanged after the copy' ((Get-TreeFingerprint $source $sid) -eq $baseline)

    # --- S4: rollback --------------------------------------------------------
    $r = Invoke-Tool @('rollback', '--migration', $id)
    Write-Result 'S4: rollback succeeds (exit 0)' ($r.ExitCode -eq 0) $r.Output
    Write-Result 'S4: working copy removed' (-not (Test-Path -LiteralPath $staging))
    if (-not (Test-Path -LiteralPath $staging)) { $staging = $null }
    Write-Result 'S4: source unchanged after the rollback' ((Get-TreeFingerprint $source $sid) -eq $baseline)

    # --- S5: a copy that cannot be completed --------------------------------
    $holder = [IO.File]::Open("$docs\random.bin", 'Open', 'ReadWrite', 'None')
    $r = Invoke-Tool @('migrate', '--stage-only', '--source', ".\$testUser", '--target', $TargetAccount)
    $holder.Dispose(); $holder = $null
    $failedId = Get-MigrationId $r.Output
    Write-Result 'S5: copy fails and says so (exit 3)' (($r.ExitCode -eq 3) -and ($r.Output -match 'random.bin')) $r.Output
    Write-Result 'S5: the partial copy was removed automatically' (($r.Output -match 'system is as it was') -and -not (Test-Path -LiteralPath "$targetPath$StagingSuffix"))
    $journal = Get-Content -LiteralPath (Join-Path $WorkDir "migrations\$failedId\journal.log")
    Write-Result 'S5: journal records the rollback' ($journal[-1] -match 'rollback_done')
    Write-Result 'S5: source unchanged' ((Get-TreeFingerprint $source $sid) -eq $baseline)

    # --- optional: an existing profile -----------------------------------------
    if ($RealSource) {
        $account = New-Object Security.Principal.NTAccount ($RealSource -replace '^\.\\', "$env:COMPUTERNAME\")
        $realSid = $account.Translate([Security.Principal.SecurityIdentifier]).Value
        $realPath = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$realSid").ProfileImagePath
        $realBaseline = Get-TreeFingerprint $realPath $realSid -Quick
        $r = Invoke-Tool @('migrate', '--stage-only', '--source', $RealSource, '--target', $TargetAccount)
        $realId = Get-MigrationId $r.Output
        Write-Result "R: $RealSource copied and verified (exit 0)" (($r.ExitCode -eq 0) -and ($r.Output -match 'verified: all')) $r.Output
        Write-Host ($r.Output -split "`n" | Select-String -Pattern 'folders,|cloud|verified' | Out-String)
        if ($realId) {
            $r = Invoke-Tool @('rollback', '--migration', $realId)
            Write-Result "R: $RealSource copy removed by rollback" ($r.ExitCode -eq 0) $r.Output
        }
        Write-Result "R: $RealSource unchanged" ((Get-TreeFingerprint $realPath $realSid -Quick) -eq $realBaseline)
    }

    $s = Invoke-Tool @('status')
    Write-Result 'no leftovers reported by status' ($s.Output -notmatch 'leftovers') $s.Output
}
finally {
    if ($holder) { $holder.Dispose() }
    if ($staging -and (Test-Path -LiteralPath $staging)) {
        Write-Host "leaving $staging for inspection; remove it with rollback"
    }
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

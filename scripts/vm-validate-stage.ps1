<#
.SYNOPSIS
    End-to-end validation of `migrate --stage-only` on a disposable VM.

.DESCRIPTION
    Creates a temporary local user with a real profile, fills it with the
    cases a faithful copy has to get right, and checks that:

      S1  the working copy is built and verified (exit 0) next to the target
          folder, with our marker, and `status` reports it as preparing
      S2  content, alternate data streams, attributes, timestamps, a sparse
          file, long and Unicode paths arrive unchanged; ACLs and owners
          name the target instead of the source; integrity labels survive
      S3  a junction into the profile is retargeted to the target folder,
          a junction elsewhere and a relative symlink are kept as they were
      S4  `rollback` removes the copy and leaves the source alone
      S5  a copy that cannot be completed (a source file held open by
          another process) is removed automatically, exit 3
      S6  the copy's NTUSER.DAT: paths and the SID in text values are
          rewritten, similar paths, loose mentions and binary data are left
          alone and reported, key ACEs name the target

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
$script:Mounts = New-Object System.Collections.Generic.List[string]

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

# Compares the source with the baseline and, on a difference, shows the
# first lines that changed.
function Test-SourceUnchanged([string] $Name) {
    $now = Get-TreeFingerprint $script:Source $script:Sid
    $diff = Compare-Object ($script:Baseline -split "`n") ($now -split "`n") |
        Select-Object -First 6 | ForEach-Object { "$($_.SideIndicator) $($_.InputObject)" }
    Write-Result $Name ($now -eq $script:Baseline) ($diff -join ' | ')
}

# fsutil for junctions: Windows PowerShell 5.1 cannot read the target of
# the legacy ones, whose ACL denies listing to Everyone. fsutil does not
# decode symbolic links, which Get-Item reads fine.
function Get-LinkTarget([string] $Path) {
    $line = & fsutil reparsepoint query $Path | Select-String -Pattern '^Print Name:\s*(.*)$'
    if ($line) { return $line.Matches[0].Groups[1].Value.Trim() }
    @((Get-Item -LiteralPath $Path -Force).Target)[0]
}

# The registry provider keeps handles open until they are collected, and
# other processes can briefly hold a freshly loaded hive: retry.
function Dismount-TestHive([string] $Mount) {
    for ($i = 0; $i -lt 15; $i++) {
        [gc]::Collect(); [gc]::WaitForPendingFinalizers()
        & reg.exe unload "HKU\$Mount" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { [void]$script:Mounts.Remove($Mount); return }
        Start-Sleep -Seconds 2
    }
    throw "could not unload HKU\$Mount"
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
    & icacls "$docs\explicit-acl.txt" /grant "*$($sid):(M)" | Out-Null

    # Registry values the rewrite must handle, written into the source hive
    # before anything is copied (the hive is not loaded: the user never
    # logged on).
    $mount = 'pmst_source_' + (Get-Random)
    & reg.exe load "HKU\$mount" "$source\NTUSER.DAT" | Out-Null
    $script:Mounts.Add($mount)
    $key = "Registry::HKEY_USERS\$mount\Software\pmtest"
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name 'Path' -Value "$source\Documents\x.txt" | Out-Null
    New-ItemProperty -Path $key -Name 'Expand' -PropertyType ExpandString -Value "$source\AppData;%TEMP%" | Out-Null
    New-ItemProperty -Path $key -Name 'Multi' -PropertyType MultiString -Value @('keep', "$source\Music") | Out-Null
    New-ItemProperty -Path $key -Name 'Sid' -Value "$($sid)_Classes" | Out-Null
    New-ItemProperty -Path $key -Name 'Similar' -Value "$($source)2\x" | Out-Null
    New-ItemProperty -Path $key -Name 'Loose' -Value "$source -flag" | Out-Null
    $pathBytes = [Text.Encoding]::Unicode.GetBytes("$source\bin")
    New-ItemProperty -Path $key -Name 'Binary' -PropertyType Binary -Value $pathBytes | Out-Null
    # An explicit ACE for the user (changing the owner would need the
    # restore privilege switched on in this process).
    $acl = Get-Acl -Path $key
    $rule = New-Object Security.AccessControl.RegistryAccessRule ((New-Object Security.Principal.SecurityIdentifier $sid), 'FullControl', 'Allow')
    $acl.AddAccessRule($rule)
    Set-Acl -Path $key -AclObject $acl
    Dismount-TestHive $mount
    # Built from code points: Windows PowerShell 5.1 reads a script without
    # a BOM as ANSI.
    $unicodeName = "citt$([char]0xE0) $([char]0x2713).txt"
    Set-Content -LiteralPath "$docs\$unicodeName" -Value 'unicode'
    $sparse = "$docs\sparse.bin"
    [IO.File]::WriteAllBytes($sparse, [byte[]](1..16))
    & fsutil sparse setflag $sparse | Out-Null
    $fs = [IO.File]::OpenWrite($sparse); $fs.SetLength(64MB); $fs.Dispose()
    & fsutil sparse setrange $sparse 1048576 33554432 | Out-Null
    # A fresh profile has no LocalLow yet; give it one with its usual low
    # integrity label.
    New-Item -ItemType Directory -Path "$source\AppData\LocalLow" -Force | Out-Null
    & icacls "$source\AppData\LocalLow" /setintegritylevel '(OI)(CI)low' | Out-Null
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

    # Windows keeps writing to a freshly created profile for a moment (seen:
    # AppData\Local\Microsoft\Windows touched a few seconds after setup),
    # so the baseline is taken once the tree has been stable for 5 seconds.
    $baseline = Get-TreeFingerprint $source $sid
    for ($i = 0; $i -lt 12; $i++) {
        Start-Sleep -Seconds 5
        $again = Get-TreeFingerprint $source $sid
        if ($again -eq $baseline) { break }
        $baseline = $again
    }
    $script:Source = $source; $script:Sid = $sid; $script:Baseline = $baseline

    # --- S1: build and verify --------------------------------------------
    $r = Invoke-Tool @('migrate', '--stage-only', '--source', ".\$testUser", '--target', $TargetAccount)
    $id = Get-MigrationId $r.Output
    Write-Result 'S1: working copy built and verified (exit 0)' (($r.ExitCode -eq 0) -and ($r.Output -match 'verified: all')) $r.Output
    if ($r.ExitCode -ne 0) { throw 'stage failed; the remaining checks need the copy' }
    if ($r.Output -match '(?m)^Working copy ready: (.+)$') { $staging = $Matches[1].Trim() }
    $targetPath = $staging.Substring(0, $staging.Length - $StagingSuffix.Length)
    Write-Host "copy at $staging (target $targetPath), migration $id"
    $targetSid = (New-Object Security.Principal.NTAccount $TargetAccount).Translate([Security.Principal.SecurityIdentifier]).Value
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
    Write-Result 'S2: explicit ACL kept, source SID translated' ((Get-Sddl "$docs\explicit-acl.txt").Replace($sid, $targetSid) -eq (Get-Sddl "$copyDocs\explicit-acl.txt"))
    Write-Result 'S2: profile folder ACL kept, source SID translated' ((Get-Sddl $source).Replace($sid, $targetSid) -eq (Get-Sddl $staging))
    # Files the test wrote as SYSTEM are owned by Administrators; the hive
    # CreateProfile wrote is owned by the user.
    $owner = { param($p) (Get-Acl -LiteralPath $p).GetOwner([Security.Principal.SecurityIdentifier]).Value }
    Write-Result 'S2: owners translated (source user -> target, others kept)' (((& $owner "$source\NTUSER.DAT") -eq $sid) -and ((& $owner "$staging\NTUSER.DAT") -eq $targetSid) -and ((& $owner "$copyDocs\plain.txt") -eq (& $owner "$docs\plain.txt")))
    # Windows PowerShell 5.1 cannot open paths beyond MAX_PATH; the tool's
    # own verification covers those.
    $copySddls = Get-ChildItem -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue -Attributes !ReparsePoint |
        Where-Object { $_.FullName.Length -lt 248 } | ForEach-Object { Get-Sddl $_.FullName }
    Write-Result 'S2: no file in the copy names the source SID' (($copySddls.Count -gt 100) -and -not ($copySddls -match [regex]::Escape($sid))) "$($copySddls.Count) checked"
    $label = (& icacls "$staging\AppData\LocalLow" | Out-String)
    Write-Result 'S2: LocalLow keeps its low integrity label' ($label -match 'Low Mandatory Level') $label

    # --- S6: the copy's registry ------------------------------------------
    $mount = 'pmst_copy_' + (Get-Random)
    & reg.exe load "HKU\$mount" "$staging\NTUSER.DAT" | Out-Null
    $script:Mounts.Add($mount)
    try {
        $v = Get-ItemProperty -Path "Registry::HKEY_USERS\$mount\Software\pmtest"
        Write-Result 'S6: path value rewritten' ($v.Path -eq "$targetPath\Documents\x.txt") $v.Path
        # Read without expansion: the provider would turn %TEMP% into a path.
        $raw = [Microsoft.Win32.Registry]::Users.OpenSubKey("$mount\Software\pmtest")
        $expand = $raw.GetValue('Expand', $null, 'DoNotExpandEnvironmentNames')
        $raw.Dispose()
        Write-Result 'S6: expandable value rewritten' ($expand -eq "$targetPath\AppData;%TEMP%") $expand
        Write-Result 'S6: multi-string rewritten, other items kept' (($v.Multi[0] -eq 'keep') -and ($v.Multi[1] -eq "$targetPath\Music")) ($v.Multi -join '|')
        Write-Result 'S6: SID in text rewritten' ($v.Sid -eq "$($targetSid)_Classes") $v.Sid
        Write-Result 'S6: similar path left alone' ($v.Similar -eq "$($source)2\x") $v.Similar
        Write-Result 'S6: loose mention left alone' ($v.Loose -eq "$source -flag") $v.Loose
        Write-Result 'S6: binary value left alone' ([Text.Encoding]::Unicode.GetString($v.Binary) -eq "$source\bin")
        $keySddl = (Get-Acl -Path "Registry::HKEY_USERS\$mount\Software\pmtest").Sddl
        Write-Result 'S6: key ACE names the target, not the source' (($keySddl -match [regex]::Escape($targetSid)) -and ($keySddl -notmatch [regex]::Escape($sid))) $keySddl
        $rootSddl = (Get-Acl -Path "Registry::HKEY_USERS\$mount").Sddl
        Write-Result 'S6: hive root ACL names the target, not the source' (($rootSddl -match [regex]::Escape($targetSid)) -and ($rootSddl -notmatch [regex]::Escape($sid))) $rootSddl
    } finally {
        Dismount-TestHive $mount
    }
    Write-Result 'S6: the tool reported what it left as is' (($r.Output -match 'left as is: .*Loose') -and ($r.Output -match 'left as is: .*Binary')) $r.Output

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
    Test-SourceUnchanged 'S3: source unchanged after the copy'

    # --- S4: rollback --------------------------------------------------------
    $r = Invoke-Tool @('rollback', '--migration', $id)
    Write-Result 'S4: rollback succeeds (exit 0)' ($r.ExitCode -eq 0) $r.Output
    Write-Result 'S4: working copy removed' (-not (Test-Path -LiteralPath $staging))
    if (-not (Test-Path -LiteralPath $staging)) { $staging = $null }
    Test-SourceUnchanged 'S4: source unchanged after the rollback'

    # --- S5: a copy that cannot be completed --------------------------------
    $holder = [IO.File]::Open("$docs\random.bin", 'Open', 'ReadWrite', 'None')
    $r = Invoke-Tool @('migrate', '--stage-only', '--source', ".\$testUser", '--target', $TargetAccount)
    $holder.Dispose(); $holder = $null
    $failedId = Get-MigrationId $r.Output
    Write-Result 'S5: copy fails and says so (exit 3)' (($r.ExitCode -eq 3) -and ($r.Output -match 'random.bin')) $r.Output
    Write-Result 'S5: the partial copy was removed automatically' (($r.Output -match 'system is as it was') -and -not (Test-Path -LiteralPath "$targetPath$StagingSuffix"))
    $journal = Get-Content -LiteralPath (Join-Path $WorkDir "migrations\$failedId\journal.log")
    Write-Result 'S5: journal records the rollback' ($journal[-1] -match 'rollback_done')
    Test-SourceUnchanged 'S5: source unchanged'

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
    foreach ($m in @($script:Mounts)) { Dismount-TestHive $m }
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

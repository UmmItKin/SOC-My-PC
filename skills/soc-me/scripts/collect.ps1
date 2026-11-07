# Read-only SOC triage collector for Windows 10/11. Changes nothing.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File collect.ps1 [DAYS]
#   DAYS = "recently changed" window, default 7.
# Works without admin; sections that need admin say so instead of failing.
# Targets Windows PowerShell 5.1 (no ?., ??, or ternary operators).
param([int]$Days = 7)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}
$since = (Get-Date).AddDays(-$Days)

function Sec([string]$name) { "`n=== $name ===" }
function Show($rows) { if ($rows) { $rows | Format-Table -AutoSize -Wrap | Out-String -Width 400 } else { '(none)' } }
function Run([string]$name, [scriptblock]$block) {
    Sec $name
    try { & $block } catch { "(unavailable: $(($_.Exception.Message -split "`n")[0]))" }
}
function Under($path, [string[]]$dirs) {
    if (-not $path) { return $false }
    foreach ($d in $dirs) { if ($d -and $path.StartsWith($d, [StringComparison]::OrdinalIgnoreCase)) { return $true } }
    return $false
}

$windir = $env:SystemRoot
$procs = @()
try { $procs = @(Get-CimInstance Win32_Process) } catch {}
$byPid = @{}
foreach ($p in $procs) { $byPid[[int]$p.ProcessId] = $p }
$name = { param($id) if ($byPid.ContainsKey([int]$id)) { $byPid[[int]$id].Name } else { '?' } }

Run 'host' {
    $os = Get-CimInstance Win32_OperatingSystem
    "$($os.Caption) $($os.Version) build $($os.BuildNumber)"
    "uptime: $(((Get-Date) - $os.LastBootUpTime).ToString('d\.hh\:mm'))  (d.hh:mm)"
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $admin = (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    "user: $($id.Name)  elevated: $admin  (not elevated: Defender exclusions, WMI subscriptions and some owners are hidden)"
}

Run 'top-cpu' {
    # Total CPU seconds since start; average % = cpu_s / runtime / cores.
    $cores = [Environment]::ProcessorCount
    Show (Get-Process | Where-Object { $_.CPU } | Sort-Object CPU -Descending | Select-Object -First 25 | ForEach-Object {
        $p = $byPid[[int]$_.Id]
        $run = $null; try { $run = (Get-Date) - $_.StartTime } catch {}
        [pscustomobject]@{
            PID = $_.Id; Name = $_.ProcessName; CPU_s = [int]$_.CPU
            AvgPct = if ($run -and $run.TotalSeconds -gt 0) { [math]::Round($_.CPU / $run.TotalSeconds / $cores * 100, 1) } else { '' }
            Runtime = if ($run) { $run.ToString('d\.hh\:mm') } else { '' }
            MB = [int]($_.WorkingSet64 / 1MB)
            Cmd = if ($p -and $p.CommandLine) { $p.CommandLine.Substring(0, [math]::Min(160, $p.CommandLine.Length)) } else { '' }
        } })
}

Run 'top-mem' {
    Show (Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 15 |
        Select-Object Id, ProcessName, @{n='MB'; e={[int]($_.WorkingSet64 / 1MB)}}, Path)
}

Run 'exe-from-odd-path' {
    # Executables in user-writable or temp locations.
    $odd = '\\AppData\\Local\\Temp\\|\\Windows\\Temp\\|\\Users\\Public\\|\\Downloads\\|\\\$Recycle\.Bin\\|^[A-Z]:\\ProgramData\\[^\\]+\.exe$|\\AppData\\Roaming\\[^\\]+\.exe$'
    Show ($procs | Where-Object { $_.ExecutablePath -match $odd } |
        Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine)
}

Run 'masquerade' {
    # Windows system binary names running from outside the Windows folder.
    $sys = 'svchost.exe','lsass.exe','csrss.exe','winlogon.exe','services.exe','smss.exe','wininit.exe','explorer.exe',
           'taskhostw.exe','dllhost.exe','rundll32.exe','conhost.exe','spoolsv.exe','lsm.exe','dwm.exe','sihost.exe'
    Show ($procs | Where-Object { $sys -contains $_.Name.ToLower() -and $_.ExecutablePath -and -not (Under $_.ExecutablePath @($windir)) } |
        Select-Object ProcessId, Name, ExecutablePath)
}

Run 'suspicious-cmdline' {
    # Encoded or download-and-run PowerShell, and LOLBins fetching remote content.
    $rx = '(?i)-enc(odedcommand)?\s|frombase64string|downloadstring|downloadfile|invoke-expression|\biex\b|net\.webclient|' +
          'invoke-webrequest.+\|\s*iex|bitsadmin.+/transfer|certutil.+-urlcache|mshta(\.exe)?\s+["'']?(https?|javascript|vbscript):|' +
          'regsvr32.+/i:https?|rundll32.+(javascript|https?:)|-w(indowstyle)?\s+hid'
    Show ($procs | Where-Object { $_.CommandLine -match $rx } | Select-Object ProcessId, ParentProcessId, Name, CommandLine)
}

Run 'odd-parent-child' {
    # Office, PDF readers or script hosts starting a shell.
    $parents = 'winword.exe','excel.exe','powerpnt.exe','outlook.exe','onenote.exe','acrord32.exe','acrobat.exe','wscript.exe','cscript.exe','mshta.exe'
    $kids = 'cmd.exe','powershell.exe','pwsh.exe','wscript.exe','cscript.exe','mshta.exe','rundll32.exe','regsvr32.exe','certutil.exe','bitsadmin.exe'
    Show ($procs | Where-Object { $kids -contains $_.Name.ToLower() -and $parents -contains (& $name $_.ParentProcessId).ToLower() } |
        Select-Object ProcessId, @{n='Parent'; e={& $name $_.ParentProcessId}}, Name, CommandLine)
}

Run 'unsigned-running' {
    # Running executables outside the Windows folder without a valid signature.
    $paths = $procs | Where-Object { $_.ExecutablePath -and -not (Under $_.ExecutablePath @($windir)) } |
             Select-Object -ExpandProperty ExecutablePath -Unique | Select-Object -First 200
    Show ($paths | ForEach-Object {
        $s = Get-AuthenticodeSignature -FilePath $_ -ErrorAction SilentlyContinue
        if ($s -and $s.Status -ne 'Valid') { [pscustomobject]@{ Status = $s.Status; Path = $_ } } })
}

Run 'orphans-long-running' {
    # Interactive-session processes whose parent has exited, running over 1 hour: forgotten dev servers, browsers, agents.
    $cut = (Get-Date).AddHours(-1)
    Show ($procs | Where-Object { $_.SessionId -ne 0 -and -not $byPid.ContainsKey([int]$_.ParentProcessId) -and $_.CreationDate -lt $cut } |
        Select-Object ProcessId, Name, @{n='Started'; e={$_.CreationDate}},
            @{n='MB'; e={[int]($_.WorkingSetSize / 1MB)}}, CommandLine)
}

Run 'listeners' {
    $tcp = Get-NetTCPConnection -State Listen | Select-Object @{n='Proto'; e={'tcp'}}, LocalAddress, LocalPort, OwningProcess
    $udp = Get-NetUDPEndpoint | Select-Object @{n='Proto'; e={'udp'}}, LocalAddress, LocalPort, OwningProcess
    Show (@($tcp) + @($udp) | Where-Object { $_.LocalAddress -notmatch '^(127\.|::1$)' } | Sort-Object Proto, LocalPort |
        Select-Object Proto, LocalAddress, LocalPort, OwningProcess, @{n='Process'; e={& $name $_.OwningProcess}})
}

Run 'established' {
    Show (Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1$)' } |
        Select-Object LocalPort, RemoteAddress, RemotePort, OwningProcess, @{n='Process'; e={& $name $_.OwningProcess}})
}

Run 'autoruns' {
    $keys = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    Show ($keys | ForEach-Object {
        $k = $_; $v = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
        if ($v) { $v.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } |
            ForEach-Object { [pscustomobject]@{ Key = $k; Name = $_.Name; Command = $_.Value } } } })
    '-- startup folders'
    $dirs = [Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup')
    Show ($dirs | Where-Object { $_ } | ForEach-Object { Get-ChildItem -LiteralPath $_ -Force -ErrorAction SilentlyContinue } |
        Select-Object LastWriteTime, FullName)
    '-- winlogon, IFEO debuggers, AppInit_DLLs'
    $wl = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
    "Shell=$($wl.Shell)  Userinit=$($wl.Userinit)"
    Show (Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue |
        ForEach-Object { $d = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
            if ($d) { [pscustomobject]@{ Image = $_.PSChildName; Debugger = $d } } })
    $ai = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows' -ErrorAction SilentlyContinue
    "AppInit_DLLs=$($ai.AppInit_DLLs)  LoadAppInit_DLLs=$($ai.LoadAppInit_DLLs)"
}

Run 'scheduled-tasks' {
    # Non-Microsoft tasks. Date is when the task was registered, if the author set it.
    Show (Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
        [pscustomobject]@{ Task = $_.TaskPath + $_.TaskName; State = $_.State; Author = $_.Author; Date = $_.Date
            Action = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' ; ' } })
}

Run 'services' {
    # Services whose binary is outside the Windows folder; Unquoted = path with spaces and no quotes.
    Show (Get-CimInstance Win32_Service | Where-Object { $_.PathName -and $_.PathName -notmatch [regex]::Escape($windir) } |
        Select-Object Name, State, StartMode, StartName,
            @{n='Unquoted'; e={ $_.PathName -notmatch '^"' -and ($_.PathName -split '\.exe')[0] -match ' ' }}, PathName)
}

Run 'wmi-subscriptions' {
    # Permanent WMI event subscriptions are rare on desktops and a known persistence method. Needs admin.
    $f = Get-CimInstance -Namespace root/subscription -ClassName __EventFilter
    $c = Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer
    Show (@($f | Select-Object @{n='Kind'; e={'filter'}}, Name, Query) + @($c | Select-Object @{n='Kind'; e={$_.CimClass.CimClassName}}, Name,
        @{n='Query'; e={ if ($_.CommandLineTemplate) { $_.CommandLineTemplate } else { $_.ScriptText } }}))
}

Run 'defender' {
    $s = Get-MpComputerStatus
    "AntivirusEnabled=$($s.AntivirusEnabled)  RealTimeProtectionEnabled=$($s.RealTimeProtectionEnabled)  " +
    "TamperProtected=$($s.IsTamperProtected)  SignatureAge(days)=$($s.AntivirusSignatureAge)"
    $p = Get-MpPreference
    "ExclusionPath=$($p.ExclusionPath -join '; ')"
    "ExclusionProcess=$($p.ExclusionProcess -join '; ')"
    "ExclusionExtension=$($p.ExclusionExtension -join '; ')"
    '(without admin, exclusions show as "N/A: Must be an administrator")'
}

Run 'accounts' {
    Show (Get-LocalUser | Where-Object Enabled | Select-Object Name, LastLogon, PasswordLastSet)
    '-- Administrators group'
    Show (Get-LocalGroupMember -Group Administrators | Select-Object Name, ObjectClass, PrincipalSource)
}

Run 'recent-executables' {
    # Scripts and binaries written in the window to user-writable folders.
    $roots = $env:TEMP, $env:APPDATA, $env:LOCALAPPDATA, $env:PUBLIC, $env:ProgramData
    if ($env:USERPROFILE) { $roots += Join-Path $env:USERPROFILE 'Downloads' }
    $ext = '.exe','.dll','.scr','.ps1','.bat','.cmd','.vbs','.js','.hta','.lnk','.msi'
    Show ($roots | Where-Object { $_ -and (Test-Path $_) } | ForEach-Object {
        Get-ChildItem -Path $_ -Recurse -Depth 3 -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt $since -and $ext -contains $_.Extension.ToLower() } } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 60 LastWriteTime, Length, FullName)
}

Run 'hardening' {
    '-- firewall profiles'
    try { Show (Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction) } catch { "(unavailable: $(($_.Exception.Message -split "`n")[0]))" }
    $g = { param($k, $v) $x = Get-ItemProperty -Path $k -Name $v -ErrorAction SilentlyContinue; if ($x) { $x.$v } else { '(not set)' } }
    "LLMNR policy EnableMulticast=$(& $g 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast')  (0 = off; not set = on)"
    "SMB1 server=$(& $g 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1')  (0 = off)"
    "RDP fDenyTSConnections=$(& $g 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections')  (1 = RDP off)"
    "UAC EnableLUA=$(& $g 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA')  (1 = on)"
}

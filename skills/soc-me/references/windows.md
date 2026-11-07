# Windows

## Collect
From PowerShell or cmd:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "<skill-dir>\scripts\collect.ps1" [DAYS]
```
From WSL, to check the Windows host:
```sh
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$(wslpath -w <skill-dir>/scripts/collect.ps1)" [DAYS]
```
`-ExecutionPolicy Bypass` applies to this one run only and changes no setting. DAYS is the window for "recently changed" (default 7). The signature checks can take a few minutes.

It works without administrator rights. Without them, Defender exclusions, WMI subscriptions and some process details are hidden; the collector prints "(unavailable: ...)" for those, and the report should say what admin would reveal.

## Follow-up checks
- Command line and parent: `Get-CimInstance Win32_Process -Filter "ProcessId=<pid>" | Select-Object Name, ParentProcessId, ExecutablePath, CommandLine`
- Signature: `Get-AuthenticodeSignature "<path>" | Format-List Status, SignerCertificate`
- Hash, to look up elsewhere: `Get-FileHash "<path>" -Algorithm SHA256`
- Connections of one process: `Get-NetTCPConnection -OwningProcess <pid>`
- A scheduled task in full: `Export-ScheduledTask -TaskName "<name>" -TaskPath "<path>"`

## Red flags
| Signal | ATT&CK | Collector section |
|---|---|---|
| Executable in `%TEMP%`, `Downloads`, `C:\Users\Public`, `$Recycle.Bin`, or directly in `ProgramData` or `AppData\Roaming` | T1204.002, T1036.005 | `exe-from-odd-path` |
| A Windows system name (`svchost.exe`, `lsass.exe`, `csrss.exe`, ...) running from outside `C:\Windows` | T1036.005 | `masquerade` |
| PowerShell with `-EncodedCommand`, `FromBase64String`, `DownloadString`, `IEX`, or a hidden window | T1059.001, T1027 | `suspicious-cmdline` |
| `mshta`, `rundll32`, `regsvr32`, `certutil` or `bitsadmin` fetching or running remote content | T1218, T1105 | `suspicious-cmdline` |
| Office, a PDF reader or a script host starting `cmd`, PowerShell or another script host | T1204.002, T1059 | `odd-parent-child` |
| A running executable outside `C:\Windows` with no valid signature (many open-source tools are unsigned: check the folder and the user's projects first) | T1036, T1553.002 | `unsigned-running` |
| Run or RunOnce entries, Startup folder items, or Winlogon `Shell`/`Userinit` changes you don't recognise | T1547.001, T1547.004 | `autoruns` |
| An Image File Execution Options `Debugger` value, or `AppInit_DLLs` set | T1546.012, T1546.010 | `autoruns` |
| A non-Microsoft scheduled task running a script, an `AppData` binary or an encoded command | T1053.005 | `scheduled-tasks` |
| A service whose binary is in a user-writable folder, or an unquoted path with spaces | T1543.003, T1574.009 | `services` |
| Any permanent WMI event subscription (rare on a desktop) | T1546.003 | `wmi-subscriptions` |
| Defender real-time protection off, or exclusions for a whole drive, `%TEMP%` or common script types | T1562.001 | `defender` |
| An unexpected member of Administrators, or a new enabled local account | T1136.001, T1098 | `accounts` |
| Listener on all interfaces from an unexpected program; outbound connection to a raw IP on an odd port | T1071, T1571 | `listeners`, `established` |
| Scripts or binaries written recently to user-writable folders | T1105 | `recent-executables` |
| Miners: sustained high CPU from an unfamiliar name, especially with a pool connection (ports 3333/4444/5555/14444) | T1496 | `top-cpu`, `established` |

## Junk
- Processes whose parent has exited and that have run for hours (`orphans-long-running`): forgotten dev servers (`node`, `python`), headless browsers, agent daemons, `adb`.
- Heavy CPU or memory from apps the user is not using: Electron apps left in the tray, updaters stuck in a loop.
- Cleanup commands: `Stop-Process -Id <pid>`. For a whole tree, `taskkill /PID <pid> /T` stops the children too.

## Hardening ideas
Check these only when the collector shows them. Each fix should be undone by deleting one registry value or reversing one setting, and most need an administrator PowerShell: say so in the card.
- LLMNR on (`EnableMulticast` not set): `New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null` then `Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0 -Type DWord`. Undo: delete the `EnableMulticast` value.
- SMB1 server on: `Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force`.
- A firewall profile turned off: `Set-NetFirewallProfile -Profile <Name> -Enabled True`.
- RDP on when the user doesn't use it: turn it off in Settings > System > Remote Desktop.

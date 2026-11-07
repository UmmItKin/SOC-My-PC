# SOC-My-PC

Read-only SOC triage for a Linux or Windows machine, packaged as an agent skill. Ask your coding agent to check the machine, and it tells you whether anything looks compromised, which processes are odd but probably yours, and which ones are wasting CPU or memory. You get the answer in the chat and as one HTML report.

It never changes the system. It runs only when you call it, and nothing stays running in the background.

## Install

```sh
npx skills add UmmItKin/SOC-My-PC
```

The installer asks which agents to install for. It works with Claude Code, Codex, and the other agents that `npx skills` supports.

## Use

| Agent | Linux | Windows |
|---|---|---|
| Claude Code | `/soc-me linux` | `/soc-me windows` |
| Codex | `$soc-me linux` | `$soc-me windows` |

Without `linux` or `windows`, the agent detects the system it runs on. From WSL, `/soc-me windows` checks the Windows host.

Add `recheck` (for example `/soc-me linux recheck`) to see what changed since the last report in the same session: what is gone, what is new, and what is still there.

The skill is explicit only. The agent never starts it on its own.

## What it checks

On both systems: processes running from temp or user-writable folders, processes that pretend to be system processes, listening ports and outbound connections, persistence, extra admin accounts, recently added executables, long-running orphaned processes, and heavy CPU or memory use.

**Linux** also checks `/etc/ld.so.preload` and `LD_PRELOAD`, systemd units, timers, cron, autostart and shell startup files, SSH `authorized_keys`, files no package owns, SUID/SGID files, kernel taint and zombies.

**Windows** also checks encoded or download-and-run PowerShell, Office or script hosts starting a shell, running programs without a valid signature, Run keys, the Startup folder, Winlogon and IFEO hijacks, scheduled tasks, services in user-writable folders, WMI event subscriptions, Defender status and exclusions, and firewall, SMB1, LLMNR and RDP settings.

The full lists, with what counts as a red flag, are in [`references/linux.md`](skills/soc-me/references/linux.md) and [`references/windows.md`](skills/soc-me/references/windows.md).

When something looks suspicious, the report adds the matching MITRE ATT&CK technique ID, such as T1574.006 for `LD_PRELOAD` hijacking.

## License

[MIT](LICENSE)

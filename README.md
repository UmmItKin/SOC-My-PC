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

## The report

The agent writes the result to `~/.local/state/soc-me/` on Linux or `%LOCALAPPDATA%\soc-me\` on Windows, and gives you the link. The page has:

- the verdict (clean, suspicious or compromised) with a one-line summary
- what you can clean, with a button that copies all cleanup commands
- what looks odd but is probably yours
- hardening suggestions, each with the risk explained and a command you can copy
- the checks that passed

Light or dark follows your system. Printing gives a 16:9 slide deck.

To see one before you install, open [`skills/soc-me/references/example.html`](skills/soc-me/references/example.html) in a browser (download it; GitHub shows HTML as source). It is a made-up compromised machine, so every section appears.

The page makes no network requests. Every value from the host is escaped, because process names and arguments can be attacker-controlled. The only script on the page is the copy button, and the page's Content Security Policy allows only that script.

The agent never runs the cleanup commands. You read them and run them yourself.

## Requirements

- `python3` for the HTML report (on Windows, `py -3` or `python`)
- No root or administrator needed. Without them, some details are hidden (socket owners on Linux; Defender exclusions and WMI subscriptions on Windows), and the report says so.

**Linux:** `sh`, `ps`, `find`, and `ss` or `netstat`. Tested on Arch Linux. On Debian, Ubuntu, Fedora and similar systems the collector should work as is. On Alpine and other BusyBox systems, the CPU and memory rankings and the "recently changed" checks come out empty, because they need GNU `ps --sort` and `find -newermt`.

**Windows:** Windows 10 or 11 with the built-in Windows PowerShell 5.1. The Windows collector is new: it parses and degrades cleanly under PowerShell 7 on Linux, but has not yet been run on a real Windows machine. Reports of problems are welcome.

## Run without an agent

```sh
sh skills/soc-me/scripts/collect.sh [DAYS]   # Linux raw findings; DAYS = "recently changed" window, default 7
sh skills/soc-me/scripts/smoke.sh            # self-test: collector sections, HTML escaping, CSP hash
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File skills\soc-me\scripts\collect.ps1 [DAYS]   # Windows raw findings
```

## Layout

```
skills/soc-me/
├── SKILL.md              shared rules; picks linux.md or windows.md
├── agents/openai.yaml    Codex settings (explicit invocation only)
├── references/
│   ├── linux.md          Linux collector, follow-up checks, red flags, junk, hardening
│   ├── windows.md        the same for Windows
│   ├── example.json      a complete made-up report; the agent copies its structure
│   └── example.html      the same report, rendered
└── scripts/
    ├── collect.sh        read-only Linux collector
    ├── collect.ps1       read-only Windows collector
    ├── report.py         JSON to HTML report
    └── smoke.sh          self-test
```

## License

[MIT](LICENSE)

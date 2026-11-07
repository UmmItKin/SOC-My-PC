# SOC-My-PC

Read-only SOC triage for a Linux machine, packaged as an agent skill. Ask your coding agent to check the machine, and it tells you whether anything looks compromised, which processes are odd but probably yours, and which ones are wasting CPU or memory. You get the answer in the chat and as one HTML report.

It never changes the system. It runs only when you call it, and nothing stays running in the background.

## Install

```sh
npx skills add UmmItKin/SOC-My-PC
```

The installer asks which agents to install for. It works with Claude Code, Codex, and the other agents that `npx skills` supports.

## Use

| Agent | Command |
|---|---|
| Claude Code | `/soc-me` |
| Codex | `$soc-me` |

Run it again with `/soc-me recheck` (Claude Code) to see what changed since the last report in the same session: what is gone, what is new, and what is still there.

The skill is explicit only. The agent never starts it on its own.

## What it checks

- Processes running from deleted files or from `/tmp`, `/dev/shm` and similar temp folders
- Processes that pretend to be kernel threads
- `/etc/ld.so.preload` and `LD_PRELOAD`
- Listening ports and outbound connections
- systemd units, timers, cron, autostart entries and shell startup files changed recently
- Extra root accounts, service accounts with a login shell, and SSH `authorized_keys`
- Recent executables that no package owns, and recent SUID/SGID files
- Kernel taint and loaded modules
- Orphaned long-running processes, zombies, and heavy CPU or memory use

When something looks suspicious, the report adds the matching MITRE ATT&CK technique ID, such as T1574.006 for `LD_PRELOAD` hijacking.

## The report

The agent writes the result to `~/.local/state/soc-me/report-<time>.html` and gives you the link. The page has:

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

- Linux with `sh`, `ps` and `find`, plus `ss` or `netstat`
- `python3` for the HTML report
- No root needed. Without root, some socket owners and other users' processes are hidden, and the report says so.

Tested on Arch Linux. On Debian, Ubuntu, Fedora and similar systems the collector should work as is. On Alpine and other BusyBox systems, the CPU and memory rankings and the "recently changed" checks come out empty, because they need GNU `ps --sort` and `find -newermt`.

## Run without an agent

```sh
sh skills/soc-me/scripts/collect.sh [DAYS]   # raw findings; DAYS = "recently changed" window, default 7
sh skills/soc-me/scripts/smoke.sh            # self-test: collector sections, HTML escaping, CSP hash
```

## Layout

```
skills/soc-me/
├── SKILL.md              instructions the agent follows
├── agents/openai.yaml    Codex settings (explicit invocation only)
├── references/
│   ├── example.json      a complete made-up report; the agent copies its structure
│   └── example.html      the same report, rendered
└── scripts/
    ├── collect.sh        read-only collector
    ├── report.py         JSON to HTML report
    └── smoke.sh          self-test
```

## License

[MIT](LICENSE)

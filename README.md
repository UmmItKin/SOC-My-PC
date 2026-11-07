# SOC-My-PC

Read-only SOC triage for any Linux host, packaged as an agent skill. It flags suspicious processes, persistence and network activity, and lists junk processes you can clean. It never modifies the system. It runs only when you call it; nothing stays running in the background.

## Install

```sh
npx skills add UmmItKin/SOC-My-PC
```

## Use

| Agent | Command |
|---|---|
| Claude Code | `/soc-me` (later, `/soc-me recheck`) |
| Codex | `$soc-me` |

The collector also works on its own: `sh skills/soc-me/scripts/collect.sh [DAYS]`.

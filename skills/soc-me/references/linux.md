# Linux

## Collect
```sh
sh <skill-dir>/scripts/collect.sh [DAYS]
```
DAYS is the window for "recently modified" (default 7). It takes about 30 s and needs no root. Without root, other users' socket owners and executables are hidden.

Needs GNU `ps` and `find`. On Alpine and other BusyBox systems the CPU and memory rankings and the "recently modified" checks come out empty: say so in the report instead of reading empty as clean.

## Follow-up checks
- Working folder: `ls -l /proc/<pid>/cwd`
- Parent and runtime: `ps -o pid,ppid,etime,args -p <pid>`
- Executable: `ls -l /proc/<pid>/exe` (`(deleted)` means the file is gone from disk)
- Package owner: `pacman -Qo <path>`, `dpkg -S <path>`, `rpm -qf <path>` or `apk info -W <path>`
- Connections of one process: `ss -tunp | grep 'pid=<pid>,'`

## Red flags
| Signal | ATT&CK | Collector section |
|---|---|---|
| Executable is deleted, or lives in `/tmp`, `/dev/shm`, `/var/tmp`, `/run/user` | T1070.004, T1036.005 | `exe-from-odd-path` |
| `[bracketed]` kernel-thread name but has an exe | T1036.005 | `fake-kernel-thread` |
| Any `/etc/ld.so.preload`, or a process with `LD_PRELOAD` (`libmozsandbox.so` in Firefox or Floorp children is the browser sandbox, which is normal) | T1574.006 | `preload` |
| Listener on `0.0.0.0`/`::` from an unexpected binary; outbound connection to a raw IP on an odd port; reverse-shell shape (`sh`/`bash`/`python` holding a socket) | T1059.004, T1071 | `listeners`, `established` |
| Recently modified systemd unit, cron, XDG autostart, shell rc, or an `authorized_keys` you don't recognise | T1543.002, T1053.003, T1547.013, T1546.004, T1098.004 | `persistence-files`, `ssh-keys` |
| Extra uid 0 account; a service account with a login shell (check the package defaults first: `postgres` and `greeter` get one from their packages) | T1136.001, T1078.003 | `accounts` |
| Recent binary with no owning package; recent SUID/SGID outside known sandboxes (`chrome-sandbox` is normal) | T1548.001 | `unowned-recent-binaries`, `suid-recent` |
| Kernel tainted with out-of-tree or unsigned modules | T1547.006 | `host`, `kernel-modules` |
| Miners: sustained high CPU from an unfamiliar name, especially with a pool connection (ports 3333/4444/5555/14444) | T1496 | `top-cpu`, `established` |

## Junk
- Orphaned long-running user processes (`orphans-long-running`): forgotten headless browsers, dev servers, `adb`, agent daemons.
- Heavy CPU or RAM use from something the user is not actively using.
- Zombies. They clear only when the parent exits, so name the **parent** and its command.
- Cleanup commands: `kill <pid>`; for a whole tree, list every PID, parent first.

## Hardening ideas
Check these only when the collector shows them. Each fix should be undone by deleting one file.
- LLMNR listening on `0.0.0.0:5355`: drop-in `/etc/systemd/resolved.conf.d/no-llmnr.conf` with `[Resolve]` and `LLMNR=no`, then `sudo systemctl restart systemd-resolved`.
- A service listening on all interfaces that only needs localhost.
- `authorized_keys` with keys the user does not recognise: tell them to review the file, not to delete it.

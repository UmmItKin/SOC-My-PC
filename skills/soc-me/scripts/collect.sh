#!/bin/sh
# Read-only SOC triage collector for any Linux. Changes nothing.
# Usage: collect.sh [DAYS]   (DAYS = "recently modified" window, default 7)
# Without root some owners/paths are hidden; the output says where.
DAYS=${1:-7}
have() { command -v "$1" >/dev/null 2>&1; }
sec() { printf '\n=== %s ===\n' "$1"; }

sec host
uname -a
grep -E '^(PRETTY_NAME|ID)=' /etc/os-release 2>/dev/null
uptime
echo "uid=$(id -u) (non-root: other users' sockets/exe are hidden)"
echo "kernel tainted=$(cat /proc/sys/kernel/tainted 2>/dev/null)"

sec top-cpu
ps -eo pid,ppid,user,%cpu,%mem,rss,etime,args --sort=-%cpu | head -25 | cut -c1-220

sec top-mem
ps -eo pid,ppid,user,rss,etime,comm --sort=-rss | head -15

sec exe-from-odd-path
# deleted binaries or binaries living in world-writable/temp dirs
for p in /proc/[0-9]*; do
  e=$(readlink "$p/exe" 2>/dev/null) || continue
  case "$e" in *'(deleted)'*|/tmp/*|/dev/shm/*|/var/tmp/*|/run/user/*|*/.cache/*)
    echo "${p#/proc/} $e :: $(tr '\0' ' ' < "$p/cmdline" | cut -c1-160)";; esac
done

sec fake-kernel-thread
# real kthreads have no exe; a [bracketed] name WITH an exe is masquerading
for p in /proc/[0-9]*; do
  a=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
  case "$a" in '['*) readlink "$p/exe" >/dev/null 2>&1 && echo "${p#/proc/} $a -> $(readlink "$p/exe")";; esac
done

sec preload
cat /etc/ld.so.preload 2>/dev/null || echo "(no /etc/ld.so.preload)"
grep -l 'LD_PRELOAD=' /proc/[0-9]*/environ 2>/dev/null | head

sec zombies
ps -eo pid,ppid,stat,etime,comm | awk 'NR==1 || $3 ~ /Z/'

sec orphans-long-running
# reparented to init, human user (uid>=1000), up >1h: often forgotten dev servers/browsers
ps -eo pid,ppid,uid,user,etimes,etime,args | awk 'NR==1 || ($2==1 && $3>=1000 && $3<65534 && $5>3600)' | cut -c1-200

sec listeners
if have ss; then ss -tulpnH; elif have netstat; then netstat -tulpn 2>/dev/null; else echo "(no ss/netstat)"; fi

sec established
if have ss; then ss -tpnH state established; elif have netstat; then netstat -tpn 2>/dev/null | grep ESTAB; fi

sec systemd
if have systemctl; then
  echo "-- running services"; systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}' | tr '\n' ' '; echo
  echo "-- user services"; systemctl --user list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print $1}' | tr '\n' ' '; echo
  echo "-- failed"; systemctl list-units --failed --no-pager --no-legend
  echo "-- timers"; systemctl list-timers --all --no-pager --no-legend | awk '{print $(NF-1), $NF}'
  systemctl --user list-timers --all --no-pager --no-legend 2>/dev/null | awk '{print $(NF-1), $NF}'
else echo "(no systemd)"; ls /etc/init.d 2>/dev/null | tr '\n' ' '; fi

sec persistence-files
# admin/user-added units, cron, autostart, rc files: list and flag recent ones
for d in /etc/systemd/system ~/.config/systemd/user /etc/cron.d /etc/cron.hourly /etc/cron.daily \
         /var/spool/cron /var/spool/cron/crontabs /etc/xdg/autostart ~/.config/autostart /etc/profile.d; do
  [ -e "$d" ] && { echo "-- $d"; ls -la "$d" 2>&1 | tail -n +2; }
done
for f in /etc/crontab /etc/rc.local; do [ -f "$f" ] && { echo "-- $f"; grep -v '^#' "$f" | grep .; }; done
have crontab && { echo "-- crontab -l"; crontab -l 2>&1; }
echo "-- modified in last $DAYS days"
find /etc/systemd /etc/cron* /etc/xdg/autostart /etc/profile.d /etc/ld.so.conf.d \
     ~/.config/systemd ~/.config/autostart ~/.bashrc ~/.zshrc ~/.profile ~/.bash_profile ~/.ssh \
     -newermt "-$DAYS days" -type f 2>/dev/null

sec ssh-keys
for h in /root /home/*; do f="$h/.ssh/authorized_keys"; [ -r "$f" ] && echo "$f: $(grep -c . "$f") key(s)"; done

sec accounts
awk -F: '$3==0 {print "uid0:", $1}' /etc/passwd
awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print "login-shell:", $1, $7}' /etc/passwd
have who && who
have last && last -n 10 2>/dev/null | head -12

sec unowned-recent-binaries
# binaries changed in the window that no package owns
if   have pacman; then own() { pacman -Qo "$1" >/dev/null 2>&1; }
elif have dpkg;   then own() { dpkg -S "$1" >/dev/null 2>&1; }
elif have rpm;    then own() { rpm -qf "$1" >/dev/null 2>&1; }
elif have apk;    then own() { apk info -W "$1" >/dev/null 2>&1; }
else own() { false; }; echo "(no known package manager: all listed)"; fi
find /usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin /opt -maxdepth 2 \
     -newermt "-$DAYS days" -type f -perm -u+x 2>/dev/null | while read -r f; do own "$f" || echo "$f"; done

sec suid-recent
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -newermt "-$DAYS days" 2>/dev/null

sec kernel-modules
have lsmod && echo "loaded: $(lsmod | tail -n +2 | wc -l)"
dmesg >/dev/null 2>&1 && dmesg | grep -iE "taint|out-of-tree|unsigned module" | tail -5 || echo "(dmesg restricted)"

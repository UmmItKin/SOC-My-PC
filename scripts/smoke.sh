#!/bin/sh
# Smoke check: collector exits 0 and emits every section header.
d=$(dirname "$0"); out=$(sh "$d/collect.sh" 1 2>&1) || { echo "FAIL: collect.sh exited non-zero"; exit 1; }
for s in host top-cpu top-mem exe-from-odd-path fake-kernel-thread preload zombies orphans-long-running \
         listeners established systemd persistence-files ssh-keys accounts unowned-recent-binaries suid-recent kernel-modules; do
  printf '%s\n' "$out" | grep -qx "=== $s ===" || { echo "FAIL: missing section $s"; exit 1; }
done
printf '%s\n' "$out" | sed -n '/=== orphans/,/^===/p' | grep -q ' nobody ' && { echo "FAIL: nobody in orphans"; exit 1; }
echo PASS

#!/bin/sh
# Smoke check: collector exits 0 and emits every section header.
d=$(dirname "$0"); out=$(sh "$d/collect.sh" 1 2>&1) || { echo "FAIL: collect.sh exited non-zero"; exit 1; }
for s in host top-cpu top-mem exe-from-odd-path fake-kernel-thread preload zombies orphans-long-running \
         listeners established systemd persistence-files ssh-keys accounts unowned-recent-binaries suid-recent kernel-modules; do
  printf '%s\n' "$out" | grep -qx "=== $s ===" || { echo "FAIL: missing section $s"; exit 1; }
done
printf '%s\n' "$out" | sed -n '/=== orphans/,/^===/p' | grep -q ' nobody ' && { echo "FAIL: nobody in orphans"; exit 1; }
t=$(mktemp); echo '{"title":"<script>x</script>","panels":[{"title":"t","cols":["a"],"rows":[["`<img onerror=1>`"]],"items":["+ <x-inj>","a `<x-inj>` b"],"copy":["kill 1</pre><x-inj>"]}]}' \
  | python3 "$d/report.py" -o "$t" >/dev/null || { echo "FAIL: report.py"; exit 1; }
grep -qE "<script>x|<img onerror|<x-inj>" "$t" && { echo "FAIL: unescaped HTML in report"; rm -f "$t"; exit 1; }
python3 - "$t" <<'PY' || { rm -f "$t"; exit 1; }
import base64, hashlib, re, sys
h = open(sys.argv[1]).read()
scripts = re.findall(r"<script>(.*?)</script>", h, re.S)
csp = re.search(r"script-src '(sha256-[^']+)'", h).group(1)
ok = len(scripts) == 1 and csp == "sha256-" + base64.b64encode(hashlib.sha256(scripts[0].encode()).digest()).decode()
sys.exit(0 if ok else print("FAIL: script count or CSP hash mismatch") or 1)
PY
rm -f "$t"
# The committed example must match what the renderer produces now.
t=$(mktemp); python3 "$d/report.py" -o "$t" < "$d/../references/example.json" >/dev/null \
  && cmp -s "$t" "$d/../references/example.html" || { echo "FAIL: references/example.html is stale; re-render it from example.json"; rm -f "$t"; exit 1; }
rm -f "$t"
# Windows collector: parse check only (it needs Windows to run for real). Skipped without pwsh.
if command -v pwsh >/dev/null 2>&1; then
  pwsh -NoProfile -Command "\$e=\$null; [void][System.Management.Automation.Language.Parser]::ParseFile('$d/collect.ps1',[ref]\$null,[ref]\$e); if (\$e) { \$e | ForEach-Object { \$_.ToString() }; exit 1 }" \
    || { echo "FAIL: collect.ps1 does not parse"; exit 1; }
else echo "skip: collect.ps1 parse check (no pwsh)"; fi
echo PASS

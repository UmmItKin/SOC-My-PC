#!/usr/bin/env python3
"""Render a soc-me report (JSON on stdin) into one self-contained HTML page.

Every string from the JSON is HTML-escaped: host data (process args, file
names) can be attacker-controlled. The only script is the copy button, allowed
by its hash in the CSP. No external resources.
On screen it is one readable page: title and host line, the verdict, then one
section per panel. Printing gives a
16:9 landscape deck, one section per page. Light or dark follows the system.

Usage: report.py [-o out.html] < report.json   (prints the output path)

JSON shape:
{
  "lang": "zh-Hant", "title": "...", "verdict": "clean|suspicious|compromised",
  "summary": "one-line verdict", "meta": {"time": "...", "host": "...", "kernel": "..."},
  "panels": [{"title": "...", "tone": "ok|warn|err|", "note": "...",
              "copy": ["kill 1", "kill 2"],      (optional: "copy all" button in the section header)
              "cols": ["PID", "..."], "rows": [["1", "`kill 1`", "no"]],
              "items": ["plain line", "+ new", "- gone", "~ still"],
              "cards": [{"title": "low Name", "body": "what it is and the risk", "cmd": ["line 1", "line 2"]}]}],
}
Text: `code` spans render as code anywhere in a string (one click selects a span).
A leading ok / no / warn renders a status badge; a leading crit / high / med /
low / info renders a severity label. Items starting with "+ ", "- ", "~ " get
diff marks.
"""
import base64, datetime, hashlib, html, json, os, sys

SANS = 'system-ui,-apple-system,"Segoe UI","Noto Sans TC","Noto Sans CJK TC","PingFang TC",Roboto,sans-serif'
SERIF = '"Iowan Old Style","Palatino Linotype",Palatino,Georgia,"Noto Serif CJK TC","Songti TC",serif'
MONO = 'ui-monospace,SFMono-Regular,"JetBrains Mono",Menlo,Consolas,monospace'

# Paper palette (from answer-me-with-html). Contrast on --paper, light / dark:
# ink 16.4 / 13.9, ink2 7.6 / 7.8, badges 5.5-7.6 on their tints, chip text 6.3-10.0.
CSS = """
:root{color-scheme:light dark;--bg:#f5f2ea;--paper:#fdfbf6;--ink:#1f1c17;--ink2:#57514a;--line:#e5dfd3;--fline:#cbc3b4;
--fill:#f3eee4;--ok:#2e6a3b;--ok-bg:#e4efe5;--warn:#7f5300;--warn-bg:#f6ecd6;--err:#a3251b;--err-bg:#f7e3e0;
--chip:#1f1c17;--chip-fg:#fdfbf6;--focus:#8c2f1e}
@media (prefers-color-scheme:dark){:root{--bg:#15130f;--paper:#1c1a15;--ink:#ebe5d8;--ink2:#b5ad9e;--line:#2d2a24;
--fline:#4a443a;--fill:#242119;--ok:#8cc79a;--ok-bg:#1c3122;--warn:#e3b866;--warn-bg:#352a13;--err:#f0928a;--err-bg:#3a1d1a;
--chip:#ebe5d8;--chip-fg:#15130f;--focus:#e59a7d}}
*{box-sizing:border-box}html{background:var(--bg)}
body{margin:0;color:var(--ink);font:16px/1.6 """ + SANS + """;-webkit-font-smoothing:antialiased}
main{max-width:980px;margin:0 auto;padding:40px 24px 56px;display:flex;flex-direction:column;gap:20px}
header{display:flex;flex-direction:column;gap:16px}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
h1{margin:0;font:600 30px/1.25 """ + SERIF + """}
.meta{margin:6px 0 0;display:flex;flex-wrap:wrap;gap:2px 16px;font-size:14px;color:var(--ink2)}
.meta b{font:500 14px """ + MONO + """;color:var(--ink)}
.verdict{display:flex;gap:16px;align-items:flex-start;border:1px solid var(--fline);border-radius:2px;padding:20px 22px;background:var(--fill)}
.verdict.ok{background:var(--ok-bg);border-color:color-mix(in srgb,var(--ok) 35%,var(--fline))}
.verdict.warn{background:var(--warn-bg);border-color:color-mix(in srgb,var(--warn) 35%,var(--fline))}
.verdict.err{background:var(--err-bg);border-color:color-mix(in srgb,var(--err) 35%,var(--fline))}
.verdict .b{width:40px;height:40px;font-size:22px;margin:2px 0 0}
.verdict strong{display:block;font:600 15px """ + SANS + """}
.verdict.ok strong{color:var(--ok)}.verdict.warn strong{color:var(--warn)}.verdict.err strong{color:var(--err)}
.lead{margin:4px 0 0;font:22px/1.5 """ + SERIF + """}
section{background:var(--paper);border:1px solid var(--fline);border-radius:2px;overflow:hidden}
.ph{display:flex;align-items:center;gap:12px;padding:14px 18px}
section>.ph{border-bottom:1px solid var(--fline)}
.n{display:grid;place-items:center;flex:none;min-width:28px;height:28px;padding:0 6px;border-radius:2px;background:var(--chip);color:var(--chip-fg);
font:600 14px """ + MONO + """}
.n.err{background:var(--err)}.n.warn{background:var(--warn)}.n.ok{background:var(--ok)}
h2{margin:0;font:600 20px/1.3 """ + SERIF + """}
.note{flex:1;font-size:14px;color:var(--ink2)}
table{width:100%;font-size:15px;border-spacing:0}
th{text-align:left;font-size:13px;font-weight:600;color:var(--ink2);padding:9px 18px;border-bottom:1px solid var(--line);background:var(--fill)}
td{padding:12px 18px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:break-word}
tbody tr:last-child td{border-bottom:0}td:first-child{font-weight:500}
ul{margin:0;padding:0;list-style:none}
ul li{padding:11px 18px;border-bottom:1px solid var(--line)}ul li:last-child{border-bottom:0}
.mark{display:inline-block;width:18px;font:700 16px """ + MONO + """}.add .mark{color:var(--err)}.del .mark{color:var(--ok)}.same .mark{color:var(--warn)}
code{font:14px """ + MONO + """;background:var(--fill);border:1px solid var(--line);border-radius:2px;padding:2px 6px;
user-select:all;-webkit-user-select:all;cursor:copy;-webkit-box-decoration-break:clone;box-decoration-break:clone;line-height:1.9}
.b,.sev{display:inline-grid;place-items:center;height:24px;font:700 12px """ + MONO + """;border-radius:2px;
margin-right:3px;vertical-align:-5px;border:1px solid}
.b{min-width:24px;padding:0 4px;font-size:13px}.sev{padding:0 7px;letter-spacing:.04em}
.b.ok{color:var(--ok);background:var(--ok-bg);border-color:color-mix(in srgb,var(--ok) 40%,transparent)}
.b.no,.sev.crit{color:var(--err);background:var(--err-bg);border-color:color-mix(in srgb,var(--err) 40%,transparent)}
.b.warn,.sev.high,.sev.med{color:var(--warn);background:var(--warn-bg);border-color:color-mix(in srgb,var(--warn) 40%,transparent)}
.sev.low,.sev.info{color:var(--ink2);background:var(--fill);border-color:var(--fline)}
.fx{padding:18px}.fx+.fx{border-top:1px solid var(--line)}
.fx h3{margin:0;font-size:17px;font-weight:600}.fx h3 .sev{vertical-align:2px}.fx p{margin:6px 0 12px;max-width:46em}
.term{position:relative;background:var(--fill);border:1px solid var(--line);border-radius:2px}
.term pre{margin:0;padding:14px 96px 14px 16px;font:14px/1.75 """ + MONO + """;white-space:pre;overflow-x:auto;
user-select:all;-webkit-user-select:all}
.term .copy{position:absolute;top:8px;right:8px}
.copy{flex:none;font:600 13px """ + SANS + """;color:var(--chip-fg);background:var(--chip);border:0;border-radius:2px;padding:6px 12px;
cursor:pointer;min-height:32px}
.copy:hover{opacity:.88}
@media (max-width:640px){main{padding:24px 14px 40px}h1{font-size:24px}.lead{font-size:19px}.ph{flex-wrap:wrap}
.note{flex-basis:100%;order:3}
table,thead,tbody,tr,td{display:block}thead{display:none}tr{border-bottom:1px solid var(--line);padding:6px 0}tbody tr:last-child{border-bottom:0}
td{border:0;padding:4px 18px}td[data-col]:not(:first-child):before{content:attr(data-col);display:block;font-size:13px;color:var(--ink2)}
.term pre{padding-right:16px;padding-top:52px}}
@media print{@page{size:13.333in 7.5in;margin:.35in}html,body{background:#fff}main{max-width:none;padding:0;display:block;zoom:1.35}
header{break-after:page}section{break-before:page;border:0}code{cursor:auto}.copy{display:none}.term pre{padding:14px 16px;white-space:pre-wrap}}
"""
# The only script on the page: copies a command block. The CSP allows it by hash, so injected scripts cannot run.
SCRIPT = ("document.addEventListener('click',function(ev){var b=ev.target.closest('[data-copy]');if(!b)return;"
          "var el=document.getElementById(b.dataset.copy),t=el.textContent;"
          "function done(){b.textContent=b.dataset.done;setTimeout(function(){b.textContent=b.dataset.label},1500)}"
          "function sel(){var r=document.createRange();r.selectNodeContents(el);var x=getSelection();x.removeAllRanges();x.addRange(r);"
          "try{document.execCommand('copy');done()}catch(e){}}"
          "if(navigator.clipboard){navigator.clipboard.writeText(t).then(done,sel)}else{sel()}});")
SCRIPT_HASH = "sha256-" + base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
TONES = {"clean": "ok", "suspicious": "warn", "compromised": "err"}
BADGE = {"ok": "✓", "no": "✗", "warn": "!"}
SEV = ("crit", "high", "med", "low", "info")
TONE_BADGE = {"ok": "ok", "warn": "warn", "err": "no"}
MARKS = {"+ ": ("add", "+"), "- ": ("del", "−"), "~ ": ("same", "~")}
WORDS = {  # per language: clean, suspicious, compromised, copy, copied, copy all
    "zh-Hant": ("乾淨", "可疑", "已入侵", "複製", "已複製", "複製全部指令"),
    "zh": ("干净", "可疑", "已入侵", "复制", "已复制", "复制全部指令"),
    "en": ("Clean", "Suspicious", "Compromised", "Copy", "Copied", "Copy all commands"),
}
e = lambda s: html.escape(str(s), quote=True)


def words(lang):
    lang = str(lang)
    if lang in ("zh-TW", "zh-HK") or lang.startswith("zh-Hant"):
        return WORDS["zh-Hant"]
    return WORDS["zh" if lang.startswith("zh") else "en"]


def lead(s):
    """Split a leading status or severity keyword off s; return (label html, rest)."""
    s = str(s)
    head, _, rest = s.partition(" ")
    if head in BADGE:
        return f'<span class="b {head}" aria-label="{head}">{BADGE[head]}</span>', rest
    if head in SEV:
        return f'<span class="sev {head}">{head.upper()}</span>', rest
    return "", s


def text(s):
    """Escape s; `backtick` spans anywhere become <code>. Unbalanced backticks stay literal."""
    parts = str(s).split("`")
    if len(parts) % 2 == 0:
        return e(s)
    return "".join(f"<code>{e(p)}</code>" if i % 2 else e(p) for i, p in enumerate(parts) if p or i % 2)


def cell(v):
    tag, rest = lead(v)
    return f"{tag} {text(rest)}" if tag else text(rest)  # real space, so copied text reads "LOW LLMNR", not "LOWLLMNR"


def item(s):
    s = str(s)
    cls, mark = MARKS.get(s[:2], ("", ""))
    if cls:
        return f'<li class="{cls}"><span class="mark" aria-hidden="true">{mark}</span>{cell(s[2:])}</li>'
    return f"<li>{cell(s)}</li>"


def table(cols, rows):
    th = "".join(f'<th scope="col">{e(c)}</th>' for c in cols)
    label = lambda j: f' data-col="{e(cols[j])}"' if j < len(cols) else ""
    tr = "".join("<tr>" + "".join(f"<td{label(j)}>{cell(c)}</td>" for j, c in enumerate(r)) + "</tr>" for r in rows)
    return f"<table><thead><tr>{th}</tr></thead><tbody>{tr}</tbody></table>"


def count(p):
    return len(p.get("rows", [])) + len(p.get("items", [])) + len(p.get("cards", []))


def lines(xs):
    return [str(x) for x in xs or [] if str(x).strip()]


def copy_button(tid, label, w):
    return (f'<button type="button" class="copy" data-copy="{tid}" data-label="{e(label)}" data-done="{e(w[4])}" '
            f'aria-live="polite">{e(label)}</button>')


def term(tid, cmd, w):
    """A terminal-style block: one command per line, with a Copy button."""
    return f'<div class="term"><pre id="{tid}">{e(chr(10).join(cmd))}</pre>{copy_button(tid, w[3], w)}</div>'


def card(c, tid, w):
    cmd = lines(c.get("cmd"))
    body = f'<p>{text(c["body"])}</p>' if c.get("body") else ""
    return f'<div class="fx"><h3>{cell(c.get("title", ""))}</h3>{body}{term(tid, cmd, w) if cmd else ""}</div>'


def section(i, p, w):
    tone = p.get("tone", "") if p.get("tone") in TONE_BADGE else ""
    body = table(p.get("cols", []), p["rows"]) if p.get("rows") else ""
    body += "<ul>" + "".join(item(s) for s in p["items"]) + "</ul>" if p.get("items") else ""
    body += "".join(card(c, f"c{i}-{k}", w) for k, c in enumerate(p.get("cards", [])))
    note = f'<span class="note">{e(p["note"])}</span>' if p.get("note") else '<span class="note"></span>'
    cp = lines(p.get("copy"))
    btn = copy_button(f"all{i}", w[5], w) + f'<pre id="all{i}" hidden>{e(chr(10).join(cp))}</pre>' if cp else ""
    head = (f'<span class="n {tone}" aria-hidden="true">{count(p)}</span>'
            f'<h2 id="h{i}">{e(p.get("title", ""))}</h2>{note}{btn}')
    return f'<section aria-labelledby="h{i}"><div class="ph">{head}</div>{body}</section>'


def render(d):
    title, panels, lang = d.get("title", "soc-me"), d.get("panels", []), d.get("lang", "en")
    w = words(lang)
    verdict = d.get("verdict", "")
    tone = TONES.get(verdict, "")
    vlabel = dict(zip(("clean", "suspicious", "compromised"), w[:3])).get(verdict, verdict)
    meta = dict(d.get("meta", {}))
    when = meta.pop("time", "")
    facts = ([f"<span><b>{e(when)}</b></span>"] if when else []) + [f"<span>{e(k)} <b>{e(v)}</b></span>" for k, v in meta.items()]
    k = TONE_BADGE.get(tone)
    mark = f'<span class="b {k}" aria-hidden="true">{BADGE[k]}</span>' if k else ""
    top = (f'<div><h1>{e(title)}</h1>' + (f'<p class="meta">{"".join(facts)}</p>' if facts else "") + '</div>'
           f'<div class="verdict {tone}">{mark}<div><strong>{e(vlabel)}</strong><p class="lead">{text(d.get("summary", ""))}</p></div></div>')
    secs = "".join(section(i, p, w) for i, p in enumerate(panels))
    script = f"<script>{SCRIPT}</script>" if 'class="copy"' in secs else ""
    return (f'<!doctype html><html lang="{e(lang)}"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; script-src \'{SCRIPT_HASH}\'">'
            f'<title>{e(title)}</title><style>{CSS}</style><noscript><style>.copy{{display:none}}</style></noscript></head>'
            f'<body><main><header>{top}</header>{secs}</main>{script}</body></html>')


if __name__ == "__main__":
    out = sys.argv[2] if sys.argv[1:2] == ["-o"] else None
    if not out:
        if os.name == "nt":
            state = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        else:
            state = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
        os.makedirs(os.path.join(state, "soc-me"), exist_ok=True)
        out = os.path.join(state, "soc-me", datetime.datetime.now().strftime("report-%Y%m%d-%H%M%S.html"))
    with open(out, "w", encoding="utf-8") as f:
        f.write(render(json.load(sys.stdin)))
    print(out)

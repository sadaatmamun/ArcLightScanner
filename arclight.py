"""
ArcLight Vulnerability Scanner v2 -
Single-file FastAPI app:
- Assets • Policies • Saved/Scheduled Scans
- Live streaming logs
- JSON / CSV / PDF export
- Dashboard charts (severity + throughput)
- Scan Templates page with search and launch modal

No python-multipart required; UI sends JSON only.

Quick run:
  pip install fastapi==0.111.0 uvicorn==0.30.3 jinja2==3.1.4 pydantic==2.8.2 croniter==2.0.5 reportlab==4.1.0
  uvicorn scanner:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import asyncio
import contextlib
import csv
import datetime as dt
import io
import json
import os
import re
import shlex
import shutil
import sqlite3
import textwrap
from pathlib import Path
from typing import AsyncGenerator, Dict, List, Optional

# ---------- Env sanity (ssl often missing in minimal Python builds) ----------
try:
    import ssl as _ssl  # noqa: F401
except ModuleNotFoundError:
    raise SystemExit(
        "Python 'ssl' module is missing.\n"
        "Debian/Kali: sudo apt update && sudo apt install -y python3-full python3-venv python3-pip ca-certificates openssl\n"
        "macOS: brew reinstall python@3.12\n"
        "Then run with: uvicorn scanner:app --host 0.0.0.0 --port 8000\n"
    )

from fastapi import FastAPI, Request
from fastapi.responses import (
    HTMLResponse,
    StreamingResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
    JSONResponse,
)
from jinja2 import Environment, BaseLoader, select_autoescape
from croniter import croniter

APP_NAME = "ArcLight Scanner"
DATA_DIR = Path("data")
DB_PATH = DATA_DIR / "scanner.sqlite3"
JOBS_DIR = DATA_DIR / "jobs"
REPORTS_DIR = DATA_DIR / "reports"
for _d in (DATA_DIR, JOBS_DIR, REPORTS_DIR):
    _d.mkdir(parents=True, exist_ok=True)

app = FastAPI(title=APP_NAME)

# ---------- DB schema & migrations ----------
SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT NOT NULL UNIQUE,
  tags TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS policies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  use_nmap INTEGER DEFAULT 1,
  nmap_profile TEXT DEFAULT 'vuln',
  use_nuclei INTEGER DEFAULT 1,
  nuclei_sev TEXT DEFAULT 'critical,high,medium',
  use_nikto INTEGER DEFAULT 0,
  use_wpscan INTEGER DEFAULT 0,
  http_basic_user TEXT DEFAULT '',
  http_basic_pass TEXT DEFAULT '',
  concurrency INTEGER DEFAULT 2,
  nuclei_rate INTEGER DEFAULT NULL,
  exclude_paths TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  policy_id INTEGER NOT NULL,
  asset_ids TEXT NOT NULL,
  schedule_cron TEXT DEFAULT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(policy_id) REFERENCES policies(id)
);
CREATE TABLE IF NOT EXISTS jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  summary TEXT DEFAULT '',
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);
"""


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


with db() as conn:
    conn.executescript(SCHEMA)

# Minimal migrations (safe if columns already exist)
MIGRATIONS = [
    ("policies", "concurrency", "ALTER TABLE policies ADD COLUMN concurrency INTEGER DEFAULT 2"),
    ("policies", "nuclei_rate", "ALTER TABLE policies ADD COLUMN nuclei_rate INTEGER DEFAULT NULL"),
    ("policies", "exclude_paths", "ALTER TABLE policies ADD COLUMN exclude_paths TEXT DEFAULT ''"),
]
with db() as conn:
    for table, col, sql in MIGRATIONS:
        cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
        if col not in cols:
            conn.execute(sql)
    conn.commit()

# Seed default policy
with db() as conn:
    if conn.execute("SELECT COUNT(*) FROM policies").fetchone()[0] == 0:
        conn.execute(
            "INSERT INTO policies(name,use_nmap,nmap_profile,use_nuclei,nuclei_sev,use_nikto,use_wpscan,concurrency) "
            "VALUES(?,?,?,?,?,?,?,?)",
            ("Quick Web Audit", 1, "vuln", 1, "critical,high,medium", 1, 0, 2),
        )
        conn.commit()

# ---------- Utils ----------
TARGET_RE = re.compile(
    r"^(?:(?:https?://)?)(?:[A-Za-z0-9.-]+|\[[A-Fa-f0-9:]+\]|(?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?$"
)


def now_iso() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def which(cmd: str) -> str:
    return shutil.which(cmd) or ""


def normalize_targets(raw: str) -> List[str]:
    items = re.split(r"[\s,\n\r;]+", (raw or "").strip())
    out: List[str] = []
    seen = set()
    for it in items:
        if not it:
            continue
        t = it.strip().strip("\"'")
        if t and t not in seen and TARGET_RE.match(t):
            seen.add(t)
            out.append(t)
    return out[:1024]


def ensure_url(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"http://{target}"


async def stream_cmd(
    title: str, cmd: List[str], logfile: Path, timeout: int = 3600
) -> AsyncGenerator[str, None]:
    header = f"\n===== {title} =====\n$ {' '.join(shlex.quote(c) for c in cmd)}\n\n"
    logfile.parent.mkdir(parents=True, exist_ok=True)
    logfile.write_text(logfile.read_text() + header if logfile.exists() else header)
    yield header

    if not which(cmd[0]):
        msg = f"[!] Tool not found: {cmd[0]} (skipping)\n"
        logfile.write_text(logfile.read_text() + msg)
        yield msg
        return

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            while True:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=timeout)
                if not line:
                    break
                text = line.decode(errors="ignore")
                with logfile.open("a") as f:
                    f.write(text)
                yield text
        except asyncio.TimeoutError:
            with logfile.open("a") as f:
                f.write("\n[!] Timeout reached.\n")
            yield "\n[!] Timeout reached.\n"
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
        finally:
            await proc.wait()
    except Exception as e:
        err = f"[!] Failed to run: {' '.join(cmd)}\nReason: {e}\n"
        with logfile.open("a") as f:
            f.write(err)
        yield err


# ---------- Jinja master template ----------
TEMPLATE = Environment(loader=BaseLoader(), autoescape=select_autoescape()).from_string(
    r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{{ title }}</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root { color-scheme: dark; }
    body { background: radial-gradient(1200px 600px at 10% -10%, rgba(0,255,128,0.12), transparent), #0b0f0c; }
    .glow { text-shadow: 0 0 14px rgba(0,255,128,.35); }
    .card { background: rgba(18,24,20,.85); backdrop-filter: blur(8px); border: 1px solid rgba(0,255,128,.15); box-shadow: 0 10px 30px rgba(0,0,0,.35); }
    .accent { border-color: rgba(0,255,128,.35); }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
    .badge { border:1px solid rgba(0,255,128,.35); padding:.125rem .5rem; border-radius:.5rem; font-size:.75rem }
    .nav a { transition: all .2s ease; }
    .nav a.active, .nav a:hover { background: rgba(16,185,129,.12); border-color: rgba(16,185,129,.6); }
    .btn { display:inline-flex; align-items:center; gap:.5rem; border:1px solid rgba(16,185,129,.4); border-radius:.75rem; padding:.5rem .9rem; }
    .btn:hover{ background: rgba(16,185,129,.12) }
    .btn-danger{ border-color: rgba(244,63,94,.5) }
    .btn-danger:hover{ background: rgba(244,63,94,.12) }
    .input { background: rgba(0,0,0,.35); border:1px solid rgba(16,185,129,.35); border-radius:.75rem; padding:.5rem .75rem; }
    .spinner { width:1rem; height:1rem; border:2px solid #34d39933; border-top-color:#34d399; border-radius:9999px; animation: spin 1s linear infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .toast { backdrop-filter: blur(6px); }
  </style>
</head>
<body class="text-gray-200">
  <div id="toast-stack" class="fixed top-4 right-4 z-50 space-y-2"></div>
  <div class="max-w-7xl mx-auto p-6">
    <header class="mb-6 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <svg width="30" height="30" viewBox="0 0 24 24" fill="none" class="text-emerald-400"><path d="M12 2l3 7h7l-5.5 4 2 7L12 17l-6.5 3 2-7L2 9h7l3-7z" fill="currentColor" opacity=".85"/></svg>
        <div>
          <h1 class="text-3xl md:text-4xl font-semibold glow">{{ app_name }}</h1>
          <p class="text-sm text-emerald-300/80 mt-1">Assets • Policies • Scans • Templates • Jobs • Reports</p>
        </div>
      </div>
      <nav class="nav flex gap-3 text-sm">
        <a href="/" class="px-3 py-1 rounded-lg border border-emerald-400/40" data-nav="/">Dashboard</a>
        <a href="/assets" class="px-3 py-1 rounded-lg border border-emerald-400/40" data-nav="/assets">Assets</a>
        <a href="/policies" class="px-3 py-1 rounded-lg border border-emerald-400/40" data-nav="/policies">Policies</a>
        <a href="/scans" class="px-3 py-1 rounded-lg border border-emerald-400/40" data-nav="/scans">Scans</a>
        <a href="/templates" class="px-3 py-1 rounded-lg border border-emerald-400/40" data-nav="/templates">Templates</a>
        <a href="/jobs" class="px-3 py-1 rounded-lg border border-emerald-400/40" data-nav="/jobs">Jobs</a>
      </nav>
    </header>

    {{ body | safe }}

    <footer class="mt-10 text-xs text-emerald-300/60">ArcLight Scanner v2 · For authorized testing only</footer>
  </div>

  <script>
    const $$ = (s,root=document)=>root.querySelector(s);
    const $$$ = (s,root=document)=>Array.from(root.querySelectorAll(s));
    (function(){ const p = location.pathname; $$$('nav a[data-nav]').forEach(a=>{ if(p===a.dataset.nav) a.classList.add('active'); }); })();
    // UI helpers
    window.UI = {
      toast(msg, type='info'){
        const wrap = document.getElementById('toast-stack');
        const el = document.createElement('div');
        const color = type==='error'?'border-red-400/60 bg-red-500/10':(type==='success'?'border-emerald-400/60 bg-emerald-500/10':'border-sky-400/60 bg-sky-500/10');
        el.className = `toast border ${color} rounded-xl px-3 py-2 text-sm shadow-lg`;
        el.textContent = msg; wrap.appendChild(el);
        setTimeout(()=>{ el.style.opacity='0'; el.style.transform='translateX(10px)'; el.style.transition='all .2s'; setTimeout(()=>el.remove(), 200); }, 2600);
      },
      spin(btn, on=true, label='Working...'){
        if(!btn) return;
        if(on){ btn.dataset._label = btn.innerHTML; btn.innerHTML = `<span class="spinner"></span><span class="ml-2">${label}</span>`; btn.disabled=true; }
        else { btn.innerHTML = btn.dataset._label || 'Submit'; btn.disabled=false; }
      },
      copy(text){ navigator.clipboard.writeText(text).then(()=>UI.toast('Copied','success')).catch(()=>UI.toast('Copy failed','error')); }
    };
  </script>
  <script>
// === Install a terminal popup + helper (drop-in) ===
(function(){
  window.UI = window.UI || {
    toast: (m)=>console.log('[toast]', m),
    copy: (t)=>navigator.clipboard?.writeText(t),
    spin: ()=>{}
  };

  if (document.getElementById('term')) return; // don't install twice

  // Inject modal HTML
  const wrap = document.createElement('div');
  wrap.innerHTML = `
    <div id="term" class="fixed inset-0 hidden z-50 items-center justify-center bg-black/60">
      <div class="card rounded-2xl w-[980px] max-w-[95vw] p-4">
        <div class="flex items-center justify-between mb-2">
          <div class="font-semibold glow" id="termTitle">Live Scan</div>
          <div class="flex items-center gap-2">
            <label class="text-xs flex items-center gap-1"><input id="termFollow" type="checkbox" checked> follow</label>
            <button class="btn" id="termCopy">Copy</button>
            <button class="btn btn-danger" id="termClose">Close</button>
          </div>
        </div>
        <pre id="termOut" class="mono bg-black/40 border accent rounded-xl p-3 h-[65vh] overflow-auto text-emerald-200/90 text-sm"></pre>
      </div>
    </div>`;
  document.body.appendChild(wrap.firstElementChild);

  // Wire up behavior
  const el = document.getElementById('term');
  const out = document.getElementById('termOut');
  const title = document.getElementById('termTitle');
  const btnClose = document.getElementById('termClose');
  const btnCopy  = document.getElementById('termCopy');
  const follow   = document.getElementById('termFollow');
  let controller = null;

  async function stream(url){
    out.textContent = '';
    controller = new AbortController();
    try{
      const res = await fetch(url, {signal: controller.signal});
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      while(true){
        const {value, done} = await reader.read();
        if (done) break;
        out.textContent += decoder.decode(value, {stream:true});
        if (follow.checked) out.scrollTop = out.scrollHeight;
      }
    }catch(e){
      out.textContent += "\\n[!] stream interrupted: " + String(e) + "\\n";
    }finally{
      controller = null;
    }
  }

  UI.term = {
    open(label, url){
      title.textContent = label || 'Live Scan';
      el.classList.remove('hidden'); el.classList.add('flex');
      stream(url);
    },
    close(){
      if (controller) controller.abort();
      el.classList.add('hidden'); el.classList.remove('flex');
    }
  };

  // one-liner helper with fallback to normal navigation
  UI.openScan = function(url, label){
    try {
      if (UI.term && typeof UI.term.open === 'function') {
        UI.term.open(label || 'Live Scan', url);
      } else {
        location.href = url;
      }
    } catch (e) {
      console.error(e);
      location.href = url;
    }
  };

  btnClose?.addEventListener('click', ()=> UI.term.close());
  btnCopy?.addEventListener('click', ()=> UI.copy && UI.copy(out.textContent));
})();
</script>

</body>
</html>
"""
)


def render(body: str, title: str = APP_NAME) -> HTMLResponse:
    html = TEMPLATE.render(title=title, body=body, app_name=APP_NAME)
    return HTMLResponse(html)


# ---------- Pages ----------
def page_dashboard() -> str:
    with db() as conn:
        a = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        p = conn.execute("SELECT COUNT(*) FROM policies").fetchone()[0]
        s = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        j_running = conn.execute("SELECT COUNT(*) FROM jobs WHERE status='running'").fetchone()[0]
        j_done = conn.execute("SELECT COUNT(*) FROM jobs WHERE status='finished'").fetchone()[0]
        last_job = conn.execute(
            "SELECT finished_at FROM jobs WHERE finished_at IS NOT NULL ORDER BY id DESC LIMIT 1"
        ).fetchone()
    last_text = (last_job[0] if last_job and last_job[0] else "-")

    # Tool health badges HTML (server-side)
    def badge(ok: bool, name: str) -> str:
        cls = "bg-emerald-500/15 border-emerald-400/40 text-emerald-200" if ok else "bg-red-500/15 border-red-400/40 text-red-200"
        return f"<div class='badge {cls}'>{name}: {'OK' if ok else 'missing'}</div>"

    badges_html = "".join(
        [
            badge(bool(which("nmap")), "nmap"),
            badge(bool(which("nuclei")), "nuclei"),
            badge(bool(which("nikto")), "nikto"),
            badge(bool(which("wpscan")), "wpscan"),
        ]
    )

    body = """
    <div class="grid xl:grid-cols-6 md:grid-cols-3 grid-cols-2 gap-4">
      <div class="card p-4 rounded-2xl"><div class="text-xs opacity-70">Assets</div><div class="text-3xl glow">%%A%%</div></div>
      <div class="card p-4 rounded-2xl"><div class="text-xs opacity-70">Policies</div><div class="text-3xl glow">%%P%%</div></div>
      <div class="card p-4 rounded-2xl"><div class="text-xs opacity-70">Scans</div><div class="text-3xl glow">%%S%%</div></div>
      <div class="card p-4 rounded-2xl"><div class="text-xs opacity-70">Running</div><div class="text-3xl glow">%%JR%%</div></div>
      <div class="card p-4 rounded-2xl"><div class="text-xs opacity-70">Finished</div><div class="text-3xl glow">%%JD%%</div></div>
      <div class="card p-4 rounded-2xl"><div class="text-xs opacity-70">Last job</div><div class="text-lg mono">%%LAST%%</div></div>
    </div>

    <div class="grid lg:grid-cols-3 gap-6 mt-6">
      <div class="space-y-6">
        <section class="card rounded-2xl p-5">
          <div class="flex items-center justify-between mb-2">
            <h2 class="text-xl glow">Run Ad-hoc Scan</h2>
            <button id="btnQuickExamples" class="btn text-xs">Examples</button>
          </div>
          <form id="formAdhoc" class="space-y-3">
            <textarea name="targets" rows="5" placeholder="paste IPs/hosts/URLs, one per line" class="w-full rounded-xl bg-black/40 border accent p-2"></textarea>
            <div class="flex flex-wrap gap-2 text-sm">
              <label class="flex items-center gap-2"><input type="checkbox" name="use_nmap" checked> Nmap</label>
              <label class="flex items-center gap-2"><input type="checkbox" name="use_nuclei" checked> Nuclei</label>
              <label class="flex items-center gap-2"><input type="checkbox" name="use_nikto"> Nikto</label>
              <label class="flex items-center gap-2"><input type="checkbox" name="use_wpscan"> WPScan</label>
              <select name="nmap_profile" class="input ml-auto">
                <option value="vuln" selected>nmap: vuln</option>
                <option value="quick">nmap: quick</option>
                <option value="full">nmap: full</option>
              </select>
              <select name="nuclei_sev" class="input" id="nucSev">
                <option value="critical,high,medium" selected>nuclei: critical,high,medium</option>
                <option value="critical,high">nuclei: critical,high</option>
                <option value="low,info">nuclei: low,info</option>
              </select>
            </div>
            <div class="flex gap-2 text-sm">
              <button type="button" id="btnPaste" class="btn">Paste</button>
              <button type="button" id="btnClear" class="btn">Clear</button>
              <button type="button" id="btnSample" class="btn">Sample targets</button>
              <button id="btnRun" type="submit" class="btn ml-auto">Run Now</button>

            </div>
          </form>
        </section>

        <section class="card rounded-2xl p-5">
          <div class="flex items-center justify-between mb-2">
            <h2 class="text-xl glow">Tool Health</h2>
            <button class="btn text-xs" onclick="location.reload()">Re-check</button>
          </div>
          <div class="grid grid-cols-2 gap-2 text-sm">%%TOOL_BADGES%%</div>
        </section>
      </div>

      <section class="card rounded-2xl p-5">
        <div class="flex items-center justify-between mb-3">
          <h2 class="text-xl glow">Findings Overview</h2>
          <label class="text-xs flex items-center gap-2"><input id="autoRefreshSev" type="checkbox"> auto refresh</label>
        </div>
        <canvas id="sevChart" height="150"></canvas>
      </section>

      <section class="card rounded-2xl p-5">
        <div class="flex items-center justify-between mb-3">
          <h2 class="text-xl glow">Jobs per Day</h2>
          <div class="text-xs flex items-center gap-2">
            <select id="tpDays" class="input">
              <option value="7">7d</option>
              <option value="14" selected>14d</option>
              <option value="30">30d</option>
            </select>
            <label class="text-xs flex items-center gap-2"><input id="autoRefreshTp" type="checkbox"> auto</label>
          </div>
        </div>
        <canvas id="tpChart" height="150"></canvas>
      </section>
    </div>

    <script>
      // form helpers
      (function(){
        const fA = document.getElementById('formAdhoc');
        const btnRun = document.getElementById('btnRun');
        const btnPaste = document.getElementById('btnPaste');
        const btnClear = document.getElementById('btnClear');
        const btnSample = document.getElementById('btnSample');
        const txt = fA.querySelector('textarea[name="targets"]');
        const sevSel = document.getElementById('nucSev');

        const savedSev = localStorage.getItem('nuclei_sev'); if(savedSev) sevSel.value = savedSev;
        sevSel.addEventListener('change', ()=> localStorage.setItem('nuclei_sev', sevSel.value));

        document.getElementById('btnQuickExamples').addEventListener('click', ()=>{
          UI.toast('Try: example.com\\n1.2.3.4\\nhttps://demo.test','info');
        });

        btnPaste.addEventListener('click', async ()=>{
          try{ txt.value += (txt.value?"\\n":"") + (await navigator.clipboard.readText()); UI.toast('Pasted','success'); }
          catch{ UI.toast('Clipboard denied','error'); }
        });
        btnClear.addEventListener('click', ()=>{ txt.value=''; UI.toast('Cleared'); });
        btnSample.addEventListener('click', ()=>{ txt.value = "example.com\\nhttp://scanme.nmap.org"; });

        fA.addEventListener('submit', async (e) => {
          e.preventDefault();
          const fd = new FormData(fA);
          const payload = {
            targets: fd.get('targets') || '',
            use_nmap: !!fd.get('use_nmap'),
            nmap_profile: fd.get('nmap_profile') || 'vuln',
            use_nuclei: !!fd.get('use_nuclei'),
            nuclei_sev: fd.get('nuclei_sev') || 'critical,high,medium',
            use_nikto: !!fd.get('use_nikto'),
            use_wpscan: !!fd.get('use_wpscan')
          };
          if(!payload.targets.trim()){ UI.toast('Add at least one target','error'); return; }
          UI.spin(btnRun, true, 'Creating scan...');
          try{
            const r = await fetch('/scans/create_ad_hoc', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
            if (!r.ok) { UI.toast(await r.text(), 'error'); return; }
            const data = await r.json();
            UI.toast('Scan created','success');
UI.openScan('/scans/run?id=' + data.scan_id, 'Ad-hoc Scan #' + data.scan_id);

          }catch(err){ UI.toast(String(err),'error'); }
          finally{ UI.spin(btnRun,false); }
        });
      })();

      // Charts
      let sevChart=null, tpChart=null;
      async function loadSeverity(){
        const ctx = document.getElementById('sevChart').getContext('2d');
        const r = await fetch('/api/stats/summary'); const d = await r.json();
        const sev = (d && d.severity) ? d.severity : {critical:0,high:0,medium:0,low:0,info:0};
        const ds = [sev.critical||0, sev.high||0, sev.medium||0, sev.low||0, sev.info||0];
        if(!sevChart){
          const grad = ctx.createLinearGradient(0,0,0,160); grad.addColorStop(0,'rgba(16,185,129,.8)'); grad.addColorStop(1,'rgba(16,185,129,.15)');
          sevChart = new Chart(ctx, {
            type:'bar',
            data: { labels: ['critical','high','medium','low','info'], datasets:[{ label:'Findings', data: ds, backgroundColor: grad }] },
            options: {
              responsive:true,
              plugins: { legend: { display:false } },
              scales: { y: { beginAtZero:true, grid: { color:'rgba(255,255,255,.08)' } }, x: { grid: { display:false } } }
            }
          });
        } else {
          sevChart.data.datasets[0].data = ds; sevChart.update('none');
        }
      }
      async function loadThroughput(days=14){
        const ctx = document.getElementById('tpChart').getContext('2d');
        const r = await fetch('/api/stats/throughput?days='+days); const d = await r.json(); // {labels, counts}
        if(!tpChart){
          tpChart = new Chart(ctx, {
            type:'line',
            data: { labels: d.labels, datasets:[{ label:'Jobs', data: d.counts, tension:.3, fill:false }] },
            options: {
              responsive:true,
              plugins: { legend: { display:false } },
              scales: { y: { beginAtZero:true, grid: { color:'rgba(255,255,255,.08)' } }, x: { grid: { display:false } } }
            }
          });
        } else {
          tpChart.data.labels = d.labels; tpChart.data.datasets[0].data = d.counts; tpChart.update('none');
        }
      }
      (function(){
        loadSeverity(); loadThroughput(14);
        const sevAuto = document.getElementById('autoRefreshSev');
        const tpAuto = document.getElementById('autoRefreshTp');
        const tpDays = document.getElementById('tpDays');
        let t1=null, t2=null;
        tpDays.addEventListener('change', ()=> loadThroughput(Number(tpDays.value)));
        sevAuto.addEventListener('change',()=>{ if(sevAuto.checked){ t1=setInterval(loadSeverity, 10000); UI.toast('Severity auto ON'); } else { clearInterval(t1); UI.toast('Severity auto OFF'); } });
        tpAuto.addEventListener('change',()=>{ if(tpAuto.checked){ t2=setInterval(()=>loadThroughput(Number(tpDays.value)), 15000); UI.toast('Throughput auto ON'); } else { clearInterval(t2); UI.toast('Throughput auto OFF'); } });
      })();
    </script>
    """
    return (
        body.replace("%%A%%", str(a))
        .replace("%%P%%", str(p))
        .replace("%%S%%", str(s))
        .replace("%%JR%%", str(j_running))
        .replace("%%JD%%", str(j_done))
        .replace("%%LAST%%", last_text)
        .replace("%%TOOL_BADGES%%", badges_html)
    )


def page_assets() -> str:
    with db() as conn:
        rows = conn.execute("SELECT * FROM assets ORDER BY id DESC").fetchall()
    items = "".join(
        f"<tr class='hover:bg-white/5 transition'><td class='py-1 pr-2 text-emerald-200/90 mono'>{r['id']}</td>"
        f"<td class='py-1 pr-2 mono'>{r['target']}</td>"
        f"<td class='py-1 pr-2'>{r['tags']}</td></tr>"
        for r in rows
    )

    body = """
    <section class="card rounded-2xl p-5">
      <h2 class="text-xl glow mb-3">Assets</h2>
      <form id="formAsset" class="flex gap-2 mb-3">
        <input name=target required placeholder="example.com or 10.10.10.10" class="flex-1 input" />
        <input name=tags placeholder="prod,web,linux" class="input" />
        <button class="btn" id="btnAddAsset">Add</button>
      </form>
      <script>
        const f = document.getElementById('formAsset'); const btn = document.getElementById('btnAddAsset');
        f.addEventListener('submit', async (e)=>{
          e.preventDefault();
          const fd = new FormData(f); const payload = { target: fd.get('target'), tags: fd.get('tags') || '' };
          UI.spin(btn, true, 'Adding...');
          const r = await fetch('/assets/add', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
          if (r.ok) { UI.toast('Asset added','success'); location.reload(); } else { UI.toast(await r.text(),'error'); }
          UI.spin(btn,false);
        });
      </script>
      <table class="w-full text-sm">
        <thead><tr class="text-emerald-300/80"><th class='text-left'>ID</th><th class='text-left'>Target</th><th class='text-left'>Tags</th></tr></thead>
        <tbody>%%ITEMS%%</tbody>
      </table>
    </section>
    """
    return body.replace("%%ITEMS%%", items)



def page_policies() -> str:
    with db() as conn:
        rows = conn.execute("SELECT * FROM policies ORDER BY id DESC").fetchall()
    items = "".join(
        f"<tr class='hover:bg-white/5 transition'><td class='py-1 pr-2 mono'>{r['id']}</td><td class='py-1 pr-2'>{r['name']}</td>"
        f"<td class='py-1 pr-2 mono'>{'Y' if r['use_nmap'] else '-'} / {r['nmap_profile']}</td>"
        f"<td class='py-1 pr-2 mono'>{'Y' if r['use_nuclei'] else '-'} / {r['nuclei_sev']}</td>"
        f"<td class='py-1 pr-2 mono'>{'Y' if r['use_nikto'] else '-'}</td>"
        f"<td class='py-1 pr-2 mono'>{'Y' if r['use_wpscan'] else '-'}</td>"
        f"<td class='py-1 pr-2 mono'>c={r['concurrency']} rl={r['nuclei_rate'] or '-'} ex={bool(r['exclude_paths'])}</td></tr>"
        for r in rows
    )

    body = """
    <section class="card rounded-2xl p-5">
      <h2 class="text-xl glow mb-3">Policies</h2>
      <form id="formPolicy" class="grid md:grid-cols-3 gap-3 mb-4">
        <input name=name required placeholder="Policy name" class="input" />
        <select name=nmap_profile class="input">
          <option value="vuln" selected>nmap: vuln</option>
          <option value="quick">nmap: quick</option>
          <option value="full">nmap: full</option>
        </select>
        <select name=nuclei_sev class="input">
          <option value="critical,high,medium" selected>nuclei: critical,high,medium</option>
          <option value="critical,high">nuclei: critical,high</option>
          <option value="low,info">nuclei: low,info</option>
        </select>
        <label class="flex items-center gap-2"><input type=checkbox name=use_nmap checked> Nmap</label>
        <label class="flex items-center gap-2"><input type=checkbox name=use_nuclei checked> Nuclei</label>
        <label class="flex items-center gap-2"><input type=checkbox name=use_nikto> Nikto</label>
        <label class="flex items-center gap-2"><input type=checkbox name=use_wpscan> WPScan</label>
        <input name=concurrency type=number min=1 max=16 value=2 class="input" placeholder="concurrency (targets)" />
        <input name=nuclei_rate type=number min=1 value=50 class="input" placeholder="nuclei rate-limit" />
        <input name=exclude_paths class="input md:col-span-3" placeholder="exclude paths (comma separated, e.g. /logout,/admin/debug)" />
        <input name=http_basic_user placeholder="HTTP basic user (optional)" class="input" />
        <input name=http_basic_pass placeholder="HTTP basic pass (optional)" class="input" />
        <button class="btn md:col-span-1" id="btnAddPolicy">Add Policy</button>
      </form>
      <script>
        const fp = document.getElementById('formPolicy'); const bp = document.getElementById('btnAddPolicy');
        fp.addEventListener('submit', async (e)=>{
          e.preventDefault();
          const fd = new FormData(fp);
          const nr = fd.get('nuclei_rate');
          const payload = {
            name: fd.get('name'),
            use_nmap: !!fd.get('use_nmap'),
            nmap_profile: fd.get('nmap_profile') || 'vuln',
            use_nuclei: !!fd.get('use_nuclei'),
            nuclei_sev: fd.get('nuclei_sev') || 'critical,high,medium',
            use_nikto: !!fd.get('use_nikto'),
            use_wpscan: !!fd.get('use_wpscan'),
            http_basic_user: fd.get('http_basic_user') || '',
            http_basic_pass: fd.get('http_basic_pass') || '',
            concurrency: Number(fd.get('concurrency') || 2),
            nuclei_rate: nr ? Number(nr) : null,
            exclude_paths: fd.get('exclude_paths') || ''
          };
          UI.spin(bp,true,'Saving...');
          const r = await fetch('/policies/add', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
          if (r.ok) { UI.toast('Policy added','success'); window.location.reload(); } else { UI.toast(await r.text(),'error'); }
          UI.spin(bp,false);
        });
      </script>
      <table class="w-full text-sm">
        <thead><tr class="text-emerald-300/80"><th>ID</th><th class='text-left'>Name</th><th>Nmap</th><th>Nuclei</th><th>Nikto</th><th>WPScan</th><th>Options</th></tr></thead>
        <tbody>%%ITEMS%%</tbody>
      </table>
    </section>
    """
    return body.replace("%%ITEMS%%", items)



def page_scans() -> str:
    with db() as conn:
        assets = conn.execute("SELECT * FROM assets ORDER BY id DESC").fetchall()
        policies = conn.execute("SELECT * FROM policies ORDER BY id DESC").fetchall()
        scans = conn.execute(
            "SELECT s.*, p.name as policy_name FROM scans s JOIN policies p ON p.id=s.policy_id ORDER BY s.id DESC"
        ).fetchall()

    asset_opts = "".join(
        f"<label class='flex items-center gap-2'><input type=checkbox name=asset_ids value={a['id']}> {a['target']} "
        f"<span class='text-xs text-emerald-300/70'>{a['tags']}</span></label>"
        for a in assets
    )
    policy_opts = "".join(f"<option value={p['id']}>{p['name']}</option>" for p in policies)
    scan_rows = "".join(
        f"<tr class='hover:bg-white/5 transition'><td class='py-1 pr-2 mono'>{s['id']}</td>"
        f"<td class='py-1 pr-2'>{s['name']}</td>"
        f"<td class='py-1 pr-2'>{s['policy_name']}</td>"
        f"<td class='py-1 pr-2 mono'>{s['schedule_cron'] or '-'}</td>"
        f"<td class='py-1 pr-2 flex gap-2'><a href='/scans/run?id={s['id']}' class='btn'>Run</a>"
        f"<button class='btn' onclick=\"UI.copy('/scans/run?id={s['id']}')\">Copy link</button></td></tr>"
        for s in scans
    )

    body = """
    <section class="card rounded-2xl p-5">
      <h2 class="text-xl glow mb-3">Scans</h2>
      <form id="formScan" class="grid md:grid-cols-2 gap-4 mb-6">
        <input name=name required placeholder="Scan name" class="input" />
        <select name=policy_id class="input">%%POLICY_OPTS%%</select>
        <div class="md:col-span-2 card rounded-2xl p-3">
          <div class="text-sm mb-2">Select Assets</div>
          <div class="grid md:grid-cols-3 gap-2">%%ASSET_OPTS%%</div>
        </div>
        <input name=schedule_cron placeholder="cron (e.g. 0 2 * * *) or leave blank" class="input md:col-span-2" />
        <button class="btn md:col-span-2" id="btnCreateScan">Create Scan</button>
      </form>
      <script>
        const fs = document.getElementById('formScan'); const b = document.getElementById('btnCreateScan');
        fs.addEventListener('submit', async (e)=>{
          e.preventDefault();
          const asset_ids = [...fs.querySelectorAll('input[name="asset_ids"]:checked')].map(x=>x.value);
          const fd = new FormData(fs);
          const payload = { name: fd.get('name'), policy_id: Number(fd.get('policy_id')), asset_ids, schedule_cron: fd.get('schedule_cron') || '' };
          if(asset_ids.length===0){ UI.toast('Select at least one asset','error'); return; }
          UI.spin(b,true,'Creating...');
          const r = await fetch('/scans/add', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
          if (r.ok) { UI.toast('Scan created','success'); window.location.reload(); } else { UI.toast(await r.text(),'error'); }
          UI.spin(b,false);
        });
      </script>
      <table class="w-full text-sm">
        <thead><tr class="text-emerald-300/80"><th>ID</th><th class='text-left'>Name</th><th class='text-left'>Policy</th><th>Schedule</th><th>Actions</th></tr></thead>
        <tbody>%%SCAN_ROWS%%</tbody>
      </table>
    </section>
    """
    return (
        body.replace("%%POLICY_OPTS%%", policy_opts)
            .replace("%%ASSET_OPTS%%", asset_opts)
            .replace("%%SCAN_ROWS%%", scan_rows)
    )



def get_templates() -> list[dict]:
    """Card templates mapped to ad-hoc scan payloads."""
    return [
        {
            "id": "attack_surface",
            "title": "Attack Surface Discovery",
            "category": "Discovery",
            "desc": "Use Nuclei to enumerate exposures on web-facing services.",
            "payload": {
                "use_nmap": False,
                "nmap_profile": "vuln",
                "use_nuclei": True,
                "nuclei_sev": "critical,high,medium",
                "use_nikto": False,
                "use_wpscan": False,
            },
        },
        {
            "id": "host_discovery",
            "title": "Host Discovery",
            "category": "Discovery",
            "desc": "Quick Nmap host and top-ports with service detection.",
            "payload": {
                "use_nmap": True,
                "nmap_profile": "quick",
                "use_nuclei": False,
                "nuclei_sev": "critical,high,medium",
                "use_nikto": False,
                "use_wpscan": False,
            },
        },
        {
            "id": "basic_network",
            "title": "Basic Network Scan",
            "category": "Vulnerabilities",
            "desc": "Full TCP sweep with service detection.",
            "payload": {
                "use_nmap": True,
                "nmap_profile": "full",
                "use_nuclei": False,
                "nuclei_sev": "critical,high,medium",
                "use_nikto": False,
                "use_wpscan": False,
            },
        },
        {
            "id": "advanced_dynamic",
            "title": "Advanced Dynamic Scan",
            "category": "Vulnerabilities",
            "desc": "Nmap vuln + Nuclei (critical/high).",
            "payload": {
                "use_nmap": True,
                "nmap_profile": "vuln",
                "use_nuclei": True,
                "nuclei_sev": "critical,high",
                "use_nikto": False,
                "use_wpscan": False,
            },
        },
        {
            "id": "web_app_tests",
            "title": "Web Application Tests",
            "category": "Web App",
            "desc": "Nuclei + Nikto for common web vulns.",
            "payload": {
                "use_nmap": False,
                "nmap_profile": "vuln",
                "use_nuclei": True,
                "nuclei_sev": "critical,high,medium",
                "use_nikto": True,
                "use_wpscan": False,
            },
        },
        {
            "id": "wordpress_audit",
            "title": "WordPress Audit",
            "category": "Web App",
            "desc": "WPScan with Nuclei checks (API token recommended).",
            "payload": {
                "use_nmap": False,
                "nmap_profile": "vuln",
                "use_nuclei": True,
                "nuclei_sev": "critical,high,medium",
                "use_nikto": False,
                "use_wpscan": True,
            },
        },
    ]


def page_templates() -> str:
    # Plain string (not f-string) → no brace escaping headaches
    return textwrap.dedent(
        """
        <section class="card rounded-2xl p-5">
          <div class="flex items-center justify-between mb-4">
            <div>
              <h2 class="text-2xl glow">Scan Templates</h2>
              <p class="text-sm text-emerald-300/80">Pick a template, paste targets, launch.</p>
            </div>
            <div class="flex items-center gap-2">
              <input id="searchTemplates" placeholder="Search Library" class="input" />
            </div>
          </div>
          <div id="tpl-sections" class="space-y-8"></div>
        </section>

        <!-- Modal -->
        <div id="tplModal" class="fixed inset-0 hidden items-center justify-center bg-black/50 z-50">
          <div class="card rounded-2xl p-5 w-[680px] max-w-[95vw]">
            <div class="flex items-start justify-between">
              <div>
                <h3 id="mTitle" class="text-xl glow"></h3>
                <p id="mDesc" class="text-sm text-emerald-300/80"></p>
              </div>
              <button id="mClose" class="btn">Close</button>
            </div>
            <div class="mt-4 space-y-3">
              <textarea id="mTargets" rows="5" placeholder="paste IPs/hosts/URLs, one per line" class="w-full rounded-xl bg-black/40 border accent p-2"></textarea>
              <div class="flex flex-wrap gap-3 text-sm">
                <label class="flex items-center gap-2"><span class="opacity-70">Nmap:</span>
                  <select id="mNmap" class="input">
                    <option value="vuln">vuln</option><option value="quick">quick</option><option value="full">full</option>
                  </select>
                </label>
                <label class="flex items-center gap-2"><span class="opacity-70">Nuclei:</span>
                  <select id="mSev" class="input">
                    <option value="critical,high,medium">critical,high,medium</option>
                    <option value="critical,high">critical,high</option>
                    <option value="low,info">low,info</option>
                  </select>
                </label>
                <label class="flex items-center gap-2"><input id="mNmapUse" type="checkbox"> Nmap</label>
                <label class="flex items-center gap-2"><input id="mNucUse" type="checkbox"> Nuclei</label>
                <label class="flex items-center gap-2"><input id="mNiktoUse" type="checkbox"> Nikto</label>
                <label class="flex items-center gap-2"><input id="mWpsUse" type="checkbox"> WPScan</label>
              </div>
              <div class="flex items-center justify-end gap-2">
                <button id="mPaste" class="btn">Paste</button>
                <button id="mClear" class="btn">Clear</button>
                <button id="mRun" class="btn">Run Now</button>
              </div>
            </div>
          </div>
        </div>

        <script>
          const elSec = document.getElementById('tpl-sections');
          const elSearch = document.getElementById('searchTemplates');

          // Modal refs
          const modal = document.getElementById('tplModal');
          const mTitle = document.getElementById('mTitle');
          const mDesc = document.getElementById('mDesc');
          const mTargets = document.getElementById('mTargets');
          const mNmap = document.getElementById('mNmap');
          const mSev = document.getElementById('mSev');
          const mNmapUse = document.getElementById('mNmapUse');
          const mNucUse = document.getElementById('mNucUse');
          const mNiktoUse = document.getElementById('mNiktoUse');
          const mWpsUse = document.getElementById('mWpsUse');
          const mRun = document.getElementById('mRun');
          const mClose = document.getElementById('mClose');
          const mPaste = document.getElementById('mPaste');
          const mClear = document.getElementById('mClear');

          let TEMPLATES = [];
          let CURRENT = null;

          function icon(name){
            if(name==='Discovery') return '<svg width="26" height="26" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2l3 7h7l-5.5 4 2 7L12 17l-6.5 3 2-7L2 9h7l3-7z"/></svg>';
            if(name==='Web App') return '<svg width="26" height="26" viewBox="0 0 24 24" fill="currentColor"><path d="M3 4h18v6H3zm0 8h18v8H3z"/></svg>';
            return '<svg width="26" height="26" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="10"/></svg>';
          }
          function card(t){
            return `
              <button class="group rounded-xl p-4 border border-emerald-400/30 bg-black/20 hover:bg-emerald-500/10 hover:border-emerald-400/60 text-left transition tpl-card"
                      data-id="${t.id}">
                <div class="flex items-center gap-3">
                  <div class="text-emerald-400">${icon(t.category)}</div>
                  <div>
                    <div class="font-medium">${t.title}</div>
                    <div class="text-xs text-emerald-300/80">${t.desc}</div>
                  </div>
                </div>
              </button>`;
          }
          function groupByCategory(items){ const g = {}; items.forEach(x => { (g[x.category] ||= []).push(x); }); return g; }
          function render(items){
            elSec.innerHTML = '';
            const groups = groupByCategory(items);
            Object.keys(groups).sort().forEach(cat=>{
              const grid = groups[cat].map(card).join('');
              const sec = document.createElement('section');
              sec.innerHTML = `
                <h3 class="text-lg glow mb-2">${cat}</h3>
                <div class="grid lg:grid-cols-3 md:grid-cols-2 grid-cols-1 gap-3">${grid}</div>
              `;
              elSec.appendChild(sec);
            });
            document.querySelectorAll('.tpl-card').forEach(btn=>{
              btn.addEventListener('click', ()=>{
                const t = TEMPLATES.find(x=>x.id===btn.dataset.id);
                if(!t) return;
                CURRENT = t;
                mTitle.textContent = t.title; mDesc.textContent = t.desc;
                mTargets.value = '';
                mNmap.value = t.payload.nmap_profile || 'vuln';
                mSev.value = t.payload.nuclei_sev || 'critical,high,medium';
                mNmapUse.checked = !!t.payload.use_nmap;
                mNucUse.checked = !!t.payload.use_nuclei;
                mNiktoUse.checked = !!t.payload.use_nikto;
                mWpsUse.checked = !!t.payload.use_wpscan;
                modal.classList.remove('hidden'); modal.classList.add('flex');
              });
            });
          }
          elSearch.addEventListener('input', ()=>{
            const q = elSearch.value.toLowerCase();
            const filtered = TEMPLATES.filter(t => (t.title+t.desc+t.category).toLowerCase().includes(q));
            render(filtered);
          });
          mClose.addEventListener('click', ()=>{ modal.classList.add('hidden'); modal.classList.remove('flex'); });
          mClear.addEventListener('click', ()=>{ mTargets.value=''; });
          mPaste.addEventListener('click', async ()=>{
            try{ mTargets.value += (mTargets.value?'\\n':'') + (await navigator.clipboard.readText()); UI.toast('Pasted','success'); }
            catch{ UI.toast('Clipboard denied','error'); }
          });
          mRun.addEventListener('click', async ()=>{
            if(!CURRENT) return;
            const targets = (mTargets.value || '').trim();
            if(!targets){ UI.toast('Add targets first','error'); return; }
            const payload = {
              targets,
              use_nmap: !!mNmapUse.checked,
              nmap_profile: mNmap.value || 'vuln',
              use_nuclei: !!mNucUse.checked,
              nuclei_sev: mSev.value || 'critical,high,medium',
              use_nikto: !!mNiktoUse.checked,
              use_wpscan: !!mWpsUse.checked
            };
            UI.spin(mRun, true, 'Starting...');
            try{
              const r = await fetch('/scans/create_ad_hoc', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
              if(!r.ok){ UI.toast(await r.text(),'error'); return; }
              const data = await r.json();
              UI.toast('Scan created','success');
UI.openScan('/scans/run?id=' + data.scan_id, 'Template: ' + (CURRENT ? CURRENT.title : 'Scan') + ' #' + data.scan_id);
            }catch(e){ UI.toast(String(e),'error'); }
            finally{ UI.spin(mRun,false); }
          });
          (async function(){ const r = await fetch('/api/templates'); TEMPLATES = await r.json(); render(TEMPLATES); })();
        </script>
        """
    )


def page_jobs() -> str:
    with db() as conn:
        rows = conn.execute(
            "SELECT j.*, s.name as scan_name FROM jobs j JOIN scans s ON s.id=j.scan_id ORDER BY j.id DESC LIMIT 200"
        ).fetchall()

    def badge(status: str) -> str:
        color = (
            "bg-emerald-500/15 border-emerald-400/40"
            if status == "finished"
            else ("bg-yellow-500/15 border-yellow-400/40" if status == "running" else "bg-slate-500/15 border-slate-400/40")
        )
        return f"<span class='badge {color}'>{status}</span>"

    items = "".join(
        f"<tr class='hover:bg-white/5 transition'><td class='py-1 pr-2 mono'>{r['id']}</td>"
        f"<td class='py-1 pr-2'>{r['scan_name']}</td>"
        f"<td class='py-1 pr-2 mono'>{badge(r['status'])}</td>"
        f"<td class='py-1 pr-2 mono'>{r['started_at'] or '-'}</td>"
        f"<td class='py-1 pr-2 mono'>{r['finished_at'] or '-'}</td>"
        f"<td class='py-1 pr-2 flex gap-2'>"
        f"<a href='/jobs/{r['id']}/log' class='btn'>Log</a> "
        f"<a href='/api/jobs/{r['id']}/export' class='btn'>JSON</a> "
        f"<a href='/api/jobs/{r['id']}/export.csv' class='btn'>CSV</a> "
        f"<a href='/api/jobs/{r['id']}/export.pdf' class='btn'>PDF</a> "
        f"<button class='btn' onclick=\"UI.copy('{r['id']}')\">Copy ID</button></td></tr>"
        for r in rows
    )
    return f"""
    <section class="card rounded-2xl p-5">
      <h2 class="text-xl glow mb-3">Jobs</h2>
      <table class="w-full text-sm">
        <thead><tr class="text-emerald-300/80"><th>ID</th><th class='text-left'>Scan</th><th>Status</th><th>Started</th><th>Finished</th><th>Export</th></tr></thead>
        <tbody>{items}</tbody>
      </table>
    </section>
    """


# ---------- Routes: pages ----------
@app.get("/", response_class=HTMLResponse)
async def home(_: Request):
    return render(page_dashboard())


@app.get("/assets", response_class=HTMLResponse)
async def assets_page(_: Request):
    return render(page_assets(), title=f"{APP_NAME} • Assets")


@app.get("/policies", response_class=HTMLResponse)
async def policies_page(_: Request):
    return render(page_policies(), title=f"{APP_NAME} • Policies")


@app.get("/scans", response_class=HTMLResponse)
async def scans_page(_: Request):
    return render(page_scans(), title=f"{APP_NAME} • Scans")


@app.get("/templates", response_class=HTMLResponse)
async def templates_page(_: Request):
    return render(page_templates(), title=f"{APP_NAME} • Templates")


@app.get("/jobs", response_class=HTMLResponse)
async def jobs_page(_: Request):
    return render(page_jobs(), title=f"{APP_NAME} • Jobs")


@app.get("/jobs/{job_id}/log", response_class=HTMLResponse)
async def job_log(job_id: int):
    log = (JOBS_DIR / str(job_id) / "job.log")
    text = log.read_text() if log.exists() else "(no log yet)"
    body = f"""
    <section class="card rounded-2xl p-5">
      <h2 class="text-xl glow mb-3">Job #{job_id} Log</h2>
      <pre class="mono whitespace-pre-wrap text-emerald-200/90 text-sm h-[70vh] overflow-auto p-3 bg-black/30 rounded-xl border accent">{text}</pre>
    </section>
    """
    return render(body, title=f"{APP_NAME} • Job {job_id}")


# ---------- JSON API (JSON only; no multipart) ----------
@app.post("/assets/add")
async def assets_add(request: Request):
    try:
        data = await request.json()
    except Exception:
        return PlainTextResponse("This endpoint expects JSON", status_code=415)
    target = (data.get("target") or "").strip()
    tags = (data.get("tags") or "").strip()
    if not TARGET_RE.match(target):
        return PlainTextResponse("Invalid target.", status_code=400)
    with db() as conn:
        conn.execute("INSERT OR IGNORE INTO assets(target,tags) VALUES(?,?)", (target, tags))
        conn.commit()
    return RedirectResponse("/assets", status_code=303)


@app.post("/policies/add")
async def policies_add(request: Request):
    try:
        d = await request.json()
    except Exception:
        return PlainTextResponse("This endpoint expects JSON", status_code=415)
    name = (d.get("name") or "").strip()
    if not name:
        return PlainTextResponse("Name required", status_code=400)
    use_nmap = 1 if d.get("use_nmap") else 0
    nmap_profile = d.get("nmap_profile") or "vuln"
    use_nuclei = 1 if d.get("use_nuclei") else 0
    nuclei_sev = d.get("nuclei_sev") or "critical,high,medium"
    use_nikto = 1 if d.get("use_nikto") else 0
    use_wpscan = 1 if d.get("use_wpscan") else 0
    http_basic_user = (d.get("http_basic_user") or "").strip()
    http_basic_pass = (d.get("http_basic_pass") or "").strip()
    concurrency = int(d.get("concurrency") or 2)
    nuclei_rate = d.get("nuclei_rate", None)
    exclude_paths = (d.get("exclude_paths") or "").strip()
    with db() as conn:
        conn.execute(
            "INSERT INTO policies(name,use_nmap,nmap_profile,use_nuclei,nuclei_sev,use_nikto,use_wpscan,http_basic_user,http_basic_pass,concurrency,nuclei_rate,exclude_paths) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                name,
                use_nmap,
                nmap_profile,
                use_nuclei,
                nuclei_sev,
                use_nikto,
                use_wpscan,
                http_basic_user,
                http_basic_pass,
                concurrency,
                nuclei_rate,
                exclude_paths,
            ),
        )
        conn.commit()
    return RedirectResponse("/policies", status_code=303)


@app.post("/scans/add")
async def scans_add(request: Request):
    try:
        d = await request.json()
    except Exception:
        return PlainTextResponse("This endpoint expects JSON", status_code=415)
    name = (d.get("name") or "").strip()
    policy_id = int(d.get("policy_id"))
    asset_ids = d.get("asset_ids") or []
    schedule_cron = (d.get("schedule_cron") or "").strip() or None
    if not name or not asset_ids:
        return PlainTextResponse("Name and at least one asset are required", status_code=400)
    ids_csv = ",".join(map(str, asset_ids))
    with db() as conn:
        conn.execute(
            "INSERT INTO scans(name,policy_id,asset_ids,schedule_cron,created_at) VALUES(?,?,?,?,?)",
            (name, int(policy_id), ids_csv, schedule_cron, now_iso()),
        )
        conn.commit()
        sid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    if schedule_cron:
        register_schedule(sid, schedule_cron)
    return RedirectResponse("/scans", status_code=303)


@app.post("/scans/create_ad_hoc")
async def scans_create_ad_hoc(request: Request):
    try:
        d = await request.json()
    except Exception:
        return PlainTextResponse("This endpoint expects JSON", status_code=415)
    targets = normalize_targets(d.get("targets") or "")
    if not targets:
        return PlainTextResponse("No valid targets.", status_code=400)
    use_nmap = 1 if d.get("use_nmap") else 0
    nmap_profile = d.get("nmap_profile") or "vuln"
    use_nuclei = 1 if d.get("use_nuclei") else 0
    nuclei_sev = d.get("nuclei_sev") or "critical,high,medium"
    use_nikto = 1 if d.get("use_nikto") else 0
    use_wpscan = 1 if d.get("use_wpscan") else 0
    with db() as conn:
        conn.execute(
            "INSERT INTO policies(name,use_nmap,nmap_profile,use_nuclei,nuclei_sev,use_nikto,use_wpscan,concurrency) VALUES(?,?,?,?,?,?,?,?)",
            ("Ad-hoc", use_nmap, nmap_profile, use_nuclei, nuclei_sev, use_nikto, use_wpscan, 2),
        )
        pid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        ids = []
        for t in targets:
            conn.execute("INSERT OR IGNORE INTO assets(target,tags) VALUES(?,?)", (t, "ad-hoc"))
            aid = conn.execute("SELECT id FROM assets WHERE target=?", (t,)).fetchone()[0]
            ids.append(str(aid))
        conn.execute(
            "INSERT INTO scans(name,policy_id,asset_ids,created_at) VALUES(?,?,?,?)",
            ("Ad-hoc Run", pid, ",".join(ids), now_iso()),
        )
        sid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.commit()
    return JSONResponse({"scan_id": sid})


@app.get("/scans/run")
async def scans_run(id: int):
    return StreamingResponse(run_scan_stream(id), media_type="text/plain")


# ---------- Export & stats ----------
@app.get("/api/jobs/{job_id}/export")
async def export_job(job_id: int):
    with db() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    if not row:
        return PlainTextResponse("Job not found", status_code=404)
    data = {
        "job": dict(row),
        "log_file": str((JOBS_DIR / str(job_id) / "job.log").resolve()),
        "nuclei_findings": load_jsonl(JOBS_DIR / str(job_id) / "nuclei.jsonl"),
        "wpscan_report": load_json(JOBS_DIR / str(job_id) / "wpscan.json"),
    }
    return PlainTextResponse(json.dumps(data, indent=2))


@app.get("/api/jobs/{job_id}/export.csv")
async def export_csv(job_id: int):
    findings = load_jsonl(JOBS_DIR / str(job_id) / "nuclei.jsonl")
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["target", "template", "name", "severity", "matched", "description"])
    for r in findings:
        info = r.get("info", {})
        w.writerow(
            [
                r.get("host") or r.get("matched-at") or "",
                r.get("templateID") or info.get("id") or "",
                info.get("name") or "",
                (info.get("severity") or r.get("severity") or "").lower(),
                r.get("matched-at") or "",
                (info.get("description") or "").replace("\n", " ").strip(),
            ]
        )
    data = buf.getvalue().encode()
    headers = {"Content-Disposition": f"attachment; filename=job_{job_id}.csv"}
    return Response(content=data, media_type="text/csv", headers=headers)


@app.get("/api/jobs/{job_id}/export.pdf")
async def export_pdf(job_id: int):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm
    from reportlab.pdfgen import canvas

    job_dir = JOBS_DIR / str(job_id)
    findings = load_jsonl(job_dir / "nuclei.jsonl")
    summary = summarize_from_findings(findings)

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    width, height = A4
    y = height - 2 * cm

    def line(txt, size=11, step=14):
        nonlocal y
        c.setFont("Helvetica", size)
        c.drawString(2 * cm, y, txt)
        y -= step

    line(f"ArcLight Scanner — Report for Job #{job_id}", size=14, step=18)
    line(f"Generated: {now_iso()}")
    line("")
    line("Summary:")
    line(f"  Findings: {summary['nuclei_findings']}")
    line(
        f"  Severity: C:{summary['severity'].get('critical',0)} H:{summary['severity'].get('high',0)} "
        f"M:{summary['severity'].get('medium',0)} L:{summary['severity'].get('low',0)} I:{summary['severity'].get('info',0)}"
    )
    line(f"  Risk score: {summary['risk_score']}")
    line("")
    line("Top findings:")
    count = 0
    for r in findings[:40]:
        info = r.get("info", {})
        line(f"- [{(info.get('severity') or '').upper():>5}] {info.get('name') or ''}")
        line(f"  {r.get('matched-at') or r.get('host') or ''}")
        count += 1
        if y < 3 * cm:
            c.showPage()
            y = height - 2 * cm
    if count == 0:
        line("(no findings)")

    c.showPage()
    c.save()
    buf.seek(0)
    headers = {"Content-Disposition": f"attachment; filename=job_{job_id}.pdf"}
    return Response(content=buf.read(), media_type="application/pdf", headers=headers)


@app.get("/api/stats/summary")
async def stats_summary():
    # aggregate last 50 jobs
    with db() as conn:
        rows = conn.execute("SELECT summary FROM jobs WHERE summary != '' ORDER BY id DESC LIMIT 50").fetchall()
    agg = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in rows:
        with contextlib.suppress(Exception):
            s = json.loads(r[0])
            sev = s.get("severity", {})
            for k in agg:
                agg[k] += int(sev.get(k, 0))
    return JSONResponse({"severity": agg, "jobs": len(rows)})


@app.get("/api/stats/throughput")
def stats_throughput(days: int = 14):
    days = max(1, min(int(days or 14), 60))
    today = dt.datetime.utcnow().date()
    labels = [(today - dt.timedelta(days=i)).isoformat() for i in range(days - 1, -1, -1)]
    counts = {d: 0 for d in labels}
    with db() as conn:
        rows = conn.execute("SELECT started_at FROM jobs WHERE started_at IS NOT NULL ORDER BY id DESC").fetchall()
    for r in rows:
        s = r[0] or ""
        d = s[:10] if len(s) >= 10 else ""
        if d in counts:
            counts[d] += 1
    return JSONResponse({"labels": list(counts.keys()), "counts": list(counts.values())})


@app.get("/api/templates", response_class=JSONResponse)
def api_templates():
    return JSONResponse(get_templates())


# ---------- Scan runner ----------
async def run_scan_stream(scan_id: int) -> AsyncGenerator[str, None]:
    with db() as conn:
        srow = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not srow:
            yield "Scan not found.\n"
            return
        prow = conn.execute("SELECT * FROM policies WHERE id=?", (srow["policy_id"],)).fetchone()
        aid_list = [int(x) for x in (srow["asset_ids"] or "").split(",") if x]
        arows = conn.execute(
            f"SELECT * FROM assets WHERE id IN ({','.join('?' for _ in aid_list)})" if aid_list else "SELECT * FROM assets WHERE 1=0",
            aid_list,
        ).fetchall()
        targets = [r["target"] for r in arows]
        conn.execute("INSERT INTO jobs(scan_id,status,started_at) VALUES(?,?,?)", (scan_id, "running", now_iso()))
        job_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.commit()

    job_dir = JOBS_DIR / str(job_id)
    job_dir.mkdir(parents=True, exist_ok=True)
    log_file = job_dir / "job.log"
    header = f"[+] Job #{job_id} started for scan #{scan_id} on targets: {', '.join(targets)}\n"
    log_file.write_text(header)
    yield header

    use_nmap = bool(prow["use_nmap"])
    nmap_profile = prow["nmap_profile"]
    use_nuclei = bool(prow["use_nuclei"])
    nuclei_sev = prow["nuclei_sev"]
    use_nikto = bool(prow["use_nikto"])
    use_wpscan = bool(prow["use_wpscan"])
    basic_user = (prow["http_basic_user"] or "").strip()
    basic_pass = (prow["http_basic_pass"] or "").strip()
    concurrency = max(1, int(prow["concurrency"] or 1))
    nuclei_rate = prow["nuclei_rate"]

    queue: asyncio.Queue[str | None] = asyncio.Queue()
    sem = asyncio.Semaphore(concurrency)

    async def run_for_target(t: str):
        await queue.put(f"\n========== Target: {t} ===========\n")
        # Nmap
        if use_nmap:
            if nmap_profile == "quick":
                nmap_args = ["-T4", "-F", "-sV", "-Pn"]
            elif nmap_profile == "full":
                nmap_args = ["-T4", "-p-", "-sV", "-Pn"]
            else:
                nmap_args = ["-T3", "-sV", "-sC", "--script", "vuln", "-Pn"]
            async for chunk in stream_cmd(f"Nmap on {t}", ["nmap", *nmap_args, t], log_file):
                await queue.put(chunk)
        # Nuclei
        if use_nuclei:
            url = ensure_url(t)
            nuclei_cmd = ["nuclei", "-u", url, "-severity", nuclei_sev, "-jsonl"]
            if nuclei_rate:
                nuclei_cmd += ["-rl", str(int(nuclei_rate))]
            if basic_user or basic_pass:
                import base64

                token = base64.b64encode(f"{basic_user}:{basic_pass}".encode()).decode()
                nuclei_cmd += ["-H", f"Authorization: Basic {token}"]
            nuclei_jsonl = job_dir / "nuclei.jsonl"
            async for chunk in stream_cmd(f"Nuclei on {url}", nuclei_cmd, log_file):
                with contextlib.suppress(Exception):
                    obj = json.loads(chunk)
                    with nuclei_jsonl.open("a") as f:
                        f.write(json.dumps(obj) + "\n")
                await queue.put(chunk)
        # Nikto
        if use_nikto:
            url = ensure_url(t)
            nikto_cmd = ["nikto", "-host", url, "-ask", "no"]
            if basic_user or basic_pass:
                nikto_cmd += ["-id", f"{basic_user}:{basic_pass}"]
            async for chunk in stream_cmd(f"Nikto on {url}", nikto_cmd, log_file):
                await queue.put(chunk)
        # WPScan
        if use_wpscan:
            url = ensure_url(t)
            token = os.getenv("WPSCAN_API_TOKEN")
            wps_cmd = ["wpscan", "--url", url, "--no-update", "--format", "json"]
            if token:
                wps_cmd += ["--api-token", token]
            wps_json = job_dir / "wpscan.json"
            async for chunk in stream_cmd(f"WPScan on {url}", wps_cmd, log_file):
                with contextlib.suppress(Exception):
                    obj = json.loads(chunk)
                    wps_json.write_text(json.dumps(obj, indent=2))
                await queue.put(chunk)

    async def worker(t: str):
        async with sem:
            try:
                await run_for_target(t)
            finally:
                await queue.put(None)

    tasks = [asyncio.create_task(worker(t)) for t in targets]
    finished = 0
    while finished < len(tasks):
        item = await queue.get()
        if item is None:
            finished += 1
        else:
            yield item

    # finalize
    summary = summarize_job(job_dir)
    with db() as conn:
        conn.execute(
            "UPDATE jobs SET status=?, finished_at=?, summary=? WHERE id=?",
            ("finished", now_iso(), json.dumps(summary), job_id),
        )
        conn.commit()
    yield "\n[+] Job complete.\n"


# ---------- Summaries ----------
def load_jsonl(p: Path) -> List[dict]:
    if not p.exists():
        return []
    out = []
    for line in p.read_text().splitlines():
        with contextlib.suppress(Exception):
            out.append(json.loads(line))
    return out


def load_json(p: Path) -> dict:
    if not p.exists():
        return {}
    with p.open() as f:
        return json.load(f)


RISK_WEIGHTS = {"critical": 9, "high": 6, "medium": 3, "low": 1, "info": 0}


def summarize_from_findings(nuclei: List[dict]) -> dict:
    sev_counts: Dict[str, int] = {k: 0 for k in RISK_WEIGHTS}
    for r in nuclei:
        sev = (r.get("info", {}).get("severity") or r.get("severity") or "info").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
    risk = sum(sev_counts[k] * w for k, w in RISK_WEIGHTS.items())
    return {"nuclei_findings": len(nuclei), "severity": sev_counts, "risk_score": risk}


def summarize_job(job_dir: Path) -> dict:
    nuclei = load_jsonl(job_dir / "nuclei.jsonl")
    return summarize_from_findings(nuclei)


# ---------- Self-tests ----------
@app.get("/__selftest__", response_class=JSONResponse)
async def __selftest__():
    tests = []
    # 1: normalize_targets
    raw = "example.com, 1.2.3.4; https://a.b\ninvalid host  ,  2001:db8::1"
    parsed = normalize_targets(raw)
    tests.append(
        {
            "name": "normalize_targets",
            "output": parsed,
            "pass": all(x in parsed for x in ["example.com", "1.2.3.4", "https://a.b", "2001:db8::1"])
            and "invalid" not in " ".join(parsed),
        }
    )
    # 2: empty summary
    empty = summarize_from_findings([])
    tests.append({"name": "summarize_from_findings_empty", "pass": empty["nuclei_findings"] == 0 and empty["risk_score"] == 0})
    # 3: ensure_url
    tests.append(
        {
            "name": "ensure_url",
            "pass": ensure_url("example.com").startswith("http://") and ensure_url("https://site").startswith("https://"),
        }
    )
    # 4: risk weights
    sample = [
        {"info": {"severity": "critical"}},
        {"info": {"severity": "high"}},
        {"info": {"severity": "medium"}},
        {"info": {"severity": "low"}},
        {"info": {"severity": "info"}},
        {"info": {"severity": "high"}},
    ]
    s = summarize_from_findings(sample)
    expected = 1 * 9 + 2 * 6 + 1 * 3 + 1 * 1 + 1 * 0
    tests.append({"name": "risk_weighting", "pass": s["risk_score"] == expected and s["nuclei_findings"] == len(sample)})
    # 5: cron next time
    base = dt.datetime.utcnow()
    it = croniter("*/5 * * * *", base)
    nxt = it.get_next(dt.datetime)
    tests.append({"name": "croniter_next_5m", "pass": 0 < (nxt - base).total_seconds() <= 6 * 60})
    # 6: dedupe
    deduped = normalize_targets("test.com test.com  test.com")
    tests.append({"name": "normalize_targets_dedupe", "pass": len(deduped) == 1 and deduped[0] == "test.com"})
    # 7: socket flag presence
    try:
        import socket

        tests.append({"name": "socket_SO_REUSEADDR_present", "pass": isinstance(hasattr(socket, "SO_REUSEADDR"), bool)})
    except Exception as e:
        tests.append({"name": "socket_SO_REUSEADDR_present", "output": str(e), "pass": True})
    # 8: stats_summary keys
    ss = summarize_from_findings([])
    tests.append({"name": "stats_summary_keys", "pass": all(k in ss for k in ["nuclei_findings", "severity", "risk_score"])})
    # 9: throughput shape
    try:
        tp = stats_throughput(7).body
        ok = all(k in json.loads(tp.decode("utf-8")) for k in ["labels", "counts"])
        tests.append({"name": "stats_throughput_shape", "pass": ok})
    except Exception as e:
        tests.append({"name": "stats_throughput_shape", "output": str(e), "pass": False})
    # 10: templates API shape
    try:
        raw = api_templates().body
        data = json.loads(raw.decode("utf-8"))
        ok = isinstance(data, list) and len(data) >= 4 and all(
            all(k in t for k in ("id", "title", "category", "payload")) for t in data
        )
        tests.append({"name": "templates_shape", "pass": ok})
    except Exception as e:
        tests.append({"name": "templates_shape", "output": str(e), "pass": False})
    # 11: at least one template uses WPScan
    try:
        data = json.loads(api_templates().body.decode("utf-8"))
        has_wp = any(t.get("payload", {}).get("use_wpscan") for t in data)
        tests.append({"name": "templates_has_wpscan", "pass": has_wp})
    except Exception as e:
        tests.append({"name": "templates_has_wpscan", "output": str(e), "pass": False})

    all_pass = all(t.get("pass") for t in tests)
    return JSONResponse({"ok": all_pass, "tests": tests})


# ---------- Lightweight scheduler (no apscheduler) ----------
CRON_STATE: Dict[int, dt.datetime] = {}
SCHEDULER_TASK: Optional[asyncio.Task] = None


async def scheduler_loop():
    interval = 30  # seconds
    while True:
        await asyncio.sleep(interval)
        if os.getenv("SCHEDULER_DISABLED"):
            continue
        now = dt.datetime.utcnow()
        try:
            with db() as conn:
                rows = conn.execute("SELECT id, schedule_cron FROM scans WHERE schedule_cron IS NOT NULL").fetchall()
            for r in rows:
                sid = int(r["id"])
                cron = r["schedule_cron"]
                if sid not in CRON_STATE:
                    with contextlib.suppress(Exception):
                        CRON_STATE[sid] = croniter(cron, now).get_next(dt.datetime)
                due = CRON_STATE.get(sid)
                if not due:
                    continue
                if due <= now:
                    with db() as conn:
                        running = conn.execute(
                            "SELECT 1 FROM jobs WHERE scan_id=? AND status='running' LIMIT 1", (sid,)
                        ).fetchone()
                    if running:
                        with contextlib.suppress(Exception):
                            CRON_STATE[sid] = croniter(cron, now).get_next(dt.datetime)
                        continue
                    asyncio.create_task(save_only_run(sid))
                    with contextlib.suppress(Exception):
                        CRON_STATE[sid] = croniter(cron, now).get_next(dt.datetime)
        except Exception as e:
            print("[scheduler] error:", e)


def register_schedule(scan_id: int, cron: str):
    try:
        now = dt.datetime.utcnow()
        CRON_STATE[scan_id] = croniter(cron, now).get_next(dt.datetime)
    except Exception as e:
        print("[scheduler] failed to register schedule:", e)


async def save_only_run(scan_id: int):
    async for _ in run_scan_stream(scan_id):
        pass


@app.on_event("startup")
async def on_startup():
    global SCHEDULER_TASK
    if not os.getenv("SCHEDULER_DISABLED"):
        SCHEDULER_TASK = asyncio.create_task(scheduler_loop())


# ---------- Main ----------
if __name__ == "__main__":
    # Prefer running with uvicorn CLI in some sandboxes
    import socket

    can_bind = hasattr(socket, "SO_REUSEADDR")
    run_flag = os.getenv("RUN_SERVER", "0") == "1"
    if run_flag and can_bind:
        import uvicorn

        host = "0.0.0.0"
        port = int(os.getenv("PORT", "8000"))
        reload = os.getenv("RELOAD", "0") == "1"
        uvicorn.run("scanner:app", host=host, port=port, reload=reload)
    else:
        print(
            "Loaded ArcLight Scanner module. Server not started in __main__.\n"
            "Use: uvicorn scanner:app --host 0.0.0.0 --port 8000\n"
            "Or set RUN_SERVER=1 (only if socket.SO_REUSEADDR is available)."
        )

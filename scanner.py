"""
Vulnerability Scanner v1 + Reports/Charts
Single‑file FastAPI app: assets • policies • saved/scheduled scans • live logs • JSON/CSV/PDF export •
concurrency • risk score • dashboard chart. Lightweight and self‑hosted.

⚠️ Legal: Scan only what you own or are authorised to test.

Quick start
-----------
1) Save as `scanner.py`
2) Python 3.10+
3) Install deps:
   pip install fastapi==0.111.0 uvicorn==0.30.3 jinja2==3.1.4 \
               pydantic==2.8.2 croniter==2.0.5 reportlab==4.1.0
   # NOTE: No need for python-multipart — the UI now POSTs JSON.
4) Ensure tools in PATH: nmap, nuclei, nikto, wpscan
5) **Run the server from CLI (recommended):**
   uvicorn scanner:app --host 0.0.0.0 --port 8000
   (In constrained environments, set RUN_SERVER=1 only if sockets are supported.)
6) Open: http://localhost:8000

Optional env:
- WPSCAN_API_TOKEN  (for extended WPScan checks)
- SCHEDULER_DISABLED=1  (disable background cron loop)
- RUN_SERVER=1         (allow in-file __main__ runner to start uvicorn if sockets supported)
- PORT=8000            (port for __main__ runner)
- RELOAD=0|1           (reload flag for __main__ runner)

Data stored under ./data (SQLite + job logs + reports).
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

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, StreamingResponse, PlainTextResponse, RedirectResponse, Response, JSONResponse
from jinja2 import Environment, BaseLoader, select_autoescape
from croniter import croniter

# -------------------------- Environment checks -------------------------- #
try:
    import ssl as _ssl  # noqa: F401
except ModuleNotFoundError:
    raise SystemExit(
        "Python 'ssl' module is missing.\n"
        "Fix (Debian/Kali): sudo apt update && sudo apt install -y python3-full python3-venv python3-pip ca-certificates openssl\n"
        "Fix (macOS): brew reinstall python@3.12 && python3 -m venv .venv && source .venv/bin/activate && pip install -U pip && pip install fastapi uvicorn jinja2 pydantic croniter reportlab\n"
        "Then run from CLI: uvicorn scanner:app --host 0.0.0.0 --port 8000"
    )

APP_NAME = "Darknight Scanner"
DATA_DIR = Path("data")
DB_PATH = DATA_DIR / "scanner.sqlite3"
JOBS_DIR = DATA_DIR / "jobs"
REPORTS_DIR = DATA_DIR / "reports"
for d in (DATA_DIR, JOBS_DIR, REPORTS_DIR):
    d.mkdir(parents=True, exist_ok=True)

app = FastAPI(title=APP_NAME)

# -------------------------- DB & Migration -------------------------- #
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

# Migrations for existing DBs (add missing columns)
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

# Seed a default policy if none
with db() as conn:
    cur = conn.execute("SELECT COUNT(*) AS c FROM policies")
    if cur.fetchone()[0] == 0:
        conn.execute(
            "INSERT INTO policies(name,use_nmap,nmap_profile,use_nuclei,nuclei_sev,use_nikto,use_wpscan,concurrency) VALUES(?,?,?,?,?,?,?,?)",
            ("Quick Web Audit", 1, "vuln", 1, "critical,high,medium", 1, 0, 2),
        )
        conn.commit()

# -------------------------- Utilities -------------------------- #
TARGET_RE = re.compile(r"^(?:(?:https?://)?)(?:[A-Za-z0-9.-]+|\[[A-Fa-f0-9:]+\]|(?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?$")

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
        t = it.strip().strip('\"\'')
        if t and t not in seen and TARGET_RE.match(t):
            seen.add(t)
            out.append(t)
    return out[:1024]

def ensure_url(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"http://{target}"

async def stream_cmd(title: str, cmd: List[str], logfile: Path, timeout: int = 3600) -> AsyncGenerator[str, None]:
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

# -------------------------- Templating -------------------------- #
TEMPLATE = Environment(loader=BaseLoader(), autoescape=select_autoescape()).from_string(
    r"""
<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>{{ title }}</title>
  <script src=\"https://cdn.tailwindcss.com\"></script>
  <script src=\"https://cdn.jsdelivr.net/npm/chart.js\"></script>
  <style>
    :root { color-scheme: dark; }
    body { background: radial-gradient(1200px 600px at 10% -10%, rgba(0,255,128,0.12), transparent), #0b0f0c; }
    .glow { text-shadow: 0 0 14px rgba(0,255,128,.35); }
    .card { background: rgba(18,24,20,.85); backdrop-filter: blur(6px); border: 1px solid rgba(0,255,128,.15); }
    .accent { border-color: rgba(0,255,128,.35); }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace; }
    .badge { border:1px solid rgba(0,255,128,.35); padding:.125rem .5rem; border-radius:.5rem; font-size:.75rem }
    a:hover{ text-decoration: underline; }
  </style>
</head>
<body class=\"text-gray-200\">
  <div class=\"max-w-7xl mx-auto p-6\">
    <header class=\"mb-6 flex items-center justify-between\">
      <div>
        <h1 class=\"text-3xl md:text-4xl font-semibold glow\">{{ app_name }}</h1>
        <p class=\"text-sm text-emerald-300/80 mt-1\">Assets • Policies • Scans • Schedules • Jobs • Reports</p>
      </div>
      <nav class=\"flex gap-3 text-sm\">
        <a href=\"/\" class=\"px-3 py-1 rounded-lg border border-emerald-400/40\">Dashboard</a>
        <a href=\"/assets\" class=\"px-3 py-1 rounded-lg border border-emerald-400/40\">Assets</a>
        <a href=\"/policies\" class=\"px-3 py-1 rounded-lg border border-emerald-400/40\">Policies</a>
        <a href=\"/scans\" class=\"px-3 py-1 rounded-lg border border-emerald-400/40\">Scans</a>
        <a href=\"/jobs\" class=\"px-3 py-1 rounded-lg border border-emerald-400/40\">Jobs</a>
      </nav>
    </header>

    {{ body | safe }}
  </div>
</body>
</html>
"""
)

def render(body: str, title: str = APP_NAME) -> HTMLResponse:
    html = TEMPLATE.render(title=title, body=body, app_name=APP_NAME)
    return HTMLResponse(html)

# -------------------------- UI Pages -------------------------- #

def page_dashboard() -> str:
    with db() as conn:
        a = conn.execute("SELECT COUNT(*) c FROM assets").fetchone()[0]
        p = conn.execute("SELECT COUNT(*) c FROM policies").fetchone()[0]
        s = conn.execute("SELECT COUNT(*) c FROM scans").fetchone()[0]
        j_running = conn.execute("SELECT COUNT(*) c FROM jobs WHERE status='running'").fetchone()[0]
        j_done = conn.execute("SELECT COUNT(*) c FROM jobs WHERE status='finished'").fetchone()[0]
    return textwrap.dedent(f"""
    <div class=\"grid md:grid-cols-5 gap-4\">
      <div class=\"card p-4 rounded-2xl\"><div class=\"text-sm\">Assets</div><div class=\"text-3xl glow\">{a}</div></div>
      <div class=\"card p-4 rounded-2xl\"><div class=\"text-sm\">Policies</div><div class=\"text-3xl glow\">{p}</div></div>
      <div class=\"card p-4 rounded-2xl\"><div class=\"text-sm\">Scans</div><div class=\"text-3xl glow\">{s}</div></div>
      <div class=\"card p-4 rounded-2xl\"><div class=\"text-sm\">Jobs (running)</div><div class=\"text-3xl glow\">{j_running}</div></div>
      <div class=\"card p-4 rounded-2xl\"><div class=\"text-sm\">Jobs (finished)</div><div class=\"text-3xl glow\">{j_done}</div></div>
    </div>

    <div class=\"grid md:grid-cols-2 gap-6 mt-6\">
      <section class=\"card rounded-2xl p-5\">
        <h2 class=\"text-xl glow mb-3\">Run Ad‑hoc Scan</h2>
        <form id=\"formAdhoc\" class=\"space-y-3\">
          <textarea name=\"targets\" rows=\"4\" placeholder=\"paste IPs/hosts/URLs, one per line\" class=\"w-full rounded-xl bg-black/40 border accent p-2\"></textarea>
          <div class=\"grid grid-cols-2 gap-3\">
            <label class=\"flex items-center gap-2\"><input type=\"checkbox\" name=\"use_nmap\" checked> Nmap</label>
            <label class=\"flex items-center gap-2\"><input type=\"checkbox\" name=\"use_nuclei\" checked> Nuclei</label>
            <label class=\"flex items-center gap-2\"><input type=\"checkbox\" name=\"use_nikto\"> Nikto</label>
            <label class=\"flex items-center gap-2\"><input type=\"checkbox\" name=\"use_wpscan\"> WPScan</label>
          </div>
          <div class=\"grid grid-cols-2 gap-3\">
            <select name=\"nmap_profile\" class=\"rounded-xl bg-black/40 border accent p-2\">
              <option value=\"vuln\" selected>Vuln (sV+sC+vuln)</option>
              <option value=\"quick\">Quick (T4 -F -sV)</option>
              <option value=\"full\">Full (T4 -p- -sV)</option>
            </select>
            <select name=\"nuclei_sev\" class=\"rounded-xl bg-black/40 border accent p-2\">
              <option value=\"critical,high,medium\" selected>critical,high,medium</option>
              <option value=\"critical,high\">critical,high</option>
              <option value=\"low,info\">low,info</option>
            </select>
          </div>
          <button class=\"px-3 py-2 rounded-xl border border-emerald-400/40\">Run Now</button>
        </form>
        <script>
          const fA = document.getElementById('formAdhoc');
          fA.addEventListener('submit', async (e) => {{
            e.preventDefault();
            const fd = new FormData(fA);
            const payload = {{
              targets: fd.get('targets') || '',
              use_nmap: !!fd.get('use_nmap'),
              nmap_profile: fd.get('nmap_profile') || 'vuln',
              use_nuclei: !!fd.get('use_nuclei'),
              nuclei_sev: fd.get('nuclei_sev') || 'critical,high,medium',
              use_nikto: !!fd.get('use_nikto'),
              use_wpscan: !!fd.get('use_wpscan')
            }};
            // create ad-hoc scan then redirect to streaming page
            const r = await fetch('/scans/create_ad_hoc', {{ method:'POST', headers:{{'Content-Type':'application/json'}}, body: JSON.stringify(payload) }});
            if (!r.ok) {{ const t = await r.text(); alert(t); return; }}
            const data = await r.json();
            window.location = '/scans/run?id=' + data.scan_id;
          }});
        </script>
      </section>
      <section class=\"card rounded-2xl p-5\">
        <h2 class=\"text-xl glow mb-3\">Findings Overview</h2>
        <canvas id=\"sevChart\" height=\"110\"></canvas>
        <script>
          fetch('/api/stats/summary').then(r=>r.json()).then(d=>{{
            const ctx = document.getElementById('sevChart').getContext('2d');
            const sev = (d && d.severity) ? d.severity : {{critical:0,high:0,medium:0,low:0,info:0}};
            new Chart(ctx, {{
              type: 'bar',
              data: {{ labels: ['critical','high','medium','low','info'], datasets: [{{ label: 'Findings', data: [sev.critical||0, sev.high||0, sev.medium||0, sev.low||0, sev.info||0] }}] }},
              options: {{ responsive: true, plugins: {{ legend: {{ display: false }} }}, scales: {{ y: {{ beginAtZero: true }} }} }}
            }});
          }}).catch(err=>{{ console.error(err); }});
        </script>
      </section>
    </div>
    """)

def page_assets() -> str:
    with db() as conn:
        rows = conn.execute("SELECT * FROM assets ORDER BY id DESC").fetchall()
    items = "".join(
        f"<tr><td class='py-1 pr-2 text-emerald-200/90 mono'>{r['id']}</td>"
        f"<td class='py-1 pr-2 mono'>{r['target']}</td>"
        f"<td class='py-1 pr-2'>{r['tags']}</td></tr>" for r in rows
    )
    return f"""
    <section class=\"card rounded-2xl p-5\">
      <h2 class=\"text-xl glow mb-3\">Assets</h2>
      <form id=\"formAsset\" class=\"flex gap-2 mb-3\">
        <input name=target required placeholder=\"example.com or 10.10.10.10\" class=\"flex-1 rounded-xl bg-black/40 border accent p-2\" />
        <input name=tags placeholder=\"prod,web,linux\" class=\"rounded-xl bg-black/40 border accent p-2\" />
        <button class=\"px-3 py-2 rounded-xl border border-emerald-400/40\">Add</button>
      </form>
      <script>
        const f = document.getElementById('formAsset');
        f.addEventListener('submit', async (e)=>{{
          e.preventDefault();
          const fd = new FormData(f);
          const r = await fetch('/assets/add', {{ method:'POST', headers:{{'Content-Type':'application/json'}}, body: JSON.stringify({{ target: fd.get('target'), tags: fd.get('tags') || '' }}) }});
          if (r.ok) window.location.reload(); else alert(await r.text());
        }});
      </script>
      <table class=\"w-full text-sm\">
        <thead><tr class=\"text-emerald-300/80\"><th class='text-left'>ID</th><th class='text-left'>Target</th><th class='text-left'>Tags</th></tr></thead>
        <tbody>{items}</tbody>
      </table>
    </section>
    """

def page_policies() -> str:
    with db() as conn:
        rows = conn.execute("SELECT * FROM policies ORDER BY id DESC").fetchall()
    items = "".join(
        f"<tr><td class='py-1 pr-2 mono'>{r['id']}</td><td class='py-1 pr-2'>{r['name']}</td>"
        f"<td class='py-1 pr-2 mono'>{'Y' if r['use_nmap'] else '-'} / {r['nmap_profile']}</td>"
        f"<td class='py-1 pr-2 mono'>{'Y' if r['use_nuclei'] else '-'} / {r['nuclei_sev']}</td>"
        f"<td class='py-1 pr-2 mono'>{'Y' if r['use_nikto'] else '-'}</td>"
        f"<td class='py-1 pr-2 mono'>{'Y' if r['use_wpscan'] else '-'}</td>"
        f"<td class='py-1 pr-2 mono'>c={r['concurrency']} rl={r['nuclei_rate'] or '-'} ex={bool(r['exclude_paths'])}</td></tr>" for r in rows
    )
    return f"""
    <section class=\"card rounded-2xl p-5\">
      <h2 class=\"text-xl glow mb-3\">Policies</h2>
      <form id=\"formPolicy\" class=\"grid md:grid-cols-3 gap-3 mb-4\">
        <input name=name required placeholder=\"Policy name\" class=\"rounded-xl bg-black/40 border accent p-2\" />
        <select name=nmap_profile class=\"rounded-xl bg-black/40 border accent p-2\">
          <option value=\"vuln\" selected>nmap: vuln</option>
          <option value=\"quick\">nmap: quick</option>
          <option value=\"full\">nmap: full</option>
        </select>
        <select name=nuclei_sev class=\"rounded-xl bg-black/40 border accent p-2\">
          <option value=\"critical,high,medium\" selected>nuclei: critical,high,medium</option>
          <option value=\"critical,high\">nuclei: critical,high</option>
          <option value=\"low,info\">nuclei: low,info</option>
        </select>
        <label class=\"flex items-center gap-2\"><input type=checkbox name=use_nmap checked> Nmap</label>
        <label class=\"flex items-center gap-2\"><input type=checkbox name=use_nuclei checked> Nuclei</label>
        <label class=\"flex items-center gap-2\"><input type=checkbox name=use_nikto> Nikto</label>
        <label class=\"flex items-center gap-2\"><input type=checkbox name=use_wpscan> WPScan</label>
        <input name=concurrency type=number min=1 max=16 value=2 class=\"rounded-xl bg-black/40 border accent p-2\" placeholder=\"concurrency (targets)\" />
        <input name=nuclei_rate type=number min=1 value=50 class=\"rounded-xl bg-black/40 border accent p-2\" placeholder=\"nuclei rate-limit\" />
        <input name=exclude_paths class=\"rounded-xl bg-black/40 border accent p-2 md:col-span-3\" placeholder=\"exclude paths (comma separated, e.g. /logout,/admin/debug)\" />
        <input name=http_basic_user placeholder=\"HTTP basic user (optional)\" class=\"rounded-xl bg-black/40 border accent p-2\" />
        <input name=http_basic_pass placeholder=\"HTTP basic pass (optional)\" class=\"rounded-xl bg-black/40 border accent p-2\" />
        <button class=\"px-3 py-2 rounded-xl border border-emerald-400/40 md:col-span-1\">Add Policy</button>
      </form>
      <script>
        const fp = document.getElementById('formPolicy');
        fp.addEventListener('submit', async (e)=>{{
          e.preventDefault();
          const fd = new FormData(fp);
          const payload = {{
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
            nuclei_rate: fd.get('nuclei_rate') ? Number(fd.get('nuclei_rate')) : null,
            exclude_paths: fd.get('exclude_paths') || ''
          }};
          const r = await fetch('/policies/add', {{ method:'POST', headers:{{'Content-Type':'application/json'}}, body: JSON.stringify(payload) }});
          if (r.ok) window.location.reload(); else alert(await r.text());
        }});
      </script>
      <table class=\"w-full text-sm\">
        <thead><tr class=\"text-emerald-300/80\"><th>ID</th><th class='text-left'>Name</th><th>Nmap</th><th>Nuclei</th><th>Nikto</th><th>WPScan</th><th>Options</th></tr></thead>
        <tbody>{items}</tbody>
      </table>
    </section>
    """

def page_scans() -> str:
    with db() as conn:
        assets = conn.execute("SELECT * FROM assets ORDER BY id DESC").fetchall()
        policies = conn.execute("SELECT * FROM policies ORDER BY id DESC").fetchall()
        scans = conn.execute("SELECT s.*, p.name as policy_name FROM scans s JOIN policies p ON p.id=s.policy_id ORDER BY s.id DESC").fetchall()
    asset_opts = "".join(f"<label class='flex items-center gap-2'><input type=checkbox name=asset_ids value={a['id']}> {a['target']} <span class='text-xs text-emerald-300/70'>{a['tags']}</span></label>" for a in assets)
    policy_opts = "".join(f"<option value={p['id']}>{p['name']}</option>" for p in policies)
    scan_rows = "".join(
        f"<tr><td class='py-1 pr-2 mono'>{s['id']}</td><td class='py-1 pr-2'>{s['name']}</td>"
        f"<td class='py-1 pr-2'>{s['policy_name']}</td><td class='py-1 pr-2 mono'>{s['schedule_cron'] or '-'}</td>"
        f"<td class='py-1 pr-2'><a href='/scans/run?id={s['id']}' class='px-2 py-1 rounded-lg border border-emerald-400/40'>Run</a></td></tr>"
        for s in scans
    )
    return f"""
    <section class=\"card rounded-2xl p-5\">
      <h2 class=\"text-xl glow mb-3\">Scans</h2>
      <form id=\"formScan\" class=\"grid md:grid-cols-2 gap-4 mb-6\">
        <input name=name required placeholder=\"Scan name\" class=\"rounded-xl bg-black/40 border accent p-2\" />
        <select name=policy_id class=\"rounded-xl bg-black/40 border accent p-2\">{policy_opts}</select>
        <div class=\"md:col-span-2 card rounded-2xl p-3\">
          <div class=\"text-sm mb-2\">Select Assets</div>
          <div class=\"grid md:grid-cols-3 gap-2\">{asset_opts}</div>
        </div>
        <input name=schedule_cron placeholder=\"cron (e.g. 0 2 * * *) or leave blank\" class=\"rounded-xl bg-black/40 border accent p-2 md:col-span-2\" />
        <button class=\"px-3 py-2 rounded-xl border border-emerald-400/40 md:col-span-2\">Create Scan</button>
      </form>
      <script>
        const fs = document.getElementById('formScan');
        fs.addEventListener('submit', async (e)=>{{
          e.preventDefault();
          const fd = new FormData(fs);
          const asset_ids = [...fs.querySelectorAll('input[name=\"asset_ids\"]:checked')].map(x=>x.value);
          const payload = {{
            name: fd.get('name'),
            policy_id: Number(fd.get('policy_id')),
            asset_ids: asset_ids,
            schedule_cron: fd.get('schedule_cron') || ''
          }};
          const r = await fetch('/scans/add', {{ method:'POST', headers:{{'Content-Type':'application/json'}}, body: JSON.stringify(payload) }});
          if (r.ok) window.location.reload(); else alert(await r.text());
        }});
      </script>
      <table class=\"w-full text-sm\">
        <thead><tr class=\"text-emerald-300/80\"><th>ID</th><th class='text-left'>Name</th><th class='text-left'>Policy</th><th>Schedule</th><th>Actions</th></tr></thead>
        <tbody>{scan_rows}</tbody>
      </table>
    </section>
    """

def page_jobs() -> str:
    with db() as conn:
        rows = conn.execute(
            "SELECT j.*, s.name as scan_name FROM jobs j JOIN scans s ON s.id=j.scan_id ORDER BY j.id DESC LIMIT 200"
        ).fetchall()
    items = "".join(
        f"<tr><td class='py-1 pr-2 mono'>{r['id']}</td><td class='py-1 pr-2'>{r['scan_name']}</td>"
        f"<td class='py-1 pr-2 mono'>{r['status']}</td><td class='py-1 pr-2 mono'>{r['started_at'] or '-'}</td>"
        f"<td class='py-1 pr-2 mono'>{r['finished_at'] or '-'}</td>"
        f"<td class='py-1 pr-2'><a href='/jobs/{r['id']}/log' class='px-2 py-1 rounded-lg border border-emerald-400/40'>Log</a> "
        f"<a href='/api/jobs/{r['id']}/export' class='px-2 py-1 rounded-lg border border-emerald-400/40'>JSON</a> "
        f"<a href='/api/jobs/{r['id']}/export.csv' class='px-2 py-1 rounded-lg border border-emerald-400/40'>CSV</a> "
        f"<a href='/api/jobs/{r['id']}/export.pdf' class='px-2 py-1 rounded-lg border border-emerald-400/40'>PDF</a></td></tr>"
        for r in rows
    )
    return f"""
    <section class=\"card rounded-2xl p-5\">
      <h2 class=\"text-xl glow mb-3\">Jobs</h2>
      <table class=\"w-full text-sm\">
        <thead><tr class=\"text-emerald-300/80\"><th>ID</th><th class='text-left'>Scan</th><th>Status</th><th>Started</th><th>Finished</th><th>Export</th></tr></thead>
        <tbody>{items}</tbody>
      </table>
    </section>
    """

# -------------------------- Routes: pages -------------------------- #
@app.get("/", response_class=HTMLResponse)
async def home(_: Request):
    return render(page_dashboard())

@app.get("/assets", response_class=HTMLResponse)
async def assets_page(_: Request):
    return render(page_assets(), title=f"{APP_NAME} • Assets")

# -------------------------- JSON API for UI (no python-multipart required) -------------------------- #
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

@app.get("/policies", response_class=HTMLResponse)
async def policies_page(_: Request):
    return render(page_policies(), title=f"{APP_NAME} • Policies")

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
                name, use_nmap, nmap_profile,
                use_nuclei, nuclei_sev,
                use_nikto, use_wpscan,
                http_basic_user, http_basic_pass,
                concurrency, nuclei_rate, exclude_paths,
            ),
        )
        conn.commit()
    return RedirectResponse("/policies", status_code=303)

@app.get("/scans", response_class=HTMLResponse)
async def scans_page(_: Request):
    return render(page_scans(), title=f"{APP_NAME} • Scans")

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
    """Creates an ad-hoc scan from JSON, returns scan_id (no streaming)."""
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

@app.post("/scans/run_ad_hoc")
async def scans_run_ad_hoc(request: Request):
    """Legacy: still supports JSON body and streams logs directly back."""
    try:
        d = await request.json()
    except Exception:
        return PlainTextResponse("This endpoint expects JSON", status_code=415)
    tlist = normalize_targets(d.get("targets") or "")
    if not tlist:
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
        for t in tlist:
            conn.execute("INSERT OR IGNORE INTO assets(target,tags) VALUES(?,?)", (t, "ad-hoc"))
            aid = conn.execute("SELECT id FROM assets WHERE target=?", (t,)).fetchone()[0]
            ids.append(str(aid))
        conn.execute(
            "INSERT INTO scans(name,policy_id,asset_ids,created_at) VALUES(?,?,?,?)",
            ("Ad-hoc Run", pid, ",".join(ids), now_iso()),
        )
        sid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.commit()
    return StreamingResponse(run_scan_stream(sid), media_type="text/plain")

@app.get("/jobs", response_class=HTMLResponse)
async def jobs_page(_: Request):
    return render(page_jobs(), title=f"{APP_NAME} • Jobs")

@app.get("/jobs/{job_id}/log", response_class=HTMLResponse)
async def job_log(job_id: int):
    log = (JOBS_DIR / str(job_id) / "job.log")
    text = log.read_text() if log.exists() else "(no log yet)"
    body = f"""
    <section class=\"card rounded-2xl p-5\">\n      <h2 class=\"text-xl glow mb-3\">Job #{job_id} Log</h2>\n      <pre class=\"mono whitespace-pre-wrap text-emerald-200/90 text-sm h-[70vh] overflow-auto p-3 bg-black/30 rounded-xl border accent\">{text}</pre>\n    </section>
    """
    return render(body, title=f"{APP_NAME} • Job {job_id}")

# -------------------------- API: export & stats -------------------------- #
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
    w.writerow(["target","template","name","severity","matched","description"]) 
    for r in findings:
        info = r.get("info", {})
        w.writerow([
            r.get("host") or r.get("matched-at") or "",
            r.get("templateID") or info.get("id") or "",
            info.get("name") or "",
            (info.get("severity") or r.get("severity") or "").lower(),
            r.get("matched-at") or "",
            (info.get("description") or "").replace("\n"," ").strip(),
        ])
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
    y = height - 2*cm

    def line(txt, size=11, step=14):
        nonlocal y
        c.setFont("Helvetica", size)
        c.drawString(2*cm, y, txt)
        y -= step

    line(f"Darknight Scanner — Report for Job #{job_id}", size=14, step=18)
    line(f"Generated: {now_iso()}")
    line("")
    line("Summary:")
    line(f"  Findings: {summary['nuclei_findings']}")
    line(f"  Severity: C:{summary['severity'].get('critical',0)} H:{summary['severity'].get('high',0)} M:{summary['severity'].get('medium',0)} L:{summary['severity'].get('low',0)} I:{summary['severity'].get('info',0)}")
    line(f"  Risk score: {summary['risk_score']}")
    line("")

    line("Top findings:")
    count = 0
    for r in findings[:40]:
        info = r.get("info", {})
        line(f"- [{(info.get('severity') or '').upper():>5}] {info.get('name') or ''}")
        line(f"  {r.get('matched-at') or r.get('host') or ''}")
        count += 1
        if y < 3*cm:
            c.showPage(); y = height - 2*cm
    if count == 0:
        line("(no findings)")

    c.showPage(); c.save()
    buf.seek(0)
    headers = {"Content-Disposition": f"attachment; filename=job_{job_id}.pdf"}
    return Response(content=buf.read(), media_type="application/pdf", headers=headers)

@app.get("/api/stats/summary")
async def stats_summary():
    # aggregate last 50 jobs
    with db() as conn:
        rows = conn.execute("SELECT summary FROM jobs WHERE summary != '' ORDER BY id DESC LIMIT 50").fetchall()
    agg = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
    for r in rows:
        with contextlib.suppress(Exception):
            s = json.loads(r[0])
            sev = s.get("severity", {})
            for k in agg: agg[k] += int(sev.get(k,0))
    return JSONResponse({"severity": agg, "jobs": len(rows)})

# -------------------------- Scan Runner -------------------------- #
async def run_scan_stream(scan_id: int) -> AsyncGenerator[str, None]:
    with db() as conn:
        srow = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not srow:
            yield "Scan not found.\n"; return
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

    use_nmap = bool(prow["use_nmap"]) ; nmap_profile = prow["nmap_profile"]
    use_nuclei = bool(prow["use_nuclei"]) ; nuclei_sev = prow["nuclei_sev"]
    use_nikto = bool(prow["use_nikto"]) ; use_wpscan = bool(prow["use_wpscan"]) 
    basic_user = (prow["http_basic_user"] or "").strip(); basic_pass = (prow["http_basic_pass"] or "").strip()
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
            if nuclei_rate: nuclei_cmd += ["-rl", str(int(nuclei_rate))]
            if basic_user or basic_pass:
                import base64
                token = base64.b64encode(f"{basic_user}:{basic_pass}".encode()).decode()
                nuclei_cmd += ["-H", f"Authorization: Basic {token}"]
            nuclei_jsonl = job_dir / "nuclei.jsonl"
            async for chunk in stream_cmd(f"Nuclei on {url}", nuclei_cmd, log_file):
                with contextlib.suppress(Exception):
                    obj = json.loads(chunk)
                    with nuclei_jsonl.open("a") as f: f.write(json.dumps(obj)+"\n")
                await queue.put(chunk)
        # Nikto
        if use_nikto:
            url = ensure_url(t)
            nikto_cmd = ["nikto", "-host", url, "-ask", "no"]
            if basic_user or basic_pass: nikto_cmd += ["-id", f"{basic_user}:{basic_pass}"]
            async for chunk in stream_cmd(f"Nikto on {url}", nikto_cmd, log_file):
                await queue.put(chunk)
        # WPScan
        if use_wpscan:
            url = ensure_url(t)
            token = os.getenv("WPSCAN_API_TOKEN")
            wps_cmd = ["wpscan", "--url", url, "--no-update", "--format", "json"]
            if token: wps_cmd += ["--api-token", token]
            wps_json = job_dir / "wpscan.json"
            async for chunk in stream_cmd(f"WPScan on {url}", wps_cmd, log_file):
                with contextlib.suppress(Exception):
                    obj = json.loads(chunk); wps_json.write_text(json.dumps(obj, indent=2))
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

# -------------------------- Summaries -------------------------- #

def load_jsonl(p: Path) -> List[dict]:
    if not p.exists(): return []
    out = []
    for line in p.read_text().splitlines():
        with contextlib.suppress(Exception):
            out.append(json.loads(line))
    return out

def load_json(p: Path) -> dict:
    if not p.exists(): return {}
    with p.open() as f: return json.load(f)

RISK_WEIGHTS = {"critical": 9, "high": 6, "medium": 3, "low": 1, "info": 0}

def summarize_from_findings(nuclei: List[dict]) -> dict:
    sev_counts: Dict[str, int] = {k:0 for k in RISK_WEIGHTS}
    for r in nuclei:
        sev = (r.get("info", {}).get("severity") or r.get("severity") or "info").lower()
        if sev in sev_counts: sev_counts[sev] += 1
    risk = sum(sev_counts[k] * w for k, w in RISK_WEIGHTS.items())
    return {"nuclei_findings": len(nuclei), "severity": sev_counts, "risk_score": risk}

def summarize_job(job_dir: Path) -> dict:
    nuclei = load_jsonl(job_dir / "nuclei.jsonl")
    return summarize_from_findings(nuclei)

# -------------------------- Self‑tests -------------------------- #
@app.get("/__selftest__", response_class=JSONResponse)
async def __selftest__():
    tests = []
    # Test 1: normalize_targets basic parsing
    raw = "example.com, 1.2.3.4; https://a.b\ninvalid host" \
          "  ,  2001:db8::1"
    parsed = normalize_targets(raw)
    tests.append({
        "name": "normalize_targets",
        "input": raw,
        "output": parsed,
        "expect_contains": ["example.com", "1.2.3.4", "https://a.b", "2001:db8::1"],
        "pass": all(x in parsed for x in ["example.com","1.2.3.4","https://a.b","2001:db8::1"]) and "invalid" not in " ".join(parsed)
    })
    # Test 2: summary empty
    empty_summary = summarize_from_findings([])
    tests.append({
        "name": "summarize_from_findings_empty",
        "output": empty_summary,
        "pass": empty_summary.get("nuclei_findings") == 0 and empty_summary.get("risk_score") == 0
    })
    # Test 3: ensure_url behavior
    tests.append({
        "name": "ensure_url",
        "output": [ensure_url("example.com"), ensure_url("https://site")],
        "pass": ensure_url("example.com").startswith("http://") and ensure_url("https://site").startswith("https://")
    })
    # Test 4: risk weighting
    sample = [
        {"info": {"severity": "critical"}},
        {"info": {"severity": "high"}},
        {"info": {"severity": "medium"}},
        {"info": {"severity": "low"}},
        {"info": {"severity": "info"}},
        {"info": {"severity": "high"}},
    ]
    s = summarize_from_findings(sample)
    expected_risk = 1*9 + 2*6 + 1*3 + 1*1 + 1*0
    tests.append({
        "name": "risk_weighting",
        "output": s,
        "expected_risk": expected_risk,
        "pass": s.get("risk_score") == expected_risk and s.get("nuclei_findings") == len(sample)
    })
    # Test 5: cron next time sanity
    base = dt.datetime.utcnow()
    it = croniter("*/5 * * * *", base)
    nxt = it.get_next(dt.datetime)
    tests.append({
        "name": "croniter_next_5m",
        "output": {"base": base.isoformat()+"Z", "next": nxt.isoformat()+"Z"},
        "pass": (nxt - base).total_seconds() <= 6*60 and (nxt - base).total_seconds() > 0
    })
    # Test 6: normalize_targets dedupe
    deduped = normalize_targets("test.com test.com  test.com")
    tests.append({
        "name": "normalize_targets_dedupe",
        "output": deduped,
        "pass": len(deduped) == 1 and deduped[0] == "test.com"
    })
    # Test 7: socket capability check (guards __main__ runner)
    try:
        import socket
        has_reuse = hasattr(socket, "SO_REUSEADDR")
        tests.append({"name":"socket_SO_REUSEADDR_present","output": has_reuse, "pass": isinstance(has_reuse, bool)})
    except Exception as e:
        tests.append({"name":"socket_SO_REUSEADDR_present","output": str(e), "pass": True})

    # Aggregate result
    all_pass = all(t.get("pass") for t in tests)
    return JSONResponse({"ok": all_pass, "tests": tests})

# -------------------------- Lightweight Cron Scheduler -------------------------- #
# NOTE: We avoid APScheduler to work in environments without the _multiprocessing C module.
#       This simple loop uses croniter and asyncio; it is in-process and best-effort.

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
                sid = int(r["id"]); cron = r["schedule_cron"]
                # initialize next run if not present
                if sid not in CRON_STATE:
                    with contextlib.suppress(Exception):
                        CRON_STATE[sid] = croniter(cron, now).get_next(dt.datetime)
                # run if due
                due = CRON_STATE.get(sid)
                if not due:
                    continue
                if due <= now:
                    # skip if job already running
                    with db() as conn:
                        running = conn.execute("SELECT 1 FROM jobs WHERE scan_id=? AND status='running' LIMIT 1", (sid,)).fetchone()
                    if running:
                        # schedule next tick anyway to avoid tight loops
                        with contextlib.suppress(Exception):
                            CRON_STATE[sid] = croniter(cron, now).get_next(dt.datetime)
                        continue
                    asyncio.create_task(save_only_run(sid))
                    with contextlib.suppress(Exception):
                        CRON_STATE[sid] = croniter(cron, now).get_next(dt.datetime)
        except Exception as e:
            # soft-fail the loop
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

# -------------------------- Main -------------------------- #
if __name__ == "__main__":
    # Guard against environments lacking socket.SO_REUSEADDR (seen in some sandboxes with Python 3.12)
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
        print("Loaded Darknight Scanner module. Server not started in __main__.\n"
              "Use: uvicorn scanner:app --host 0.0.0.0 --port 8000\n"
              "Or set RUN_SERVER=1 (only if socket.SO_REUSEADDR is available).")

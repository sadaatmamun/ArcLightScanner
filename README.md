# Darknight Vulnerability Scanner v2

Nessus‑style, single‑file **FastAPI** web app for light vulnerability assessments. Paste IPs/hosts/URLs, pick tools, stream results, and export reports.

> ⚠️ **Legal**: Only scan systems you own or are explicitly authorized to test.

---

## Features

- **Ad‑hoc scans** from the dashboard (paste targets; click Run).
- **Assets / Policies / Saved scans** with optional cron‑style **scheduling**.
- **Multi‑tool pipeline**: Nmap, Nuclei, Nikto, WPScan (optional API token).
- **Live logs** (server‑sent text stream) + **job history**.
- **Findings summary** with severity chart.
- **Exports**: JSON, CSV, and pretty **PDF** report.
- **SQLite** storage under `./data` (WAL enabled)
- **No multipart dependency**: frontend posts JSON only (works in constrained envs).

---

## Requirements

- **Python** 3.10+
- **System tools** in PATH: `nmap`, `nuclei`, `nikto`, `wpscan` (optional)
- OS: Linux/macOS/WSL recommended

### Install system tools (examples)

**Debian/Ubuntu/Kali**

```bash
sudo apt update
sudo apt install -y nmap nikto
# Nuclei
curl -L https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_*_linux_amd64.zip -o nuclei.zip \
  && unzip nuclei.zip -d /tmp && sudo mv /tmp/nuclei /usr/local/bin/
# WPScan (optional)
sudo gem install wpscan || true
```

**macOS (Homebrew)**

```bash
brew install nmap nikto nuclei
brew install ruby && gem install wpscan   # optional
```

---

## Project layout

```
.
├── scanner.py            # The app (single file)
├── requirements.txt      # Python deps (create from below)
└── data/                 # SQLite, jobs, reports (auto-created)
```

**requirements.txt**

```
fastapi==0.111.0
uvicorn==0.30.3
jinja2==3.1.4
pydantic==2.8.2
croniter==2.0.5
reportlab==4.1.0
```

---

## Run locally (step‑by‑step)

1. **Clone** your repo and enter it

```bash
git clone https://github.com/<you>/<repo>.git
cd <repo>
```

2. **Add files**
   - Put `scanner.py` at the repo root.
   - Create `requirements.txt` using the block above.
3. **Create a venv & install deps**

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -U pip wheel
pip install -r requirements.txt
```

4. **(Optional) Configure env**

```bash
# Enable WPScan API if you have a token
export WPSCAN_API_TOKEN=your_token_here
# Disable scheduler if you don’t want background cron checks yet
export SCHEDULER_DISABLED=1
```

5. **Start the server** (recommended way)

```bash
uvicorn scanner:app --host 0.0.0.0 --port 8000
```

> If your environment complains about sockets, start from the CLI as above. The `__main__` runner is guarded and won’t auto‑start unless `RUN_SERVER=1` **and** the OS exposes `socket.SO_REUSEADDR`.

6. Open the UI: [http://localhost:8000](http://localhost:8000)

---

## Using the app

### 1) Ad‑hoc scan (dashboard)

- Paste one target per line (e.g., `example.com`, `10.10.10.10`, `https://site`) and click **Run Now**.
- You’ll be redirected to a **streaming log** page for that job.

### 2) Assets / Policies / Scans

- **Assets**: Add reusable targets and tags.
- **Policies**: Choose tools, Nmap profile, Nuclei severities, concurrency, optional HTTP Basic, etc.
- **Scans**: Name it, choose a policy, select assets, and optionally set a **cron** expression (e.g., `0 2 * * *`).

### 3) Jobs & reports

- Go to **Jobs** → open **Log** to view the full transcript.
- Export: **JSON**, **CSV**, or **PDF** via the buttons per job.
- Dashboard shows an aggregate **severity chart** of recent jobs.

---

## API quickstart

> All endpoints expect **JSON** bodies (no form/multipart).

**Create an ad‑hoc scan and get **``**:**

```bash
curl -s -X POST http://localhost:8000/scans/create_ad_hoc \
  -H 'Content-Type: application/json' \
  -d '{
        "targets": "example.com\n1.2.3.4",
        "use_nmap": true,
        "nmap_profile": "vuln",
        "use_nuclei": true,
        "nuclei_sev": "critical,high,medium",
        "use_nikto": false,
        "use_wpscan": false
      }'
```

**Stream a saved scan**

```bash
curl -N "http://localhost:8000/scans/run?id=<scan_id>"
```

**Self‑test**

```bash
curl http://localhost:8000/__selftest__ | jq
```

**Export CSV/PDF**

```bash
curl -OJ http://localhost:8000/api/jobs/<job_id>/export.csv
curl -OJ http://localhost:8000/api/jobs/<job_id>/export.pdf
```

---

## Configuration

Env vars:

- `WPSCAN_API_TOKEN` – enables extra WPScan checks.
- `SCHEDULER_DISABLED=1` – turn off the background scheduler.
- `RUN_SERVER=1` – allow `python scanner.py` to start uvicorn **only if** `socket.SO_REUSEADDR` exists.
- `PORT` / `RELOAD` – used by the optional `__main__` runner.

Data locations:

- SQLite DB: `./data/scanner.sqlite3`
- Job logs: `./data/jobs/<job_id>/job.log`
- Findings: `./data/jobs/<job_id>/nuclei.jsonl`
- WPScan JSON: `./data/jobs/<job_id>/wpscan.json`

---

## Scheduling scans

When creating a scan, provide **cron** in the input (e.g., `0 3 * * *`). The lightweight scheduler checks every \~30s and fires scans when due.

> This in‑process scheduler avoids `apscheduler` so it works in environments missing Python’s `_multiprocessing` module.

---

## Troubleshooting

- `` – Your client sent form/multipart. Use `Content-Type: application/json`.
- `` – Install the tool and ensure it’s in `PATH`.
- `` – Some sandboxes lack this flag. Start with the **CLI** `uvicorn scanner:app ...` rather than `python scanner.py`, or run on a normal OS/WSL.
- `` – Not applicable here; the app avoids `Form(...)`. If you wrote custom routes using forms, switch to JSON.
- `` – Install a full Python build (system OpenSSL). See the error message at startup for distro‑specific commands.

---

## Security notes

- Default concurrency is conservative. Be mindful of rate limits and impact on targets.
- Honor robots/legal terms. Obtain written permission for every target.
- Findings depend on third‑party tools and templates; validate before remediation.

---

## Roadmap / Ideas

- Auth + RBAC
- Org/workspace multi‑tenant mode
- S3/GCS artifact storage
- HTML report with charts

---

## License

Choose a license (e.g., MIT/Apache‑2.0) and add `LICENSE` at repo root.

---

## Contributing

PRs welcome! Please:

1. Run `curl http://localhost:8000/__selftest__` and ensure `ok: true`.
2. Add tests for new helpers.
3. Keep the zero‑install JSON POST approach (no `python-multipart`).


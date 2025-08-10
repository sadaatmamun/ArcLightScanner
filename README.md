# ArcLight Scanner

ArcLight Scanner is a sleek, single-file vulnerability scanner with a modern web UI, a live **terminal-style** log popup, and built-in report exports.

> ⚠️ Use only on systems you **own** or have **explicit permission** to test.

---

## Features & Benefits

- **All-in-one UI**: Assets, Policies, Templates, Saved Scans, Jobs  
- **Live terminal popup**: click **Run Now** to stream scan logs in real time  
- **Charts**: severity distribution & jobs throughput  
- **Exports**: one click to **JSON / CSV / PDF**  
- **Works with your tools**: `nmap`, `nuclei`, `nikto`, `wpscan`  
- **Lightweight scheduling**: cron-style strings (no heavy background service)  
- **Single file**: easy to audit, fork, and customize

---

## Install

### 1) System tools (recommended)

**Kali / Debian / Ubuntu**
```bash
sudo apt update
sudo apt install -y nmap nuclei nikto wpscan
```

**macOS (Homebrew)**
```bash
brew install nmap nuclei nikto wpscan
```

> Optional for WPScan:
> ```bash
> export WPSCAN_API_TOKEN=your_token
> ```

### 2) Python deps

```bash
python3 -m pip install --upgrade pip
pip install -r requirements.txt
```

`requirements.txt`:
```txt
fastapi==0.111.0
uvicorn[standard]==0.30.3
jinja2==3.1.4
pydantic==2.8.2
croniter==2.0.5
reportlab==4.1.0
```

---

## Run

```bash
uvicorn arclight:app --host 0.0.0.0 --port 8000
```

Open: **http://127.0.0.1:8000**

> If you run behind a server/VM, allow the port in your firewall/security group.

---

## How to Use

### Dashboard
- Paste targets (one per line): hostnames, IPs, or URLs.  
  Example:
  
  <img width="1286" height="840" alt="Screenshot 2025-08-10 at 7 03 22 PM" src="https://github.com/user-attachments/assets/69f42782-552c-4032-9800-268670e09513" />

- Pick tools (Nmap/Nuclei/Nikto/WPScan) and options.
- Click **Run Now** → a **terminal popup** opens and streams `/scans/run?id=…`.

### Templates
- Library of curated presets (e.g., Discovery, Web App).
- Click a card → paste targets → **Run Now** (terminal popup streams live).

### Assets / Policies
- **Assets**: manage targets (with tags).
- **Policies**: decide which tools to run, nuclei severities, rate limit, basic auth, concurrency.

### Scans / Jobs
- **Scans**: saved scan definitions (optional cron schedule).
- **Jobs**: history of runs, status, and exports:
  - JSON: full job + findings
  - CSV: spreadsheet-friendly nuclei results
  - PDF: compact executive report

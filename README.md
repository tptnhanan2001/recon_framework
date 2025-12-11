# 🔍 Recon Framework

Streamlined recon pipeline for bug bounty and offensive security teams. A single Python orchestrator plus a modern web dashboard so you can run scans, review artifacts, and export findings without hopping between tools.

---

## TL;DR

| Task | Command |
| --- | --- |
| Install deps | `pip install -r requirements.txt` |
| Check toolchain | `python check_tools.py` |
| Run CLI scan | `python recon_tool.py -d example.com` |
| Start dashboard | `python web/api_server.py` -> http://localhost:5000 |

Default UI password: `recontool@` (override with `RECON_UI_PASSWORD`).

---

## Dashboard
<img width="1286" height="638" alt="image" src="https://github.com/user-attachments/assets/8cf71480-56b2-45b3-b0d4-23de11afd7ef" />

## Output scan
<img width="1287" height="636" alt="image" src="https://github.com/user-attachments/assets/025d8e53-ace8-443e-8eaf-ccdf465350dd" />

## Highlights

- **Full recon stack**: Subfinder, Amass, Httpx, Dirsearch, Katana, URLFinder, Waybackurls, Waymore, Nuclei, Cloudenum.
- **Smart workflow**: alive filtering, parallel stages, resumable runs, graceful stop files.
- **Web UI upgrades**: severity-colored nuclei viewer, keyword search for every file, download-ready viewer, config editor with backup/restore.
- **Clean storage**: results under `recon_output/`, API/server logs in `scan_logs/`, uploads isolated in `uploads/`.

---

## Repo Map

```
recon_framework/
├── recon_tool.py        # Main CLI orchestrator
├── web/                 # Dashboard (index.html, app.js, api_server.py)
├── tools/               # BaseTool + integrations (httpx.py, nuclei.py, etc.)
├── db/wordlists/        # Payload sets
├── recon_output/        # Generated target data
├── scan_logs/           # API + runtime logs
├── uploads/             # Temporary file uploads
├── settings.py          # Central config toggles
└── requirements.txt     # Python deps
```

---

## Quick Start

1. **Install & verify**
   ```bash
   pip install -r requirements.txt
   python check_tools.py
   ```
2. **CLI scan**
   ```bash
   python recon_tool.py -d example.com
   python recon_tool.py -dL domains.txt   # list mode
   ```
3. **Web dashboard**
   ```bash
   python web/api_server.py
   # open http://localhost:5000 and log in with recontool@
   ```

---

## Workflow Snapshot

1. Subdomain discovery (Subfinder, Amass, Sublist3r).
2. Alive verification (Httpx) -> `subdomain_alive_*`.
3. Parallel stage:
   - Nuclei against alive targets.
   - Dirsearch, Katana, URLFinder, Waybackurls, Waymore for content discovery.
4. Optional cloud/exposure checks (Cloudenum, custom tasks).
5. Results + logs written to `recon_output/<target>/`.

Tune concurrency, enable/disable tools, or change paths inside `settings.py`.

---

## Web UI Cheatsheet

- **Targets tab**: list/download/delete scans, jump to Output Viewer.
- **Output Viewer**: nuclei severity chips, keyword search, inline downloads.
- **Config tab**: live `settings.py` editor with syntax feedback & backup restore.
- **Logs tab**: browse recent API/server logs directly in the browser.

Reset session by removing `.auth_session.json`.

---

## Customization & Troubleshooting

- Add tools under `tools/your_tool.py` (inherit `BaseTool`), register in `settings.py`, then plug into `recon_tool.py`.
- Keep wordlists or payloads in `db/wordlists/` and reference them via config.

| Symptom | Fix |
| --- | --- |
| Missing binary | Re-run `python check_tools.py` and follow install hint. |
| Web UI 401 | Delete `.auth_session.json`, restart `web/api_server.py`. |
| Empty nuclei output | Ensure `subdomain_alive_*` exists, run `nuclei -update-templates`. |
| Port already in use | Set `FLASK_RUN_PORT` or edit `web/api_server.py`. |

---

MIT licensed. Happy hunting! 🕵️‍♂️


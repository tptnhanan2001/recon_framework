# Quick Start Guide

## Fast install

### 1. Install the tools (Linux/Mac)

```bash
# Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/pingc0y/URLFinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/tomnomnom/waybackurls@latest

# FFUF
go install github.com/ffuf/ffuf/v2@latest

# Python tools
pip3 install waymore cloudenum

# Dirsearch
git clone https://github.com/maurosoria/dirsearch.git
cd dirsearch && pip3 install -r requirements.txt

# Update Nuclei templates
nuclei -update-templates
```

### 2. Verify the installation

```bash
python3 check_tools.py
```

### 3. Run the workflow

```bash
# Scan a single domain
python3 recon_tool.py -d example.com

# Scan multiple domains
python3 recon_tool.py -dL domains.txt
```

## Output structure

After the run completes, results are saved inside `recon_output/`:

- **subfinder_*.txt** — every discovered subdomain
- **httpx_alive_*.txt** — alive domains
- **ffuf/**, **dirsearch_*.txt** — content discovery output
- **katana_*.txt** — endpoints from crawling
- **urlfinder_*.txt**, **waybackurls_*.txt**, **waymore/** — URLs from Wayback sources
- **cloudenum_*.txt** — cloud resources
- **nuclei/** — vulnerability scan results

## Notes

- The run can take 30 minutes to several hours depending on scope
- Only test domains you are authorized to target
- Tail the log file to follow progress


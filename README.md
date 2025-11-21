# Recon Tool - Automated Reconnaissance Tool

Automates the reconnaissance workflow for bug bounty and penetration testing.

## Architecture

The tool follows a modular architecture:
- Every utility lives in its own module inside `tools/`
- All modules run sequentially (single core) to avoid resource conflicts
- Easy to extend and maintain

## Features

This project automates the following steps:

1. **Subdomain enumeration** — uses `subfinder`
2. **Alive host verification** — uses `httpx`
   - Automatically filters and saves responsive subdomains
   - Only alive subdomains are passed to the following steps
3. **Content discovery** — runs multiple tools (only on alive subdomains):
   - `ffuf` — web fuzzer
   - `dirsearch` — directory enumeration
   - `katana` — web crawler
   - `urlfinder` — URL finder
   - `waybackurls` — Wayback Machine URL extractor
   - `waymore` — enhanced Wayback URL extractor
4. **Cloud enumeration** — uses `cloudenum`
5. **Vulnerability scanning** — uses `nuclei`

## Requirements

### Install the external tools

#### Go tools (via `go install`)

```bash
# Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Katana
go install github.com/projectdiscovery/katana/cmd/katana@latest

# URLFinder
go install github.com/pingc0y/URLFinder@latest

# Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

#### FFUF

```bash
# Linux
go install github.com/ffuf/ffuf/v2@latest

# Or download a binary: https://github.com/ffuf/ffuf/releases
```

#### Dirsearch

```bash
git clone https://github.com/maurosoria/dirsearch.git
cd dirsearch
pip3 install -r requirements.txt
```

#### Waybackurls

```bash
go install github.com/tomnomnom/waybackurls@latest
```

#### Waymore

```bash
pip3 install waymore
```

#### Cloudenum

```bash
pip3 install cloudenum
```

### Python requirements

```bash
pip3 install -r requirements.txt
```

## Tool check

Verify that every dependency is installed before running:

```bash
python3 check_tools.py
```

## Usage

### Scan a single domain

```bash
python3 recon_tool.py -d example.com
```

### Scan multiple domains from a file

```bash
python3 recon_tool.py -dL domains.txt
```

### Specify a custom output directory

```bash
python3 recon_tool.py -d example.com -o custom_output
```

### On Windows

```bash
python recon_tool.py -d example.com
```

## Code structure

```
.
├── recon_tool.py          # Main orchestrator (runs sequentially)
├── tools/                 # Individual tool modules
│   ├── __init__.py
│   ├── base.py            # Base class for all tools
│   ├── subfinder.py       # Subdomain discovery
│   ├── httpx.py           # Alive checker
│   ├── ffuf.py            # Web fuzzer
│   ├── dirsearch.py       # Directory enumeration
│   ├── katana.py          # Web crawler
│   ├── urlfinder.py       # URL finder
│   ├── waybackurls.py     # Wayback URL extractor
│   ├── waymore.py         # Enhanced Wayback extractor
│   ├── cloudenum.py       # Cloud enumeration
│   └── nuclei.py          # Vulnerability scanner
├── check_tools.py         # Dependency checker
└── README.md
```

## Output layout

All results are saved under `recon_output` (or the directory you pass via `-o`):

```
recon_output/
├── subfinder_<domain>.txt                    # All discovered subdomains
├── httpx_alive_<domain>.txt                  # Full list of alive domains
├── subdomain_alive_<domain>.txt              # Filtered list of alive subdomains
├── urls_<domain>.txt                         # URLs extracted from httpx (alive only)
│
├── ffuf/                                     # FFUF results
│   └── ffuf_<domain>.txt
│
├── dirsearch_<domain>.txt                    # Dirsearch output
├── katana_<domain>.txt                       # Katana crawling
├── urlfinder_<domain>.txt                    # URLFinder output
├── waybackurls_<domain>.txt                  # Waybackurls output
│
├── waymore/                                  # Waymore results
│   └── waymore_<domain>.txt
│
├── cloudenum_<domain>.txt                    # Cloud enumeration
│
├── nuclei/                                   # Nuclei scan results
│   ├── nuclei_alive_<domain>.txt
│   ├── nuclei_subdomains_<domain>.txt
│   └── nuclei_exposures_<domain>.txt
│
└── recon_<timestamp>.log                     # Log file
```

## Alive subdomain filtering

Alive filtering happens automatically after the httpx stage:

1. **Subfinder** finds all subdomains → `subfinder_<domain>.txt`
2. **Httpx** checks which subdomains respond → `httpx_alive_<domain>.txt`
3. **Automatic filtering** creates `subdomain_alive_<domain>.txt`
4. **Only alive subdomains** are used for:
   - Content discovery (ffuf, dirsearch, katana, etc.)
   - Cloud enumeration
   - Nuclei scanning

Benefits:
- Saves time (skip dead domains)
- Focuses on targets that are actually online
- Reduces false positives

## Notes

1. **Runtime**: The workflow can take a long time depending on the number of subdomains and URLs.
2. **Rate limiting**: Default rate limits are set inside each tool module.
3. **Wordlists**: FFUF expects a wordlist, by default:
   - `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
   - `/usr/share/wordlists/dirb/common.txt`
   - Adjust the code to point to different lists if needed.
4. **Permissions**: Make sure you can execute every binary and write to the output directory.
5. **Legal**: Only run the tool against assets you are authorized to test.

## Customization

Tune parameters inside each module:

### Inside `tools/*.py`
- Threads and rate limits
- Number of URLs/domains processed (`max_urls`, `max_domains`)
- Wordlist paths for FFUF (`tools/ffuf.py`)
- Specific Nuclei templates (`tools/nuclei.py`)
- Amass modes (passive/active/bruteforce) inside `tools/amass.py`

### Add a new tool
1. Create a new file in `tools/` (e.g., `tools/newtool.py`)
2. Inherit from `BaseTool`
3. Implement the `run()` method
4. Import it and wire it up in `recon_tool.py`

## Troubleshooting

### "command not found"
- Make sure every binary is installed and on `PATH`
- Test each command manually
- Run `check_tools.py`

### "permission denied"
- Verify write permissions inside the output directory
- On Linux/Mac you might need `chmod +x recon_tool.py`

### Missing wordlist
- Install the required wordlists or update the paths in code
- Suggested source: https://github.com/danielmiessler/SecLists

### The run takes too long
- The tool limits how many URLs/domains are processed
- Adjust the limits in code (look for `[:5]` or `[:10]`)

## License

MIT License — free to use for research and legitimate bug bounty work.


# 🔍 Recon Framework

> **Automated Reconnaissance Framework for Bug Bounty & Penetration Testing**

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)]()

A comprehensive, modular reconnaissance framework that automates the entire recon workflow from subdomain discovery to vulnerability scanning. Features a **Streamlit web interface** for easy management and visualization, plus flexible scan modes and configuration options.

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
  - [Command Line](#command-line)
  - [Web Interface](#web-interface)
- [Scan Modes](#-scan-modes)
- [Workflow](#-workflow)
- [Project Structure](#-project-structure)
- [Output Structure](#-output-structure)
- [Configuration](#-configuration)
- [Customization](#-customization)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

### Core Capabilities

- 🔎 **Multi-Tool Subdomain Discovery** - Subfinder, Amass, Sublist3r
- ✅ **Alive Host Verification** - Automatic filtering of responsive targets
- 📂 **Content Discovery** - Multi-tool directory and file enumeration
- 🕷️ **Web Crawling** - Katana for endpoint discovery
- 🔗 **URL Discovery** - URLFinder, Waybackurls, Waymore
- ☁️ **Cloud Enumeration** - AWS, Azure, GCP resource discovery
- 🎯 **Vulnerability Scanning** - Automated Nuclei scanning

### Advanced Features

- 🌐 **Streamlit Web UI** - Visual dashboard for scan management
- 🎛️ **Scan Modes** - Quick (Mode 1) or Full (Mode 2) scans
- 🎨 **Colored Output** - Beautiful terminal output with colorama
- ⏸️ **Graceful Shutdown** - Stop scans safely with Ctrl+C or stop file
- ⚙️ **Flexible Configuration** - Customize tool parameters via `settings.py`
- 📊 **Comprehensive Logging** - Detailed logs for every step
- 🔧 **Modular Architecture** - Easy to extend with new tools

---

## 🏗️ Architecture

The framework follows a clean, modular design:

```
┌─────────────────────────────────────────┐
│      recon_tool.py                      │
│   (Main Orchestrator)                   │
│   - Mode management                     │
│   - Tool coordination                   │
│   - Graceful shutdown                   │
└──────────────┬──────────────────────────┘
               │
       ┌───────┴────────┐
       │                │
   ┌───▼───┐      ┌─────▼─────┐
   │ Tools │      │  Output   │
   │ Module│      │ Directory  │
   └───┬───┘      └────────────┘
       │
   ┌───┴──────────────────────┐
   │  BaseTool (Abstract)     │
   │  - run_command()         │
   │  - check_input_file()   │
   └───┬──────────────────────┘
       │
   ┌───┴──────────────────────┐
   │  Individual Tools         │
   │  - Subfinder, Amass       │
   │  - Sublist3r, Httpx       │
   │  - Dirsearch, Katana      │
   │  - URLFinder, etc.        │
   └───────────────────────────┘
```

**Design Principles:**
- ✅ Each tool is self-contained in its own module
- ✅ All tools inherit from `BaseTool` for consistency
- ✅ Sequential execution prevents resource conflicts
- ✅ Easy to add, remove, or modify tools

---

## 📦 Installation

### Prerequisites

- Python 3.7+
- Go 1.19+ (for Go-based tools)
- Git

### Step 1: Clone the Repository

```bash
git clone https://github.com/tptnhanan2001/recon_framework.git
cd recon_framework
```

### Step 2: Install Python Dependencies

```bash
pip3 install -r requirements.txt
```

### Step 3: Install External Tools

#### Go Tools

```bash
# Subdomain Discovery
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# HTTP Probe
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Web Crawler
go install github.com/projectdiscovery/katana/cmd/katana@latest

# URL Finder
go install github.com/pingc0y/URLFinder@latest

# Vulnerability Scanner
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates

# Wayback URLs
go install github.com/tomnomnom/waybackurls@latest
```

#### Python Tools

```bash
# Dirsearch
git clone https://github.com/maurosoria/dirsearch.git
cd dirsearch && pip3 install -r requirements.txt && cd ..

# Waymore
pip3 install waymore

# Cloudenum
pip3 install cloudenum
```

#### Additional Subdomain Tools

```bash
# Amass (optional but recommended)
go install -v github.com/owasp-amass/amass/v4/...@master

# Sublist3r (optional)
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r && pip3 install -r requirements.txt && cd ..
```

### Step 4: Verify Installation

```bash
python3 check_tools.py
```

All tools should show ✓ (checkmark) if installed correctly.

---

## 🚀 Quick Start

### Command Line

```bash
# Quick scan (Mode 1: Subdomain + Nuclei only)
python3 recon_tool.py -d example.com --mode 1

# Full scan (Mode 2: All tools - default)
python3 recon_tool.py -d example.com

# Multiple domains
python3 recon_tool.py -dL domains.txt
```

### Web Interface

```bash
# Start Streamlit web UI
streamlit run stream_app.py

# Access at http://localhost:8501
# Default password: recontool@
```

---

## 📖 Usage

### Command Line

#### Basic Options

```bash
python3 recon_tool.py [OPTIONS]

Required (one of):
  -d, --domain DOMAIN        Single domain to scan
  -dL, --domain-list FILE    File containing list of domains

Optional:
  -o, --output DIR           Output directory (default: recon_<domain>)
  --mode {1,2}               Scan mode (default: 2)
  -h, --help                 Show help message
```

#### Examples

**Example 1: Quick Scan (Mode 1)**
```bash
python3 recon_tool.py -d bugcrowd.com --mode 1
```
Runs: Subdomain discovery → Alive check → Nuclei scan

**Example 2: Full Scan (Mode 2)**
```bash
python3 recon_tool.py -d example.com --mode 2
```
Runs: All tools including content discovery

**Example 3: Multiple Domains**
```bash
# Create domains.txt
echo "example.com" > domains.txt
echo "test.com" >> domains.txt

# Run scan
python3 recon_tool.py -dL domains.txt
```

**Example 4: Custom Output Directory**
```bash
python3 recon_tool.py -d example.com -o /path/to/results
```

**Example 5: Stop a Running Scan**
```bash
# Method 1: Press Ctrl+C in the terminal
# Method 2: Create stop file
touch recon_example_com/.stop_scan
```

### Web Interface

The Streamlit web interface provides:

- 🎯 **Launch Scans** - Start new scans with domain or file upload
- 📊 **Visualize Results** - View subdomains, alive hosts, nuclei findings
- 📁 **File Browser** - Browse and download scan results
- 🗑️ **Manage Targets** - Delete old scans
- ⚙️ **Configuration** - Adjust tool settings via UI

**Start the UI:**
```bash
streamlit run stream_app.py
```

**Access:** `http://localhost:8501`

**Default Password:** `recontool@` (set via `RECON_UI_PASSWORD` env var)

---

## 🎛️ Scan Modes

The framework supports two scan modes:

### Mode 1: Quick Scan (Subdomain + Nuclei)

**Tools Enabled:**
- ✅ Subfinder
- ✅ Amass
- ✅ Sublist3r
- ✅ Httpx (alive check)
- ✅ Nuclei

**Use Case:** Fast reconnaissance focusing on subdomain discovery and vulnerability scanning.

```bash
python3 recon_tool.py -d example.com --mode 1
```

### Mode 2: Full Flow (All Tools) - Default

**Tools Enabled:**
- ✅ Subfinder
- ✅ Amass
- ✅ Sublist3r
- ✅ Httpx (alive check)
- ✅ Dirsearch
- ✅ Katana
- ✅ URLFinder
- ✅ Waybackurls
- ✅ Waymore
- ✅ Cloudenum
- ✅ Nuclei

**Use Case:** Comprehensive reconnaissance with full content discovery.

```bash
python3 recon_tool.py -d example.com --mode 2
# or simply
python3 recon_tool.py -d example.com
```

---

## 🔄 Workflow

The framework executes the following workflow:

```
┌─────────────────────────────────────────┐
│        1. Subdomain Discovery          │
│    (Subfinder, Amass, Sublist3r)      │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│      2. Alive Host Verification        │
│            (Httpx)                     │
│    ┌───────────────────────────┐      │
│    │ Auto-filter alive subs    │      │
│    └───────────────────────────┘      │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│      3. Content Discovery              │
│  (Dirsearch, Katana, URLFinder, etc.)  │
│      (Only on alive subdomains)        │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│      4. Cloud Enumeration              │
│          (Cloudenum)                    │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│    5. Vulnerability Scanning           │
│           (Nuclei)                     │
└─────────────────────────────────────────┘
```

### Detailed Steps

1. **Subdomain Discovery**
   - Runs Subfinder, Amass, and Sublist3r
   - Merges results into `subfinder_<domain>.txt`

2. **Alive Host Verification**
   - Checks which subdomains respond with `httpx`
   - Output: `httpx_alive_<domain>.txt`
   - **Auto-filtering**: Creates `subdomain_alive_<domain>.txt`

3. **Content Discovery** (Mode 2 only)
   - Runs on alive subdomains only
   - Tools: Dirsearch, Katana, URLFinder, Waybackurls, Waymore

4. **Cloud Enumeration** (Mode 2 only)
   - Discovers cloud resources (AWS, Azure, GCP)
   - Uses filtered alive subdomains

5. **Vulnerability Scanning**
   - Scans alive targets with Nuclei templates
   - Multiple scan types: general, exposures, etc.

---

## 📁 Project Structure

```
recon_framework/
├── recon_tool.py              # Main orchestrator
├── stream_app.py              # Streamlit web UI
├── check_tools.py             # Dependency checker
├── settings.py                 # Configuration & mode presets
├── requirements.txt            # Python dependencies
│
├── tools/                      # Tool modules
│   ├── __init__.py
│   ├── base.py                 # BaseTool abstract class
│   ├── subfinder.py            # Subdomain discovery
│   ├── amass.py                 # Amass subdomain discovery
│   ├── sublist3r.py             # Sublist3r subdomain discovery
│   ├── httpx.py                 # Alive checker + filtering
│   ├── dirsearch.py             # Directory enumeration
│   ├── katana.py                # Web crawler
│   ├── urlfinder.py             # URL finder
│   ├── waybackurls.py           # Wayback URL extractor
│   ├── waymore.py               # Enhanced Wayback extractor
│   ├── cloudenum.py             # Cloud enumeration
│   └── nuclei.py                # Vulnerability scanner
│
├── recon_<domain>/              # Output directories (auto-created)
│   └── ...
│
└── README.md                    # This file
```

---

## 📊 Output Structure

All results are organized in the output directory (default: `recon_<domain>`):

```
recon_example_com/
│
├── subfinder_example_com.txt           # All discovered subdomains
├── httpx_alive_example_com.txt         # Full httpx output
├── subdomain_alive_example_com.txt     # ✨ Filtered alive subdomains
├── urls_example_com.txt                 # Extracted URLs (alive only)
│
├── dirsearch_example_com.txt           # Dirsearch output
├── katana_example_com.txt              # Katana crawling results
├── urlfinder_example_com.txt           # URLFinder output
├── waybackurls_example_com.txt         # Waybackurls output
│
├── waymore/                             # Waymore results
│   └── waymore_example_com.txt
│
├── cloudenum_example_com.txt           # Cloud enumeration results
│
├── nuclei/                              # Nuclei scan results
│   ├── nuclei_alive_example_com.txt
│   ├── nuclei_subdomains_example_com.txt
│   └── nuclei_exposures_example_com.txt
│
└── recon_<timestamp>.log               # Detailed execution log
```

### Key Files

- **`subdomain_alive_<domain>.txt`** - Filtered list used by all subsequent tools
- **`recon_<timestamp>.log`** - Complete execution log with timestamps
- **`.stop_scan`** - Stop flag file (created when scan is stopped)

---

## ⚙️ Configuration

### Mode Presets

Edit `settings.py` to customize mode presets:

```python
MODE_PRESETS = {
    "1": {
        "description": "Quick scan",
        "tools_enabled": {
            "subfinder": True,
            "amass": True,
            # ... customize enabled tools
        },
    },
    "2": {
        "description": "Full flow",
        # ... full configuration
    },
}
```

### Tool Configuration

Customize individual tool parameters in `settings.py`:

```python
DEFAULT_TOOL_CONFIG = {
    "dirsearch": {
        "threads": 5,
        "max_rate": 30,
        "extensions": "all",
        "match_codes": "200,301,302,403,405,500",
    },
    "waymore": {
        "mode": "U",
        "limit": 200,
        "max_domains": 5,
    },
    "amass": {
        "passive": True,
        "active": True,
        "bruteforce": False,
    },
    # ... more tool configs
}
```

### Environment Variables

- `RECON_UI_PASSWORD` - Set Streamlit UI password (default: `recontool@`)
- `RECON_TOOL_CONFIG` - Path to JSON config file (for UI-generated configs)

---

## 🎛️ Customization

### Modifying Tool Parameters

Edit the respective tool file in `tools/` or modify `settings.py`:

#### Example: Adjust Dirsearch Threads

Edit `settings.py`:

```python
"dirsearch": {
    "threads": 10,  # Increase threads
    "max_rate": 50,  # Increase rate limit
    # ...
}
```

#### Example: Change Amass Mode

Edit `settings.py`:

```python
"amass": {
    "passive": True,
    "active": False,  # Disable active mode
    "bruteforce": True,  # Enable brute force
}
```

### Adding a New Tool

1. **Create new tool file** (`tools/newtool.py`):

```python
from .base import BaseTool
import os

class NewTool(BaseTool):
    """Description of your tool"""
    
    def run(self, input_file):
        """Run your tool"""
        if not self.check_input_file(input_file):
            return None
        
        output_file = self.output_dir / f"newtool_{self.base_name}.txt"
        cmd = ["newtool", "-input", input_file]
        
        success = self.run_command(cmd, output_file)
        return str(output_file) if success else None
```

2. **Import in `recon_tool.py`**:

```python
from tools.newtool import NewTool
```

3. **Initialize and use**:

```python
self.newtool = NewTool(self.output_dir, self.base_name, self.logger)
# ... in run() method
self.newtool.run(input_file)
```

4. **Add to `settings.py`**:

```python
"tools_enabled": {
    "newtool": True,
},
```

See `tools/README.md` for detailed documentation.

---

## 🔧 Troubleshooting

### Issue: "command not found"

**Solution:**
- Ensure all tools are installed and in `PATH`
- Run `check_tools.py` to verify
- Test each tool manually: `subfinder --help`

### Issue: "permission denied"

**Solution:**
```bash
chmod +x recon_tool.py
chmod -R 755 tools/
```

### Issue: Missing wordlist

**Solution:**
- Install SecLists: `git clone https://github.com/danielmiessler/SecLists.git`
- Update wordlist path in `settings.py` → `dirsearch.wordlist_candidates`

### Issue: Process takes too long

**Solution:**
- Use Mode 1 for quick scans: `--mode 1`
- Adjust limits in `settings.py` (e.g., `waymore.max_domains`)
- Stop gracefully with Ctrl+C or `.stop_scan` file

### Issue: Streamlit UI not starting

**Solution:**
- Check if port 8501 is available
- Verify streamlit is installed: `pip3 install streamlit`
- Check logs in `auth.log`

### Issue: No results in output

**Solution:**
- Check log file: `recon_<domain>/recon_<timestamp>.log`
- Verify target domain is accessible
- Ensure tools have proper permissions
- Check if scan was stopped (look for `.stop_scan` file)

### Issue: Amass not working

**Solution:**
- See `FIX_AMASS.md` for detailed troubleshooting
- Ensure amass config file exists (auto-detected)
- Check amass installation: `amass enum --help`

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes**
4. **Test thoroughly**
5. **Commit your changes**: `git commit -m 'Add amazing feature'`
6. **Push to the branch**: `git push origin feature/amazing-feature`
7. **Open a Pull Request**

### Contribution Guidelines

- Follow the existing code style
- Add comments for complex logic
- Update documentation as needed
- Test on multiple platforms if possible
- Update `check_tools.py` if adding new tools

---

## ⚠️ Legal & Ethical Use

**IMPORTANT:** This tool is for authorized security testing only.

- ✅ Use only on assets you own or have explicit permission to test
- ✅ Follow responsible disclosure practices
- ✅ Respect rate limits and terms of service
- ❌ Do not use for unauthorized access or malicious purposes

The authors are not responsible for misuse of this tool.

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 Recon Framework Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

## 🙏 Acknowledgments

- [ProjectDiscovery](https://github.com/projectdiscovery) - For amazing tools
- [OWASP Amass](https://github.com/owasp-amass/amass) - Subdomain enumeration
- [Sublist3r](https://github.com/aboul3la/Sublist3r) - Subdomain enumeration
- [Dirsearch](https://github.com/maurosoria/dirsearch) - Directory enumeration
- All the open-source security community

---

## 📞 Support

- 🐛 **Found a bug?** [Open an issue](https://github.com/tptnhanan2001/recon_framework/issues)
- 💡 **Have a suggestion?** [Start a discussion](https://github.com/tptnhanan2001/recon_framework/discussions)
- 📧 **Questions?** Check the [Troubleshooting](#-troubleshooting) section
- 📚 **Documentation:** See `QUICKSTART.md` and `tools/README.md`

---

<div align="center">

**⭐ If you find this project useful, please give it a star! ⭐**

Made with ❤️ for the security community

</div>

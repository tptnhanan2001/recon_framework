"""
Default configuration values for reconnaissance tools.
"""

from pathlib import Path


# Mode presets for different scan intensities
MODE_PRESETS = {
    "1": {
        "description": "Fast Scan - Subdomain Discovery + Alive Check + Nuclei",
        "tools_enabled": {
            "subfinder": True,
            "amass": False,   # Disabled in mode 1
            "sublist3r": True,
            "httpx": True,
            "dirsearch": False,
            "katana": False,
            "urlfinder": False,
            "ffuf": False,
            "naabu": False,
            "arjun": False,
            "waybackurls": False,
            "waymore": False,
            "cloudenum": False,
            "nuclei": True,
        },
    },
    "2": {
        "description": "Standard Scan - Subdomain Discovery + Alive Check + Nuclei (uses Amass)",
        "tools_enabled": {
            "subfinder": True,
            "amass": True,     # Use Amass for comprehensive enumeration
            "sublist3r": True,
            "httpx": True,
            "dirsearch": False,
            "katana": False,
            "urlfinder": False,
            "ffuf": False,
            "naabu": False,
            "arjun": False,
            "waybackurls": False,
            "waymore": False,
            "cloudenum": False,
            "nuclei": True,
        },
    },
    "3": {
        "description": "Full Flow - All tools including content discovery",
        "tools_enabled": {
            "subfinder": True,
            "amass": True,
            "sublist3r": True,
            "httpx": True,
            "dirsearch": True,
            "katana": True,
            "urlfinder": True,
            "ffuf": True,
            "naabu": True,
            "arjun": True,
            "waybackurls": True,
            "waymore": True,
            "cloudenum": True,
            "nuclei": True,
        },
    },
}


# Get base directory for relative paths
_BASE_DIR = Path(__file__).resolve().parent

DEFAULT_WORDLIST_CANDIDATES = [
    # Try relative path first (works on all platforms)
    _BASE_DIR / "db" / "wordlists" / "WebContent" / "wordlists_001.txt",
    # Fallback to absolute path (Linux/WSL)
    Path("/mnt/d/BugbountyDev/recon_framework/db/wordlists/WebContent/wordlists_001.txt")
]
DEFAULT_SUBDOMAINS_CANDIDATES = [
    # Try relative path first (works on all platforms)
    _BASE_DIR / "db" / "wordlists" / "DNS" / "subdomains.txt",
    # Fallback to absolute path (Linux/WSL)
    Path("/mnt/d/BugbountyDev/recon_framework/db/wordlists/DNS/subdomains.txt")
]
DEFAULT_TOOL_CONFIG = {
    # Tool enable/disable flags (True = enabled, False = disabled)
    "tools_enabled": {
        "subfinder": True,
        "amass": True,
        "sublist3r": True,
        "httpx": True,
        "dirsearch": True,
        "katana": True,
        "urlfinder": True,
        "ffuf": True,
        "naabu": True,
        "arjun": True,
        "waybackurls": True,
        "waymore": True,
        "cloudenum": True,
        "nuclei": True,
    },
    "dirsearch": {
        "enabled": True,  # Can be overridden by tools_enabled["dirsearch"]
        "wordlist": None,
        "wordlist_candidates": DEFAULT_WORDLIST_CANDIDATES,
        "threads": 5,
        "max_rate": 30,
        "extensions": "all",
        "match_codes": "200,301,302,403,405,500",
    },
    "ffuf": {
        "enabled": True,  # Can be overridden by tools_enabled["ffuf"]
        "wordlist": None,
        "wordlist_candidates": DEFAULT_WORDLIST_CANDIDATES,
        "threads": 50,
        "match_codes": "200,204,301,302,307,401,403,500",
        "recursion": False,
        "recursion_depth": 1,
        "timeout": 10,
        "rate": None,  # Optional: rate limit (requests per second)
        "extensions": None,  # Optional: comma-separated extensions (e.g., "php,html,js")
    },
    "naabu": {
        "enabled": True,  # Can be overridden by tools_enabled["naabu"]
        "ports": "80,443,8080,8443,3000,8000,8888,9000",  # Comma-separated port list
        "top_ports": None,  # Optional: scan top N ports (e.g., 100, 1000)
        "exclude_ports": None,  # Optional: comma-separated ports to exclude
        "rate": 1000,  # Packets per second
        "retries": 2,  # Number of retries
        "verify": False,  # Verify port status
    },
    "arjun": {
        "enabled": True,  # Can be overridden by tools_enabled["arjun"]
        "wordlist": None,
        "wordlist_candidates": DEFAULT_WORDLIST_CANDIDATES,
        "method": "GET",  # HTTP method: GET, POST, PUT, etc.
        "threads": 10,
        "timeout": 10,  # Request timeout in seconds
        "include": None,  # Optional: comma-separated parameters to include
        "exclude": None,  # Optional: comma-separated parameters to exclude
    },
    "waymore": {
        "enabled": True,  # Can be overridden by tools_enabled["waymore"]
        "mode": "U",
        "limit": 200,
        "max_domains": 5,
    },
    "katana": {
        "enabled": True,  # Can be overridden by tools_enabled["katana"]
    },
    "urlfinder": {
        "enabled": True,  # Can be overridden by tools_enabled["urlfinder"]
    },
    "waybackurls": {
        "enabled": True,  # Can be overridden by tools_enabled["waybackurls"]
    },
    "cloudenum": {
        "enabled": True,  # Can be overridden by tools_enabled["cloudenum"]
    },
    "nuclei": {
        "enabled": True,  # Can be overridden by tools_enabled["nuclei"]
    },
    "amass": {
        "enabled": True,  # Can be overridden by tools_enabled["amass"]
        "config_file": None,  # Path to amass config.ini (auto-detected if None)
        "passive": True,  # Run in passive mode
        "active": True,  # Run in active mode
        "bruteforce": False,  # Enable brute force mode (-brute)
        "wordlist": None,  # Path to wordlist (auto-detected from DEFAULT_SUBDOMAINS_CANDIDATES if None)
        "wordlist_candidates": DEFAULT_SUBDOMAINS_CANDIDATES,
    },
    "sublist3r": {
        "enabled": True,  # Can be overridden by tools_enabled["sublist3r"]
        "bruteforce": False,  # Enable subbrute bruteforce module
        "verbose": False,  # Enable verbose output
        "threads": None,  # Number of threads for bruteforce (default: auto)
        "engines": None,  # Comma-separated list of search engines (default: all)
    },
}



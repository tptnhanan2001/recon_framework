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
            "waybackurls": True,
            "waymore": True,
            "cloudenum": True,
            "nuclei": True,
        },
    },
}


DEFAULT_WORDLIST_CANDIDATES = [
    Path("/mnt/d/BugbountyDev/recon_framework/db/wordlists/WebContent/wordlists_001.txt")
]
DEFAULT_SUBDOMAINS_CANDIDATES = [
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



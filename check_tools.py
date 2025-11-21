#!/usr/bin/env python3
"""
Tool Checker - Verify all required tools are installed
"""

import subprocess
import sys
import os

REQUIRED_TOOLS = {
    "subfinder": "Subdomain discovery",
    "dnsenum": "DNS enumeration (fast subdomain discovery, used in mode 1)",
    "httpx": "HTTP probe and alive checker",
    "ffuf": "Web fuzzer",
    "dirsearch": "Directory enumeration",
    "katana": "Web crawler",
    "urlfinder": "URL finder",
    "waybackurls": "Wayback machine URL extractor",
    "waymore": "Wayback machine URL extractor (enhanced)",
    "cloudenum": "Cloud resource enumeration",
    "nuclei": "Vulnerability scanner"
}

def check_tool(tool_name):
    """Check if a tool is available in PATH"""
    try:
        # Try with --help or -h
        result = subprocess.run(
            [tool_name, "--help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # Try with -version or version
        try:
            subprocess.run(
                [tool_name, "-version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5
            )
            return True
        except:
            # Try just running the command (some tools show help on error)
            try:
                subprocess.run(
                    [tool_name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5
                )
                return True
            except:
                return False
    except Exception:
        return False

def main():
    print("=" * 70)
    print("Recon Tool - Dependency Checker")
    print("=" * 70)
    print()
    
    all_ok = True
    missing_tools = []
    
    print("Checking required tools...")
    print("-" * 70)
    for tool, description in REQUIRED_TOOLS.items():
        if check_tool(tool):
            print(f"✓ {tool:20} - {description}")
        else:
            print(f"✗ {tool:20} - {description} - NOT FOUND")
            all_ok = False
            missing_tools.append(tool)
    
    print()
    print("=" * 70)
    if all_ok:
        print("✓ All required tools are installed!")
        print()
        print("You can now run the recon tool:")
        print("  python recon_tool.py -d example.com")
        return 0
    else:
        print("✗ Some required tools are missing!")
        print()
        print("Missing tools:")
        for tool in missing_tools:
            print(f"  - {tool}")
        print()
        print("Please install the missing tools before running the recon tool.")
        print("See README.md for installation instructions.")
        return 1

if __name__ == "__main__":
    sys.exit(main())


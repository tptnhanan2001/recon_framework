#!/usr/bin/env python3
"""
Realistic test scenarios for dnsenum bruteforce output
Tests various output formats that dnsenum might produce
"""

from pathlib import Path
import sys

# Add parent directory to path to import dnsenum tool
sys.path.insert(0, str(Path(__file__).parent))

from tools.dnsenum import Dnsenum
import logging
from pathlib import Path
import tempfile
import os

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Create a temporary output directory
temp_dir = Path(tempfile.mkdtemp())
print(f"Using temporary directory: {temp_dir}")

# Create mock config with wordlist
config = {
    "wordlist": None,  # Will use candidates
    "wordlist_candidates": [
        Path("D:/BugbountyDev/recon_framework/db/wordlists/DNS/subdomains.txt")
    ],
    "threads": None
}

# Initialize DNSenum tool
dnsenum = Dnsenum(
    output_dir=temp_dir,
    base_name="test_example",
    logger=logger,
    config=config
)

# Test scenarios
test_scenarios = [
    {
        "name": "Standard DNS Zone Format",
        "output": """
dnsenum version 1.2.6
Starting enumeration of example.com
dnsenum: example.com

Bruteforcing subdomains...

www.example.com.                3600    IN    A        93.184.216.34
mail.example.com.               3600    IN    A        93.184.216.34
ftp.example.com.                 3600    IN    A        93.184.216.34
admin.example.com.               3600    IN    A        192.0.2.1
api.example.com.                 3600    IN    A        192.0.2.2
"""
    },
    {
        "name": "Simple List Format",
        "output": """
www.example.com
mail.example.com
ftp.example.com
admin.example.com
api.example.com
"""
    },
    {
        "name": "Info Format with Brackets",
        "output": """
[INFO] Bruteforcing example.com...
[+] Found: www.example.com (A: 93.184.216.34)
[+] Found: mail.example.com (A: 93.184.216.34)
[+] Found: ftp.example.com (A: 93.184.216.34)
[+] Found: admin.example.com (A: 192.0.2.1)
[INFO] Bruteforce complete.
"""
    },
    {
        "name": "Mixed Format",
        "output": """
dnsenum v1.2.6
Target: example.com
Bruteforcing with wordlist...

www.example.com -> 93.184.216.34
mail.example.com -> 93.184.216.34
ftp.example.com -> 93.184.216.34
admin.example.com -> 192.0.2.1
api.example.com -> 192.0.2.2

Done.
"""
    }
]

def simulate_dnsenum_output(output_text, domain="example.com"):
    """Simulate what dnsenum would output and test parsing - using exact logic from dnsenum.py"""
    # Write to temp file
    temp_output = temp_dir / "dnsenum_raw_test_example.txt"
    with open(temp_output, 'w', encoding='utf-8') as f:
        f.write(output_text)
    
    # Use the EXACT parsing logic from dnsenum.py
    subdomains = set()
    with open(temp_output, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith(';'):
                continue
            
            # DNSenum may output various formats:
            # - subdomain.example.com
            # - subdomain.example.com. A 1.2.3.4
            # - [INFO] subdomain.example.com
            # - [+] Found: subdomain.example.com (A: 1.2.3.4)
            # Extract subdomain-like patterns
            
            # Handle bracket format: [+] Found: subdomain.example.com (A: IP)
            if '[+]' in line or 'Found:' in line:
                # Extract text after "Found:" or colon
                if 'Found:' in line:
                    after_found = line.split('Found:', 1)[1].strip()
                elif ':' in line:
                    after_found = line.split(':', 1)[1].strip()
                else:
                    after_found = line
                
                # Remove parentheses content and brackets
                if '(' in after_found:
                    after_found = after_found.split('(')[0].strip()
                after_found = after_found.strip('.,[](){}"\'').lower()
                
                # Check if it's a valid subdomain
                if domain and domain.lower() in after_found:
                    domain_lower = domain.lower()
                    idx = after_found.find(domain_lower)
                    if idx > 0:
                        subdomain = after_found[:idx + len(domain_lower)]
                        if subdomain.count('.') >= 2 and subdomain.endswith(domain_lower):
                            if all(c.isalnum() or c in '.-' for c in subdomain):
                                subdomains.add(subdomain)
                                continue
                    elif idx == 0 and after_found != domain_lower:
                        if after_found.count('.') >= 2 and after_found.endswith(domain_lower):
                            subdomains.add(after_found)
                            continue
            
            # Standard parsing for other formats
            parts = line.split()
            for part in parts:
                # Clean the part
                part = part.strip('.,[](){}"\'').lower()
                
                # Skip if too short or doesn't look like a domain
                if len(part) < 4 or '://' in part or part.startswith('http'):
                    continue
                
                # Skip DNS record types and common keywords
                if part in ['a', 'aaaa', 'cname', 'mx', 'ns', 'txt', 'soa', 'in', '3600', '300', '86400', 'found', '->', 'info']:
                    continue
                
                # Check if it contains the target domain
                if domain and domain.lower() in part:
                    # Extract subdomain part
                    domain_lower = domain.lower()
                    idx = part.find(domain_lower)
                    if idx > 0:
                        # Found domain in the string, extract subdomain
                        potential_subdomain = part[:idx + len(domain_lower)]
                        # Validate: must have at least 2 dots (subdomain.domain.com)
                        if potential_subdomain.count('.') >= 2:
                            # Must end with the domain
                            if potential_subdomain.endswith(domain_lower):
                                # Additional validation: reasonable characters
                                if all(c.isalnum() or c in '.-' for c in potential_subdomain):
                                    subdomains.add(potential_subdomain)
                    elif idx == 0 and part != domain_lower:
                        # Starts with domain but is longer (subdomain.domain.com)
                        if part.count('.') >= 2 and part.endswith(domain_lower):
                            subdomains.add(part)
    
    return sorted(subdomains)

if __name__ == "__main__":
    print("=" * 70)
    print("DNSenum Bruteforce - Realistic Output Format Tests")
    print("=" * 70)
    print()
    
    for scenario in test_scenarios:
        print(f"\n{'=' * 70}")
        print(f"Scenario: {scenario['name']}")
        print('=' * 70)
        print("\nRaw Output:")
        print("-" * 70)
        print(scenario['output'])
        print("-" * 70)
        
        subdomains = simulate_dnsenum_output(scenario['output'])
        
        print("\nExtracted Subdomains:")
        print("-" * 70)
        if subdomains:
            for idx, subdomain in enumerate(subdomains, 1):
                print(f"{idx:2d}. {subdomain}")
            print(f"\n[OK] Successfully extracted {len(subdomains)} subdomains")
        else:
            print("[FAIL] No subdomains extracted")
        print()
    
    print("=" * 70)
    print("Summary")
    print("=" * 70)
    print("All scenarios tested. The tool should handle various dnsenum output formats.")
    print("Only subdomains found via bruteforce will be extracted and saved.")
    print("=" * 70)
    
    # Cleanup
    try:
        import shutil
        shutil.rmtree(temp_dir)
    except:
        pass


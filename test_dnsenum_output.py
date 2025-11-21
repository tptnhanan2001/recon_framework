#!/usr/bin/env python3
"""
Test script to understand dnsenum output format
This script simulates different dnsenum output formats
"""

# Simulated dnsenum output formats based on common DNS enumeration tools
# DNSenum typically outputs in various formats depending on options

test_outputs = {
    "format1": """
dnsenum version 1.2.6
Starting enumeration of example.com
dnsenum: example.com
example.com.                    3600    IN    A        93.184.216.34
www.example.com.                3600    IN    A        93.184.216.34
mail.example.com.               3600    IN    A        93.184.216.34
ftp.example.com.                3600    IN    A        93.184.216.34
subdomain.example.com.          3600    IN    A        192.0.2.1
test.example.com.               3600    IN    A        192.0.2.2
""",

    "format2": """
[+] Found: www.example.com (A: 93.184.216.34)
[+] Found: mail.example.com (A: 93.184.216.34)
[+] Found: ftp.example.com (A: 93.184.216.34)
[+] Found: subdomain.example.com (A: 192.0.2.1)
[+] Found: test.example.com (A: 192.0.2.2)
""",

    "format3": """
www.example.com
mail.example.com
ftp.example.com
subdomain.example.com
test.example.com
""",

    "format4": """
dnsenum v1.2.6
Target: example.com
[INFO] Starting DNS enumeration...
[INFO] Found: www.example.com -> 93.184.216.34
[INFO] Found: mail.example.com -> 93.184.216.34
[INFO] Found: ftp.example.com -> 93.184.216.34
[INFO] Found: subdomain.example.com -> 192.0.2.1
[INFO] Found: test.example.com -> 192.0.2.2
[INFO] Enumeration complete.
""",

    "format5": """
;; DNS Enumeration Results for example.com
www.example.com.                3600    IN    A        93.184.216.34
mail.example.com.               3600    IN    A        93.184.216.34
ftp.example.com.                3600    IN    A        93.184.216.34
subdomain.example.com.          3600    IN    A        192.0.2.1
test.example.com.               3600    IN    A        192.0.2.2
"""
}

def test_parsing(output_text, domain="example.com"):
    """Test parsing logic from dnsenum.py"""
    subdomains = set()
    
    for line in output_text.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or line.startswith(';'):
            continue
        
        # DNSenum may output various formats:
        # - subdomain.example.com
        # - subdomain.example.com. A 1.2.3.4
        # - [INFO] subdomain.example.com
        # Extract subdomain-like patterns
        parts = line.split()
        for part in parts:
            # Clean the part
            part = part.strip('.,[](){}"\'').lower()
            
            # Skip if too short or doesn't look like a domain
            if len(part) < 4 or '://' in part or part.startswith('http'):
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
    
    return subdomains

if __name__ == "__main__":
    print("=" * 70)
    print("DNSenum Output Format Test")
    print("=" * 70)
    print()
    
    for format_name, output in test_outputs.items():
        print(f"\nTesting {format_name}:")
        print("-" * 70)
        print("Raw output:")
        print(output)
        print("\nParsed subdomains:")
        subdomains = test_parsing(output)
        if subdomains:
            for subdomain in sorted(subdomains):
                print(f"  - {subdomain}")
        else:
            print("  (No subdomains extracted)")
        print()


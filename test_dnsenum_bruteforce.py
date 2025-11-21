#!/usr/bin/env python3
"""
Test script to simulate dnsenum bruteforce output
This shows what dnsenum outputs when running in bruteforce-only mode
"""

# Simulated dnsenum bruteforce output
# When running: dnsenum -f wordlist.txt --noreverse --no-whois example.com

test_domain = "example.com"

bruteforce_output = """
dnsenum version 1.2.6

Starting enumeration of example.com
dnsenum: example.com

Bruteforcing subdomains with wordlist...

www.example.com.                3600    IN    A        93.184.216.34
mail.example.com.               3600    IN    A        93.184.216.34
ftp.example.com.                 3600    IN    A        93.184.216.34
admin.example.com.               3600    IN    A        192.0.2.1
test.example.com.                3600    IN    A        192.0.2.2
api.example.com.                 3600    IN    A        192.0.2.3
dev.example.com.                 3600    IN    A        192.0.2.4
staging.example.com.             3600    IN    A        192.0.2.5

Bruteforce complete.
Found 8 subdomains.
"""

def test_parsing(output_text, domain="example.com"):
    """Test parsing logic from dnsenum.py"""
    subdomains = set()
    
    print(f"Testing bruteforce output parsing for domain: {domain}")
    print("=" * 70)
    
    for line in output_text.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or line.startswith(';'):
            continue
        
        # Skip header lines
        if any(keyword in line.lower() for keyword in ['dnsenum', 'starting', 'bruteforcing', 'complete', 'found']):
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
            
            # Skip common DNS record types and TTL values
            if part in ['a', 'aaaa', 'cname', 'mx', 'ns', 'txt', 'soa', 'in', '3600', '300', '86400']:
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
    print("DNSenum Bruteforce Output Test")
    print("=" * 70)
    print()
    print("Simulated command: dnsenum -f wordlist.txt --noreverse --no-whois example.com")
    print()
    print("Raw output:")
    print("-" * 70)
    print(bruteforce_output)
    print("-" * 70)
    print()
    
    subdomains = test_parsing(bruteforce_output, test_domain)
    
    print("\nParsed subdomains (bruteforce results only):")
    print("-" * 70)
    if subdomains:
        for idx, subdomain in enumerate(sorted(subdomains), 1):
            print(f"{idx:2d}. {subdomain}")
        print()
        print(f"Total: {len(subdomains)} subdomains found via bruteforce")
    else:
        print("  (No subdomains extracted)")
    print("=" * 70)
    
    # Show what would be saved to file
    print("\nOutput file content (dnsenum_example_com.txt):")
    print("-" * 70)
    if subdomains:
        for subdomain in sorted(subdomains):
            print(subdomain)
    print("=" * 70)


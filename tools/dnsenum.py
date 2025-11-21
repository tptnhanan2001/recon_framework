"""
DNSenum Tool - DNS enumeration for subdomain discovery
"""

from .base import BaseTool
import os
from pathlib import Path


class Dnsenum(BaseTool):
    """DNSenum tool for fast DNS enumeration and subdomain discovery"""
    
    def run(self, domain=None, domain_list=None):
        """Run dnsenum to collect subdomains"""
        self.logger.info("=" * 70)
        self.logger.info("[DNSenum] Starting DNS enumeration")
        self.logger.info("=" * 70)
        
        output_file = self.output_dir / f"dnsenum_{self.base_name}.txt"
        
        # Build dnsenum command
        # DNSenum bruteforce only mode - requires wordlist
        # We use --noreverse and --no-whois to disable other enumeration methods
        
        # Get wordlist from config or auto-detect from candidates (REQUIRED for bruteforce)
        wordlist = self.config.get("wordlist") if self.config else None
        if not wordlist:
            # Auto-detect wordlist from candidates if not specified
            wordlist_candidates = self.config.get("wordlist_candidates", []) if self.config else []
            if wordlist_candidates:
                for candidate in wordlist_candidates:
                    candidate_path = Path(candidate).expanduser() if isinstance(candidate, (str, Path)) else candidate
                    if candidate_path.exists():
                        wordlist = str(candidate_path)
                        self.logger.info(f"[DNSenum] Auto-detected wordlist from candidates: {wordlist}")
                        break
        
        # Wordlist is required for bruteforce mode
        if not wordlist:
            self.logger.error("[DNSenum] Wordlist is required for bruteforce mode. Please configure wordlist in settings.")
            return None
        
        wordlist_path = Path(wordlist).expanduser()
        if not wordlist_path.exists():
            self.logger.error(f"[DNSenum] Wordlist not found: {wordlist_path}")
            return None
        
        dnsenum_base_cmd = ["dnsenum", "-f", str(wordlist_path), "-v"]

        if domain:
            # Single domain - bruteforce only
            cmd = dnsenum_base_cmd + [domain]
        elif domain_list:
            # For domain list, we need to process each domain
            # DNSenum doesn't support domain list file directly
            # So we'll read the file and run for each domain
            try:
                with open(domain_list, 'r', encoding='utf-8') as f:
                    domains = [line.strip() for line in f if line.strip()]
                
                if not domains:
                    self.logger.error("[DNSenum] No domains found in domain list")
                    return None
                
                # Run dnsenum for first domain (or combine results)
                # For simplicity, we'll run on first domain
                # In production, you might want to run for all and merge
                domain = domains[0]
                self.logger.info(f"[DNSenum] Processing first domain from list: {domain}")
                cmd = dnsenum_base_cmd + [domain]
            except Exception as e:
                self.logger.error(f"[DNSenum] Error reading domain list: {e}")
                return None
        else:
            self.logger.error("[DNSenum] No domain or domain list provided")
            return None
        
        # Add additional options from config if available
        if self.config:
            # DNSenum options that can be configured
            if self.config.get("threads"):
                cmd.extend(["-t", str(self.config["threads"])])
        
        self.logger.info(f"[DNSenum] Running bruteforce only mode with wordlist: {wordlist_path}")
        self.logger.info("[DNSenum] Options: --noreverse --no-whois (only bruteforce subdomains)")
        
        # Run command and capture output
        # DNSenum outputs to stdout, we'll capture and process it
        temp_output = self.output_dir / f"dnsenum_raw_{self.base_name}.txt"
        success = self.run_command(cmd, temp_output, merge_stderr=True)
        
        # Process DNSenum output to extract only subdomains
        # DNSenum output format can vary, we'll extract lines that look like subdomains
        if success and os.path.exists(temp_output):
            self.logger.info(f"[DNSenum] Raw verbose output saved to: {temp_output}")
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
            
            # Write cleaned subdomains to output file
            if subdomains:
                with open(output_file, 'w', encoding='utf-8') as f:
                    for subdomain in sorted(subdomains):
                        f.write(subdomain + "\n")
                
                # Clean up temp file
                try:
                    temp_output.unlink()
                except:
                    pass
                
                self.logger.info(f"[DNSenum] ✓ Extracted {len(subdomains)} subdomains: {output_file}")
                self.notify_message(f"✅ DNSenum Success - {len(subdomains)} subdomains found")
                return str(output_file)
            else:
                self.logger.warning("[DNSenum] No subdomains extracted from output")
                # Clean up temp file
                try:
                    temp_output.unlink()
                except:
                    pass
                return str(output_file) if os.path.exists(output_file) else None
        else:
            self.logger.warning("[DNSenum] Command failed or no output generated")
            return str(output_file) if os.path.exists(output_file) else None


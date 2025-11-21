"""
Sublist3r Tool - Subdomain discovery using Sublist3r
"""

from .base import BaseTool
import os
from pathlib import Path


class Sublist3r(BaseTool):
    """Sublist3r tool for subdomain discovery"""
    
    def _run_single_domain(self, domain, output_file):
        """Run sublist3r for a single domain"""
        cmd = ["sublist3r", "-d", domain, "-n", "-o", str(output_file)]
        
        # Add additional options from config
        if self.config.get("bruteforce", False):
            cmd.append("-b")
        
        if self.config.get("verbose", False):
            cmd.append("-v")
        
        threads = self.config.get("threads")
        if threads:
            cmd.extend(["-t", str(threads)])
        
        engines = self.config.get("engines")
        if engines:
            cmd.extend(["-e", engines])
        
        # Run command
        # Sublist3r handles output via -o flag
        return self.run_command(cmd, output_file=None)
    
    def run(self, domain=None, domain_list=None):
        """Run sublist3r to collect subdomains"""
        self.logger.info("=" * 70)
        self.logger.info("[Sublist3r] Starting subdomain discovery")
        self.logger.info("=" * 70)
        
        output_file = self.output_dir / f"sublist3r_{self.base_name}.txt"
        
        # Handle single domain
        if domain:
            success = self._run_single_domain(domain, output_file)
            if success and self.check_input_file(output_file):
                self.logger.info("[Sublist3r] Success")
                self.logger.info(f"[Sublist3r] ✓ Subdomains collected: {output_file}")
                self.notify_message(f"✅ Sublist3r Success - {domain}")
                return str(output_file)
            else:
                self.logger.warning("[Sublist3r] No subdomains found or error occurred")
                return str(output_file) if os.path.exists(output_file) else None
        
        # Handle domain list file
        elif domain_list:
            if not os.path.exists(domain_list):
                self.logger.error(f"[Sublist3r] Domain list file not found: {domain_list}")
                return None
            
            # Read domains from file
            domains = []
            try:
                with open(domain_list, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        domain = line.strip()
                        if domain and not domain.startswith('#'):
                            domains.append(domain)
            except Exception as e:
                self.logger.error(f"[Sublist3r] Error reading domain list file: {e}")
                return None
            
            if not domains:
                self.logger.warning("[Sublist3r] No valid domains found in domain list file")
                return None
            
            self.logger.info(f"[Sublist3r] Found {len(domains)} domains in list. Processing each domain...")
            
            # Process each domain and collect results
            all_subdomains = set()
            temp_files = []
            successful_domains = 0
            
            for idx, domain in enumerate(domains, 1):
                self.logger.info(f"[Sublist3r] Processing domain {idx}/{len(domains)}: {domain}")
                
                # Create temp output file for this domain
                temp_output = self.output_dir / f"sublist3r_temp_{domain.replace('.', '_')}.txt"
                temp_files.append(temp_output)
                
                # Run sublist3r for this domain
                success = self._run_single_domain(domain, temp_output)
                
                if success and self.check_input_file(temp_output):
                    # Read subdomains from temp file
                    try:
                        with open(temp_output, 'r', encoding='utf-8', errors='ignore') as f:
                            for line in f:
                                subdomain = line.strip()
                                if subdomain:
                                    all_subdomains.add(subdomain)
                        successful_domains += 1
                        self.logger.info(f"[Sublist3r] ✓ Found subdomains for {domain}")
                    except Exception as e:
                        self.logger.warning(f"[Sublist3r] Error reading temp file for {domain}: {e}")
                else:
                    self.logger.warning(f"[Sublist3r] No subdomains found for {domain}")
            
            # Write merged results to final output file
            if all_subdomains:
                with open(output_file, 'w', encoding='utf-8') as f:
                    for subdomain in sorted(all_subdomains):
                        f.write(subdomain + "\n")
                
                self.logger.info(f"[Sublist3r] Successfully processed {successful_domains}/{len(domains)} domains")
                self.logger.info(f"[Sublist3r] ✓ Collected {len(all_subdomains)} unique subdomains: {output_file}")
                self.notify_message(f"✅ Sublist3r Success - {len(domains)} domains, {len(all_subdomains)} subdomains")
            else:
                self.logger.warning("[Sublist3r] No subdomains found for any domain in the list")
            
            # Clean up temp files
            for temp_file in temp_files:
                try:
                    if temp_file.exists():
                        temp_file.unlink()
                except Exception as e:
                    self.logger.debug(f"[Sublist3r] Could not delete temp file {temp_file}: {e}")
            
            return str(output_file) if os.path.exists(output_file) and self.check_input_file(output_file) else None
        
        else:
            self.logger.error("[Sublist3r] No domain or domain list provided")
            return None


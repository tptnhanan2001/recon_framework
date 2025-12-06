"""
Httpx Tool - Check alive domains
"""

from .base import BaseTool
import os
import platform
from urllib.parse import urlparse


class Httpx(BaseTool):
    """Httpx tool for checking alive domains"""
    
    def extract_alive_subdomains(self, alive_file):
        """Extract subdomains from httpx alive output (only domains, not full URLs)"""
        if not self.check_input_file(alive_file):
            return None
        
        subdomain_alive_file = self.output_dir / f"subdomain_alive_{self.base_name}.txt"
        subdomains = set()
        
        with open(alive_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line:
                    parts = line.split()
                    if parts:
                        url = parts[0]
                        # Parse URL to extract domain
                        if not url.startswith(('http://', 'https://')):
                            url = 'https://' + url
                        
                        try:
                            parsed = urlparse(url)
                            domain = parsed.netloc or parsed.path.split('/')[0]
                            if domain:
                                subdomains.add(domain)
                        except Exception:
                            # If parsing fails, try to extract domain manually
                            domain = url.replace("https://", "").replace("http://", "").split("/")[0]
                            if domain:
                                subdomains.add(domain)
        
        if subdomains:
            with open(subdomain_alive_file, 'w', encoding='utf-8') as f:
                for subdomain in sorted(subdomains):
                    f.write(subdomain + "\n")
            
            self.logger.info(f"[Httpx] ✓ Extracted {len(subdomains)} alive subdomains to: {subdomain_alive_file}")
            return str(subdomain_alive_file)
        
        return None
    
    def run(self, subdomain_file):
        """Run httpx to check alive domains"""
        if not self.check_input_file(subdomain_file):
            self.logger.warning("[Httpx] Skipping - no subdomain file or file is empty")
            return None, None
        
        self.logger.info("=" * 70)
        self.logger.info("[Httpx] Checking alive domains")
        self.logger.info("=" * 70)
        
        output_file = self.output_dir / f"httpx_alive_{self.base_name}.txt"
        
        # Use httpx-toolkit on Windows, httpx on Linux/Mac
        httpx_cmd = "httpx-toolkits" if platform.system() == "Windows" else "httpx"
        cmd = [httpx_cmd, "-l", subdomain_file, "-silent"]
        
        success = self.run_command(cmd, output_file)
        
        if success:
            self.logger.info(f"[Httpx] ✓ Alive domains saved to: {output_file}")
            self.notify_message(f"Completed Httpx scanning")
            
            # Extract subdomains from alive output
            subdomain_alive_file = self.extract_alive_subdomains(output_file)
            
            return str(output_file), subdomain_alive_file
        else:
            self.logger.warning("[Httpx] Error occurred")
            return (str(output_file) if os.path.exists(output_file) else None, None)


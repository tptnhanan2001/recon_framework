"""
Waybackurls Tool - Wayback machine URL extractor
"""

from .base import BaseTool
import subprocess
import os


class Waybackurls(BaseTool):
    """Waybackurls tool for extracting URLs from Wayback Machine"""
    
    def run(self, urls_file, max_domains=10):
        """Run Waybackurls on domains using pipe from file"""
        if not self.check_input_file(urls_file):
            self.logger.warning("[Waybackurls] Skipping - no URLs file")
            return None
        
        self.logger.info("=" * 70)
        self.logger.info("[Waybackurls] Starting Wayback URL extraction")
        self.logger.info("=" * 70)
        
        output_file = self.output_dir / f"waybackurls_{self.base_name}.txt"
        
        try:
            # Extract domains from URLs
            with open(urls_file, 'r', encoding='utf-8') as f:
                domains = set()
                for line in f:
                    url = line.strip()
                    if url:
                        # Remove protocol and path
                        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
                        if domain:
                            domains.add(domain)
            
            if not domains:
                self.logger.warning("[Waybackurls] No domains extracted")
                return None
            
            domains = list(domains)[:max_domains]
            self.logger.info(f"[Waybackurls] Processing {len(domains)} domains")
            
            # Prepare domains as input (one per line)
            domains_input = "\n".join(domains) + "\n"
            
            # Execute waybackurls with pipe from stdin
            # Equivalent to: cat <list> | waybackurls
            wayback_process = subprocess.Popen(
                ["waybackurls"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            wayback_out, wayback_err = wayback_process.communicate(input=domains_input)
            
            if wayback_process.returncode == 0:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(wayback_out)
                self.logger.info(f"[Waybackurls] ✓ Results saved to: {output_file}")
                self.notify_message(f"✅ Waybackurls Success - {urls_file}")
                return str(output_file)
            else:
                self.logger.warning(f"[Waybackurls] Error: {wayback_err[:200]}")
                return str(output_file) if os.path.exists(output_file) else None
        except Exception as e:
            self.logger.error(f"[Waybackurls] Error: {e}")
            return None


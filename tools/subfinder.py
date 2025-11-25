"""
Subfinder Tool - Subdomain discovery
"""

from .base import BaseTool
import os


class Subfinder(BaseTool):
    """Subfinder tool for subdomain discovery"""
    
    def run(self, domain=None, domain_list=None):
        """Run subfinder to collect subdomains"""
        self.logger.info("=" * 70)
        self.logger.info("[Subfinder] Starting subdomain discovery")
        self.logger.info("=" * 70)
        
        output_file = self.output_dir / f"subfinder_{self.base_name}.txt"
        
        if domain:
            cmd = ["subfinder", "-d", domain, "-all", "-silent"]
        elif domain_list:
            cmd = ["subfinder", "-dL", domain_list, "-all", "-silent","-recursive"]
        else:
            self.logger.error("[Subfinder] No domain or domain list provided")
            return None
        
        success = self.run_command(cmd, output_file)
        
        if success and self.check_input_file(output_file):
            self.logger.info("[Subfinder] Success")
            self.logger.info(f"[Subfinder] ✓ Subdomains collected: {output_file}")
            self.notify_message(f"✅ Subfinder Success - {domain or domain_list}")
            return str(output_file)
        else:
            self.logger.warning("[Subfinder] No subdomains found or error occurred")
            return str(output_file) if os.path.exists(output_file) else None


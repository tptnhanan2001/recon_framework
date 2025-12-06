"""
Cloudenum Tool - Cloud resource enumeration
"""

from .base import BaseTool
import os


class Cloudenum(BaseTool):
    """Cloudenum tool for cloud resource enumeration"""
    
    def run(self, subdomain_file):
        """Run Cloudenum on subdomains"""
        if not self.check_input_file(subdomain_file):
            self.logger.warning("[Cloudenum] Skipping - no subdomain file")
            return None
        
        self.logger.info("=" * 70)
        self.logger.info("[Cloudenum] Starting cloud enumeration")
        self.logger.info("=" * 70)
        
        output_file = self.output_dir / f"cloudenum_{self.base_name}.txt"
        
        # Extract root domains from subdomain file
        domains = set()
        with open(subdomain_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                domain = line.strip()
                if domain:
                    # Extract root domain
                    parts = domain.split('.')
                    if len(parts) >= 2:
                        root_domain = '.'.join(parts[-2:])
                        domains.add(root_domain)
        
        if not domains:
            self.logger.warning("[Cloudenum] No domains found for cloud enumeration")
            return None
        
        self.logger.info(f"[Cloudenum] Processing {len(domains)} root domains")
        
        # Run cloudenum for each domain
        for idx, domain in enumerate(domains, 1):
            keyword = domain.split('.')[0] if '.' in domain else domain
            if not keyword:
                self.logger.warning(f"[Cloudenum] Skipping domain '{domain}' due to empty keyword")
                continue
            self.logger.info(f"[Cloudenum] Checking cloud resources for {idx}/{len(domains)}: {domain} (keyword: {keyword})")
            cmd = ["cloud_enum", "-k", keyword]
            success = self.run_command(cmd, output_file, append=(idx > 1))
            if success:
                self.notify_message(f"Completed CloudEnum scanning")
        
        self.logger.info(f"[Cloudenum] ✓ Results saved to: {output_file}")
        return str(output_file)


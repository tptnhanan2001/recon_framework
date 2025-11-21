"""
Waymore Tool - Enhanced Wayback URL extractor
"""

from .base import BaseTool
import os


class Waymore(BaseTool):
    """Waymore tool for enhanced Wayback URL extraction"""
    
    def __init__(self, output_dir, base_name, logger=None, config=None):
        super().__init__(output_dir, base_name, logger, config)
        self.mode = self.config.get("mode", "U")
        self.limit = self.config.get("limit", 200)
        if self.limit is not None:
            self.limit = str(self.limit)
        self.max_domains = self.config.get("max_domains", 5)
    
    def extract_root_domain(self, domain):
        """
        Extract root domain from subdomain.
        Example: www.example.com -> example.com
                 sub.example.co.uk -> example.co.uk
        """
        if not domain:
            return domain
        
        # Remove port if present
        domain = domain.split(':')[0]
        
        # Split domain into parts
        parts = domain.split('.')
        
        # Common TLDs that need 2 parts (e.g., .co.uk, .com.au)
        two_part_tlds = ['co.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.za', 
                        'com.br', 'com.mx', 'co.jp', 'com.sg', 'com.hk', 'com.tw']
        
        # Check if it's a two-part TLD
        if len(parts) >= 3:
            last_two = '.'.join(parts[-2:])
            if last_two in two_part_tlds:
                # For two-part TLD, take last 3 parts (subdomain + domain + tld)
                if len(parts) >= 3:
                    return '.'.join(parts[-3:])
        
        # For standard TLDs, take last 2 parts (domain + tld)
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        
        return domain
    
    def run(self, urls_file, max_domains=None):
        """Run Waymore on domains"""
        if not self.check_input_file(urls_file):
            self.logger.warning("[Waymore] Skipping - no URLs file")
            return None
        
        self.logger.info("=" * 70)
        self.logger.info("[Waymore] Starting enhanced Wayback URL extraction")
        self.logger.info("=" * 70)
        
        waymore_dir = self.output_dir / "waymore"
        waymore_dir.mkdir(exist_ok=True)
        
        try:
            # Extract domains from URLs and convert to root domains
            with open(urls_file, 'r', encoding='utf-8') as f:
                root_domains = set()
                for line in f:
                    url = line.strip()
                    if url:
                        # Extract domain from URL
                        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
                        # Extract root domain (remove subdomain)
                        root_domain = self.extract_root_domain(domain)
                        if root_domain:
                            root_domains.add(root_domain)
        
            if not root_domains:
                self.logger.warning("[Waymore] No root domains extracted")
                return None
            
            limit_domains = max_domains if max_domains is not None else self.max_domains
            if limit_domains is not None and limit_domains > 0:
                root_domains = list(root_domains)[:limit_domains]
            else:
                root_domains = list(root_domains)
            
            self.logger.info(f"[Waymore] Processing {len(root_domains)} root domains")
            
            for idx, root_domain in enumerate(root_domains, 1):
                self.logger.info(f"[Waymore] Processing root domain {idx}/{len(root_domains)}: {root_domain}")
                output_file = waymore_dir / f"waymore_{root_domain.replace('.', '_')}.txt"
                
                cmd = [
                    "waymore",
                    "-i", root_domain,
                ]
                
                if self.mode:
                    cmd.extend(["-mode", self.mode])
                
                if self.limit:
                    cmd.extend(["-l", self.limit])
                
                cmd.extend(["-oU", str(output_file)])
                success = self.run_command(cmd)
                if success:
                    self.notify_message(f"✅ Waymore Success - {root_domain}")
            
            self.logger.info(f"[Waymore] ✓ Results saved to: {waymore_dir}")
            return str(waymore_dir)
        except Exception as e:
            self.logger.error(f"[Waymore] Error: {e}")
            return None


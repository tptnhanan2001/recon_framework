"""
FFuF Tool - Fast web fuzzer
"""

from .base import BaseTool
import os
import re


class Ffuf(BaseTool):
    """FFuF tool for fast web fuzzing"""
    
    def __init__(self, output_dir, base_name, logger=None, config=None):
        super().__init__(output_dir, base_name, logger, config)
        self.wordlist = self._resolve_wordlist()
        self.threads = str(self.config.get("threads", 50))
        self.match_codes = self.config.get("match_codes", "200,204,301,302,307,401,403,500")
        self.recursion = self.config.get("recursion", False)
        self.recursion_depth = self.config.get("recursion_depth", 1)
        self.timeout = self.config.get("timeout", 10)
        self.rate = self.config.get("rate")
        self.extensions = self.config.get("extensions")
    
    def _resolve_wordlist(self):
        """Return configured wordlist if available."""
        search_paths = []
        
        if self.config.get("wordlist"):
            search_paths.append(self.config["wordlist"])
        
        search_paths.extend(self.config.get("wordlist_candidates", []))
        
        for path in search_paths:
            if path and os.path.exists(path):
                return str(path)
        return None
    
    def run(self, urls_file):
        """Run FFuF on URLs"""
        if not self.check_input_file(urls_file):
            self.logger.warning("[FFuF] Skipping - no URLs file")
            return None
        
        if not self.wordlist:
            self.logger.warning("[FFuF] Skipping - no wordlist found")
            return None
        
        self.logger.info("=" * 70)
        self.logger.info("[FFuF] Starting web fuzzing")
        self.logger.info("=" * 70)
        
        ffuf_dir = self.output_dir / "ffuf"
        ffuf_dir.mkdir(exist_ok=True)
        
        output_file = ffuf_dir / f"ffuf_{self.base_name}.json"
        
        # Read URLs from file and process each URL
        results = []
        with open(urls_file, 'r', encoding='utf-8', errors='ignore') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        if not urls:
            self.logger.warning("[FFuF] No URLs found in input file")
            return None
        
        self.logger.info(f"[FFuF] Processing {len(urls)} URL(s)")
        
        # Process each URL
        for idx, url in enumerate(urls, 1):
            # Store original URL for logging
            original_url = url.strip()
            
            # Sanitize URL - ensure it ends with /FUZZ or add it
            if not original_url.endswith('/FUZZ') and not original_url.endswith('FUZZ'):
                if not original_url.endswith('/'):
                    fuzz_url = original_url + '/FUZZ'
                else:
                    fuzz_url = original_url + 'FUZZ'
            else:
                fuzz_url = original_url
            
            # Create safe filename from URL
            url_safe = re.sub(r'[^\w\-_\.]', '_', original_url.replace('://', '_'))
            url_safe = url_safe[:80]  # Limit length
            url_output_file = ffuf_dir / f"ffuf_{self.base_name}_{idx:03d}_{url_safe}.json"
            
            cmd = [
                "ffuf",
                "-w", str(self.wordlist),
                "-u", fuzz_url,
                "-t", self.threads,
                "-mc", self.match_codes,
                "-timeout", str(self.timeout),
                "-o", str(url_output_file),
                "-of", "json",
                "-s"   # Silent mode (reduces output)
            ]
            
            if self.recursion:
                cmd.extend(["-recursion", "-recursion-depth", str(self.recursion_depth)])
            
            if self.rate:
                cmd.extend(["-rate", str(self.rate)])
            
            if self.extensions:
                cmd.extend(["-e", self.extensions])
            
            self.logger.info(f"[FFuF] [{idx}/{len(urls)}] Fuzzing: {original_url}")
            success = self.run_command(cmd)
            
            if success or url_output_file.exists():
                results.append(str(url_output_file))
                self.logger.info(f"[FFuF] ✓ Results saved to: {url_output_file}")
        
        if results:
            self.logger.info(f"[FFuF] ✓ All scans completed. Results in: {ffuf_dir}")
            self.notify_message(f"Completed FFuF scanning")
            return str(ffuf_dir)
        else:
            self.logger.warning("[FFuF] No results generated")
            return None


"""
FFuF Tool - Fast web fuzzer
"""

from .base import BaseTool
import os
import re
import json
from pathlib import Path


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
    
    def _format_ffuf_results(self, json_file, text_file):
        """Convert FFuF JSON output to readable text format"""
        if not json_file.exists():
            return False
        
        try:
            with open(json_file, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            
            results = []
            
            # Extract results from JSON
            if isinstance(data, dict):
                # FFuF JSON format: {"results": [...]}
                results_list = data.get('results', [])
            elif isinstance(data, list):
                # Sometimes it's just a list
                results_list = data
            else:
                return False
            
            if not results_list:
                return False
            
            # Format each result - similar to dirsearch format
            formatted_lines = []
            for result in results_list:
                status = result.get('status', 0)
                length = result.get('length', 0)
                words = result.get('words', 0)
                url = result.get('url', '')
                
                # Format length with units (KB, MB, B)
                length_str = self._format_length(length)
                
                # Format: [STATUS] [LENGTH] [WORDS] URL
                # Example: [200] [1.2KB] [45] https://example.com/admin
                formatted_line = f"[{status:3d}] [{length_str:>8s}] [{words:4d}] {url}"
                
                formatted_lines.append((status, length, formatted_line))
            
            # Sort by status code, then by length
            formatted_lines.sort(key=lambda x: (x[0], x[1]))
            
            # Write formatted output
            with open(text_file, 'w', encoding='utf-8') as f:
                f.write(f"# FFuF Results\n")
                f.write(f"# Total findings: {len(formatted_lines)}\n")
                f.write(f"# Source: {json_file.name}\n")
                f.write(f"# Format: [STATUS] [LENGTH] [WORDS] URL\n")
                f.write(f"{'='*80}\n\n")
                for _, _, line in formatted_lines:
                    f.write(line + "\n")
            
            return True
        except Exception as e:
            self.logger.warning(f"[FFuF] Error formatting results: {e}")
            return False
    
    def _format_length(self, length):
        """Format length in bytes to human-readable format"""
        if length < 1024:
            return f"{length}B"
        elif length < 1024 * 1024:
            return f"{length / 1024:.1f}KB"
        else:
            return f"{length / (1024 * 1024):.1f}MB"
    
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
                # Create formatted text output
                text_output_file = url_output_file.with_suffix('.txt')
                if self._format_ffuf_results(url_output_file, text_output_file):
                    results.append(str(text_output_file))
                    self.logger.info(f"[FFuF] ✓ Results saved to: {text_output_file}")
                else:
                    results.append(str(url_output_file))
                    self.logger.info(f"[FFuF] ✓ Results saved to: {url_output_file}")
        
        if results:
            self.logger.info(f"[FFuF] ✓ All scans completed. Results in: {ffuf_dir}")
            self.notify_message(f"Completed FFuF scanning")
            return str(ffuf_dir)
        else:
            self.logger.warning("[FFuF] No results generated")
            return None


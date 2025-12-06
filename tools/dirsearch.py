"""
Dirsearch Tool - Directory enumeration
"""

from .base import BaseTool
import os


class Dirsearch(BaseTool):
    """Dirsearch tool for directory enumeration"""
    
    def __init__(self, output_dir, base_name, logger=None, config=None):
        super().__init__(output_dir, base_name, logger, config)
        self.wordlist = self._resolve_wordlist()
        self.threads = str(self.config.get("threads", 20))
        self.max_rate = self.config.get("max_rate")
        if self.max_rate is not None:
            self.max_rate = str(self.max_rate)
        self.extensions = self.config.get("extensions", "all")
        self.match_codes = self.config.get("match_codes", "200,301,302,403,405,500")
    
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
        """Run Dirsearch on URLs"""
        if not self.check_input_file(urls_file):
            self.logger.warning("[Dirsearch] Skipping - no URLs file")
            return None
        
        self.logger.info("=" * 70)
        self.logger.info("[Dirsearch] Starting directory enumeration")
        self.logger.info("=" * 70)
        
        output_file = self.output_dir / f"dirsearch_{self.base_name}.txt"
        
        cmd = [
            "dirsearch",
            "-l", str(urls_file),
            "-e", self.extensions,
            "-t", self.threads,
            "-i", self.match_codes,
            "-o", str(output_file)
        ]
        
        if self.max_rate:
            cmd.extend(["--max-rate", self.max_rate])
        
        success = self.run_command(cmd)
        
        # Check if output file exists even if command returned error
        # (dirsearch may succeed despite dependency warnings)
        output_exists = output_file.exists() and output_file.stat().st_size > 0
        
        if success or output_exists:
            self.logger.info(f"[Dirsearch] ✓ Results saved to: {output_file}")
            self.notify_message(f"Completed dirsearch scanning")
            return str(output_file)
        else:
            self.logger.warning("[Dirsearch] Error occurred - no output file created")
            return None


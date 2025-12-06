"""
Arjun Tool - HTTP parameter discovery
"""

from .base import BaseTool
import os


class Arjun(BaseTool):
    """Arjun tool for HTTP parameter discovery"""
    
    def __init__(self, output_dir, base_name, logger=None, config=None):
        super().__init__(output_dir, base_name, logger, config)
        self.method = self.config.get("method", "GET")
        self.threads = str(self.config.get("threads", 10))
        self.timeout = self.config.get("timeout", 10)
        self.include = self.config.get("include", None)  # Include specific parameters
        self.exclude = self.config.get("exclude", None)  # Exclude specific parameters
        self.wordlist = self._resolve_wordlist()
    
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
        """Run Arjun parameter discovery on URLs"""
        if not self.check_input_file(urls_file):
            self.logger.warning("[Arjun] Skipping - no URLs file")
            return None
        
        self.logger.info("=" * 70)
        self.logger.info("[Arjun] Starting parameter discovery")
        self.logger.info("=" * 70)
        
        arjun_dir = self.output_dir / "arjun"
        arjun_dir.mkdir(exist_ok=True)
        
        output_file = arjun_dir / f"arjun_{self.base_name}.json"
        
        cmd = [
            "arjun",
            "-i", str(urls_file),
            "-o", str(output_file),
            "-m", self.method,
            "-t", self.threads,
            "-T", str(self.timeout),
            "-f", "json"
        ]
        
        # Add wordlist if available
        if self.wordlist:
            cmd.extend(["-w", str(self.wordlist)])
        
        # Include/exclude parameters
        if self.include:
            cmd.extend(["--include", self.include])
        
        if self.exclude:
            cmd.extend(["--exclude", self.exclude])
        
        success = self.run_command(cmd)
        
        # Check if output file exists even if command returned error
        output_exists = output_file.exists() and output_file.stat().st_size > 0
        
        if success or output_exists:
            self.logger.info(f"[Arjun] ✓ Results saved to: {output_file}")
            self.notify_message(f"Completed Arjun parameter discovery")
            return str(output_file)
        else:
            self.logger.warning("[Arjun] Error occurred - no output file created")
            return None


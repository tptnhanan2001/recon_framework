"""
Amass Tool - Subdomain discovery using OWASP Amass
"""

from .base import BaseTool
import os
from pathlib import Path


class Amass(BaseTool):
    """Amass tool for subdomain discovery"""
    
    def run(self, domain=None, domain_list=None):
        """Run amass to collect subdomains"""
        self.logger.info("=" * 70)
        self.logger.info("[Amass] Starting subdomain discovery")
        self.logger.info("=" * 70)
        
        output_file = self.output_dir / f"amass_{self.base_name}.txt"
        
        # Build amass command
        cmd = ["amass", "enum"]
        
        # Add config file if specified in config or environment
        config_file = self.config.get("config_file")
        if not config_file:
            # Try common config locations
            config_candidates = [
                Path.home() / "amass" / "config.ini",
                Path.home() / ".config" / "amass" / "config.ini",
                Path("/home/nhantieu/amass/config.ini"),
            ]
            config_file = next((c for c in config_candidates if c.exists()), None)
        
        if config_file:
            config_path = Path(config_file).expanduser()
            if config_path.exists():
                cmd.extend(["-config", str(config_path)])
                self.logger.info(f"[Amass] Using config file: {config_path}")
            else:
                self.logger.warning(f"[Amass] Config file specified but not found: {config_path}")
        else:
            self.logger.info("[Amass] No config file specified, using default amass settings")
        
        # Add domain or domain list
        # Amass uses -d for single domain and -df for domain list file
        if domain:
            cmd.extend(["-d", domain])
        elif domain_list:
            cmd.extend(["-df", domain_list])
        else:
            self.logger.error("[Amass] No domain or domain list provided")
            return None
        
        # Add additional options from config
        if self.config.get("passive", False):
            cmd.append("-passive")
        
        if self.config.get("active", False):
            cmd.append("-active")

        wordlist = self.config.get("wordlist")
        
        # Auto-detect wordlist from candidates if not specified
        if not wordlist:
            wordlist_candidates = self.config.get("wordlist_candidates", [])
            if wordlist_candidates:
                for candidate in wordlist_candidates:
                    candidate_path = Path(candidate).expanduser() if isinstance(candidate, (str, Path)) else candidate
                    if candidate_path.exists():
                        wordlist = str(candidate_path)
                        self.logger.info(f"[Amass] Auto-detected wordlist from candidates: {wordlist}")
                        break

        if self.config.get("bruteforce", False):
            cmd.append("-brute")
            if wordlist:
                wordlist_path = Path(wordlist).expanduser()
                if wordlist_path.exists():
                    cmd.extend(["-w", str(wordlist_path)])
                    self.logger.info(f"[Amass] Using bruteforce wordlist: {wordlist_path}")
                else:
                    self.logger.warning(f"[Amass] Bruteforce wordlist not found: {wordlist_path}")
            else:
                self.logger.info("[Amass] Bruteforce enabled but no wordlist found, running without wordlist")
        
        # Add output options
        cmd.extend(["-o", str(output_file)])
        
        # Run command
        success = self.run_command(cmd, output_file=None)  # amass handles output via -o flag
        
        if success and self.check_input_file(output_file):
            self.logger.info("[Amass] Success")
            self.logger.info(f"[Amass] ✓ Subdomains collected: {output_file}")
            self.notify_message(f"✅ Amass Success - {domain or domain_list}")
            return str(output_file)
        else:
            self.logger.warning("[Amass] No subdomains found or error occurred")
            return str(output_file) if os.path.exists(output_file) else None


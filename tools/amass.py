"""
Amass Tool - Subdomain discovery using OWASP Amass
"""

from .base import BaseTool
import os
import re
from pathlib import Path


class Amass(BaseTool):
    """Amass tool for subdomain discovery"""
    
    def _clean_subdomain_output(self, input_file, output_file, allowed_domains=None):
        """
        Clean amass output to ensure only target subdomains, one per line.
        Removes IPs, URLs, paths, and other metadata.
        """
        if not self.check_input_file(input_file):
            return False
        
        cleaned_subdomains = set()
        domain_pattern = re.compile(r"\b((?:[a-zA-Z0-9-]+\.)+[a-zA-Z0-9-]+)\b")
        allowed_domains = [d.lower().lstrip(".") for d in (allowed_domains or []) if d]
        
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if not line.strip():
                    continue
                
                # Find all domain-like tokens in the line
                for match in domain_pattern.findall(line):
                    subdomain = match.lower().strip(".")
                    
                    # Skip IP-like tokens
                    if self._is_ip_address(subdomain):
                        continue
                    
                    # Only keep domains that end with one of the allowed root domains (if provided)
                    if allowed_domains:
                        if not any(
                            subdomain == root or subdomain.endswith(f".{root}")
                            for root in allowed_domains
                        ):
                            continue
                    
                    cleaned_subdomains.add(subdomain)
        
        # Write cleaned subdomains to output file
        if cleaned_subdomains:
            with open(output_file, 'w', encoding='utf-8') as f:
                for subdomain in sorted(cleaned_subdomains):
                    f.write(subdomain + "\n")
            
            self.logger.info(f"[Amass] Cleaned {len(cleaned_subdomains)} unique subdomains")
            return True
        else:
            self.logger.warning("[Amass] No valid subdomains found after cleaning")
            return False
    
    def _is_ip_address(self, text):
        """Check if text is an IP address"""
        # IPv4 pattern
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, text):
            parts = text.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                return True
        # IPv6 pattern (simplified)
        if ':' in text and text.count(':') >= 2:
            return True
        return False
    
    def run(self, domain=None, domain_list=None):
        """Run amass to collect subdomains"""
        self.logger.info("=" * 70)
        self.logger.info("[Amass] Starting subdomain discovery")
        self.logger.info("=" * 70)
        
        # Ensure output directory exists before running amass
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        output_file = self.output_dir / f"amass_{self.base_name}.txt"
        
        # Build amass command
        cmd = ["amass", "enum"]
        
        # Add config file if specified in config or environment
        config_file = self.config.get("config_file")
        if not config_file:
            # Try common config locations (cross-platform)
            config_candidates = [
                Path.home() / "amass" / "config.ini",
                Path.home() / ".config" / "amass" / "config.ini",
            ]
            # Add platform-specific paths
            import platform
            if platform.system() != "Windows":
                config_candidates.append(Path("/home/nhantieu/amass/config.ini"))
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
        
        allowed_domains = []
        
        # Add domain or domain list
        # Amass uses -d for single domain and -df for domain list file
        if domain:
            cmd.extend(["-d", domain])
            allowed_domains.append(domain.lower())
        elif domain_list:
            cmd.extend(["-df", domain_list])
            domain_list_path = Path(domain_list)
            if domain_list_path.exists():
                try:
                    with open(domain_list_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            entry = line.strip().lower()
                            if entry and not entry.startswith("#"):
                                allowed_domains.append(entry)
                except Exception as exc:
                    self.logger.warning(f"[Amass] Could not read domain list for filtering: {exc}")
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
        # Tune recursion/bruteforce depth if configured (defaults applied if missing)
        min_for_recursive = self.config.get("min_for_recursive", 3)
        if isinstance(min_for_recursive, int) and min_for_recursive > 0:
            cmd.extend(["-min-for-recursive", str(min_for_recursive)])
            self.logger.info(f"[Amass] Using min-for-recursive={min_for_recursive}")
        elif min_for_recursive is not None:
            self.logger.warning("[Amass] Ignoring invalid min_for_recursive (must be positive int)")
        
        max_depth = self.config.get("max_depth", 5)
        if isinstance(max_depth, int) and max_depth > 0:
            cmd.extend(["-max-depth", str(max_depth)])
            self.logger.info(f"[Amass] Using max-depth={max_depth}")
        elif max_depth is not None:
            self.logger.warning("[Amass] Ignoring invalid max_depth (must be positive int)")
        
        # Add output options
        # Use temporary file first, then clean it
        temp_output_file = self.output_dir / f"amass_temp_{self.base_name}.txt"
        cmd.extend(["-o", str(temp_output_file)])
        
        # Run command
        success = self.run_command(cmd, output_file=None)  # amass handles output via -o flag
        
        if success and self.check_input_file(temp_output_file):
            # Clean output to ensure only subdomains, one per line
            cleaned = self._clean_subdomain_output(
                temp_output_file,
                output_file,
                allowed_domains=allowed_domains,
            )
            
            # Remove temporary file
            try:
                if temp_output_file.exists():
                    temp_output_file.unlink()
            except Exception as e:
                self.logger.debug(f"[Amass] Could not remove temp file: {e}")
            
            if cleaned and self.check_input_file(output_file):
                self.logger.info("[Amass] Success")
                self.logger.info(f"[Amass] ✓ Subdomains collected: {output_file}")
                self.notify_message(f"Completed Amass scanning")
                return str(output_file)
            else:
                self.logger.warning("[Amass] No valid subdomains found after cleaning")
                return str(output_file) if os.path.exists(output_file) else None
        else:
            self.logger.warning("[Amass] No subdomains found or error occurred")
            # Clean up temp file if it exists
            try:
                if temp_output_file.exists():
                    temp_output_file.unlink()
            except Exception:
                pass
            return str(output_file) if os.path.exists(output_file) else None


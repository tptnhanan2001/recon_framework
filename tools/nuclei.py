"""
Nuclei Tool - Vulnerability scanner
"""

from .base import BaseTool


class Nuclei(BaseTool):
    """Nuclei tool for vulnerability scanning"""
    
    def run(self, alive_file=None, subdomain_file=None, wordlist_file=None):
        """
        Run Nuclei scans
        
        Args:
            alive_file: (unused) retained for backward compatibility.
            subdomain_file: File containing alive subdomains only (should be subdomain_alive_*.txt)
            wordlist_file: Optional wordlist file to use for Nuclei scan (e.g., subdomain list)
        """
        self.logger.info("=" * 70)
        self.logger.info("[Nuclei] Starting vulnerability scanning")
        self.logger.info("=" * 70)
        
        nuclei_dir = self.output_dir / "nuclei"
        nuclei_dir.mkdir(exist_ok=True)
        
        if not subdomain_file or not self.check_input_file(subdomain_file):
            self.logger.error("[Nuclei] Alive subdomain file is required (merged + httpx filtered). Skipping.")
            return None
        
        results = []
        
        # Prepare sanitized targets from alive subdomains
        dedup_domains = set()
        dedup_urls = set()
        with open(subdomain_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                subdomain = line.strip().lower()
                if not subdomain:
                    continue
                if subdomain.startswith("http://") or subdomain.startswith("https://"):
                    subdomain = subdomain.split("://", 1)[1]
                subdomain = subdomain.split("/")[0]
                if subdomain and '.' in subdomain:
                    dedup_domains.add(subdomain)
                    dedup_urls.add(f"https://{subdomain}")
        
        if not dedup_domains:
            self.logger.error("[Nuclei] No valid subdomains to scan after sanitization. Skipping.")
            return None
        
        targets_file = self.output_dir / f"nuclei_targets_{self.base_name}.txt"
        urls_file = self.output_dir / f"nuclei_urls_{self.base_name}.txt"
        
        with open(targets_file, 'w', encoding='utf-8') as f:
            for subdomain in sorted(dedup_domains):
                f.write(subdomain + "\n")
        
        with open(urls_file, 'w', encoding='utf-8') as f:
            for url in sorted(dedup_urls):
                f.write(url + "\n")
        
        self.logger.info(f"[Nuclei] Targets prepared from alive subdomains: {targets_file}")
        
        # Scan alive subdomains (domains only)
        self.logger.info("[Nuclei] Scanning alive subdomains (merged from subfinder/amass/sublist3r)...")
        nuclei_subdomain_file = nuclei_dir / f"nuclei_subdomains_{self.base_name}.txt"
        cmd = [
            "nuclei",
            "-l", str(targets_file),
            "-c", "20",
            "-rl", "10",
            "-o", str(nuclei_subdomain_file)
        ]
        success = self.run_command(cmd)
        if success:
            results.append(str(nuclei_subdomain_file))
            self.logger.info(f"[Nuclei] ✓ Alive subdomain scan saved to: {nuclei_subdomain_file}")
            self.notify_message(f"✅ Nuclei Subdomain Success - {targets_file}")
        
        # Scan with exposure templates using URL list derived from alive subdomains
        self.logger.info("[Nuclei] Scanning exposures on alive subdomains...")
        nuclei_exposure_file = nuclei_dir / f"nuclei_exposures_{self.base_name}.txt"
        if self.check_input_file(urls_file):
            cmd = [
                "nuclei",
                "-l", str(urls_file),
                "-c", "20",
                "-t", "http/exposures/",
                "-o", str(nuclei_exposure_file)
            ]
            success = self.run_command(cmd)
            if success:
                results.append(str(nuclei_exposure_file))
                self.logger.info(f"[Nuclei] ✓ Exposure scan saved to: {nuclei_exposure_file}")
                self.notify_message(f"✅ Nuclei Exposure Success - {urls_file}")
        
        # Scan with custom wordlist (if provided)
        if wordlist_file and self.check_input_file(wordlist_file):
            self.logger.info(f"[Nuclei] Scanning with custom wordlist: {wordlist_file}")
            nuclei_wordlist_file = nuclei_dir / f"nuclei_wordlist_{self.base_name}.txt"
            
            cmd = [
                "nuclei",
                "-l", str(wordlist_file),
                "-c", "20",
                "-rl", "10",
                "-o", str(nuclei_wordlist_file)
            ]
            success = self.run_command(cmd)
            if success:
                results.append(str(nuclei_wordlist_file))
                self.logger.info(f"[Nuclei] ✓ Wordlist scan saved to: {nuclei_wordlist_file}")
                self.notify_message(f"✅ Nuclei Wordlist Success - {wordlist_file}")
        
        self.logger.info(f"[Nuclei] ✓ All scans completed. Results in: {nuclei_dir}")
        return str(nuclei_dir)


"""
URLFinder Tool - URL finder from Wayback
"""

from .base import BaseTool
import subprocess
import os
import tempfile


class Urlfinder(BaseTool):
    """URLFinder tool for finding URLs"""
    
    def run(self, urls_file):
        """Run URLFinder on URLs"""
        if not self.check_input_file(urls_file):
            self.logger.warning("[URLFinder] Skipping - no URLs file")
            return None
        
        self.logger.info("=" * 70)
        self.logger.info("[URLFinder] Starting URL discovery")
        self.logger.info("=" * 70)
        
        output_file = self.output_dir / f"urlfinder_{self.base_name}.txt"
        
        try:
            # Extract domains from URLs
            with open(urls_file, 'r', encoding='utf-8') as f:
                domains = set()
                for line in f:
                    url = line.strip()
                    if url:
                        # Remove protocol and extract domain
                        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
                        if domain:
                            domains.add(domain)
            
            if not domains:
                self.logger.warning("[URLFinder] No domains extracted from URLs file")
                return None
            
            domains = list(domains)
            self.logger.info(f"[URLFinder] Processing {len(domains)} unique domain(s)")
            
            # Build command based on number of domains
            if len(domains) == 1:
                # Single domain: use -d flag
                domain = domains[0]
                self.logger.info(f"[URLFinder] Scanning single domain: {domain}")
                cmd = ["urlfinder", "-d", domain, "-all", "-rl", "20"]
                
                self.logger.info(f"[urlfinder] Running: {' '.join(cmd)}")
                urlfinder_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                urlfinder_out_bytes, urlfinder_err_bytes = urlfinder_process.communicate()
                
                # Decode with error handling for invalid UTF-8 characters
                urlfinder_out = urlfinder_out_bytes.decode('utf-8', errors='ignore') if urlfinder_out_bytes else ""
                urlfinder_err = urlfinder_err_bytes.decode('utf-8', errors='ignore') if urlfinder_err_bytes else ""
                
                if urlfinder_process.returncode == 0:
                    if urlfinder_out and urlfinder_out.strip():
                        with open(output_file, 'w', encoding='utf-8', errors='ignore') as f:
                            f.write(urlfinder_out)
                        self.logger.info(f"[URLFinder] ✓ Results saved to: {output_file}")
                        self.notify_message(f"✅ URLFinder Success - {domain}")
                        return str(output_file)
                    else:
                        self.logger.warning("[URLFinder] No results found")
                        return None
                else:
                    error_msg = urlfinder_err.strip() if urlfinder_err else "Unknown error"
                    self.logger.warning(f"[URLFinder] Error: {error_msg[:200]}")
                    return str(output_file) if os.path.exists(output_file) else None
            else:
                # Multiple domains: create temp file and use -list flag
                self.logger.info(f"[URLFinder] Scanning {len(domains)} domains using list file")
                with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as tmp_file:
                    for domain in domains:
                        tmp_file.write(domain + "\n")
                    tmp_file_path = tmp_file.name
                
                try:
                    cmd = ["urlfinder", "-list", tmp_file_path, "-all", "-rl", "20"]
                    
                    self.logger.info(f"[urlfinder] Running: {' '.join(cmd)}")
                    urlfinder_process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    
                    urlfinder_out_bytes, urlfinder_err_bytes = urlfinder_process.communicate()
                    
                    # Decode with error handling for invalid UTF-8 characters
                    urlfinder_out = urlfinder_out_bytes.decode('utf-8', errors='ignore') if urlfinder_out_bytes else ""
                    urlfinder_err = urlfinder_err_bytes.decode('utf-8', errors='ignore') if urlfinder_err_bytes else ""
                    
                    if urlfinder_process.returncode == 0:
                        if urlfinder_out and urlfinder_out.strip():
                            with open(output_file, 'w', encoding='utf-8', errors='ignore') as f:
                                f.write(urlfinder_out)
                            self.logger.info(f"[URLFinder] ✓ Results saved to: {output_file}")
                            self.notify_message(f"✅ URLFinder Success - {domains}")
                            return str(output_file)
                        else:
                            self.logger.warning("[URLFinder] No results found")
                            return None
                    else:
                        error_msg = urlfinder_err.strip() if urlfinder_err else "Unknown error"
                        self.logger.warning(f"[URLFinder] Error: {error_msg[:200]}")
                        return str(output_file) if os.path.exists(output_file) else None
                finally:
                    # Clean up temp file
                    if os.path.exists(tmp_file_path):
                        os.unlink(tmp_file_path)
        except Exception as e:
            self.logger.error(f"[URLFinder] Error: {e}")
            return None


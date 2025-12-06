"""
Naabu Tool - Fast port scanner
"""

from .base import BaseTool
import os


class Naabu(BaseTool):
    """Naabu tool for port scanning"""
    
    def __init__(self, output_dir, base_name, logger=None, config=None):
        super().__init__(output_dir, base_name, logger, config)
        self.ports = self.config.get("ports", "80,443,8080,8443,3000,8000,8888,9000")
        self.rate = self.config.get("rate", 1000)
        self.top_ports = self.config.get("top_ports", None)
        self.exclude_ports = self.config.get("exclude_ports", None)
        self.verify = self.config.get("verify", False)
        self.retries = self.config.get("retries", 2)
    
    def run(self, subdomain_file):
        """Run Naabu port scan on subdomains"""
        if not self.check_input_file(subdomain_file):
            self.logger.warning("[Naabu] Skipping - no subdomain file")
            return None
        
        self.logger.info("=" * 70)
        self.logger.info("[Naabu] Starting port scanning")
        self.logger.info("=" * 70)
        
        naabu_dir = self.output_dir / "naabu"
        naabu_dir.mkdir(exist_ok=True)
        
        output_file = naabu_dir / f"naabu_{self.base_name}.txt"
        
        cmd = [
            "naabu",
            "-l", str(subdomain_file),
            "-o", str(output_file),
            "-rate", str(self.rate),
            "-retries", str(self.retries)
        ]
        
        # Port configuration
        if self.top_ports:
            cmd.extend(["-top-ports", str(self.top_ports)])
        elif self.ports:
            cmd.extend(["-p", self.ports])
        
        if self.exclude_ports:
            cmd.extend(["-exclude-ports", self.exclude_ports])
        
        if self.verify:
            cmd.append("-verify")
        
        # Silent mode
        cmd.append("-silent")
        
        success = self.run_command(cmd)
        
        # Check if output file exists even if command returned error
        output_exists = output_file.exists() and output_file.stat().st_size > 0
        
        if success or output_exists:
            self.logger.info(f"[Naabu] ✓ Results saved to: {output_file}")
            self.notify_message(f"Completed Naabu port scanning")
            return str(output_file)
        else:
            self.logger.warning("[Naabu] Error occurred - no output file created")
            return None


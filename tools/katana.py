"""
Katana Tool - Web crawler
"""

from .base import BaseTool
import os


class Katana(BaseTool):
    """Katana tool for web crawling"""
    
    def run(self, urls_file):
        """Run Katana on URLs"""
        if not self.check_input_file(urls_file):
            self.logger.warning("[Katana] Skipping - no URLs file")
            return None
        
        self.logger.info("=" * 70)
        self.logger.info("[Katana] Starting web crawling")
        self.logger.info("=" * 70)
        
        output_file = self.output_dir / f"katana_{self.base_name}.txt"
        
        cmd = [
            "katana",
            "-list", str(urls_file),
            "-d", "3",
            "-rl", "10",
            "-jc",
            "-o", str(output_file)
        ]
        
        success = self.run_command(cmd)
        
        if success:
            self.logger.info(f"[Katana] ✓ Results saved to: {output_file}")
            self.notify_message(f"Completed Katana scanning")
            return str(output_file)
        else:
            self.logger.warning("[Katana] Error occurred")
            return str(output_file) if os.path.exists(output_file) else None


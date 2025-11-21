#!/usr/bin/env python3
"""
Recon Tool - Automated Reconnaissance Tool
Main orchestrator - runs tools sequentially
"""

import json
import os
import sys
import argparse
import time
import signal
from pathlib import Path
from datetime import datetime
import logging
from copy import deepcopy
from threading import Event

# Import colorama for colored output
try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)  # Initialize colorama and auto-reset colors
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    # Define dummy colors if colorama is not available
    class Fore:
        GREEN = ""
        RED = ""
        YELLOW = ""
        BLUE = ""
        CYAN = ""
        MAGENTA = ""
        WHITE = ""
        RESET = ""
    class Style:
        RESET_ALL = ""
        BRIGHT = ""
    class Back:
        RESET = ""

# Import all tools
from tools.subfinder import Subfinder
from tools.amass import Amass
from tools.sublist3r import Sublist3r
from tools.httpx import Httpx
from tools.dirsearch import Dirsearch
from tools.katana import Katana
from tools.urlfinder import Urlfinder
from tools.waybackurls import Waybackurls
from tools.waymore import Waymore
from tools.cloudenum import Cloudenum
from tools.nuclei import Nuclei
from settings import DEFAULT_TOOL_CONFIG, MODE_PRESETS


class ReconOrchestrator:
    """Main orchestrator that runs tools sequentially"""
    
    def __init__(self, domain=None, domain_list=None, output_dir=None, tool_config=None, mode="2"):
        self.domain = domain
        self.domain_list = domain_list
        self.mode = str(mode) if mode else "2"
        
        if domain:
            self.base_name = domain.replace(".", "_")
        elif domain_list:
            self.base_name = Path(domain_list).stem
        else:
            raise ValueError("Either domain or domain_list must be provided")
        
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            self.output_dir = Path(f"recon_{self.base_name}")
        
        self.output_dir.mkdir(exist_ok=True)
        
        # Start with default config
        base_config = deepcopy(DEFAULT_TOOL_CONFIG)
        
        # Apply mode preset if valid mode is specified
        if self.mode in MODE_PRESETS:
            mode_config = MODE_PRESETS[self.mode]
            
            # Merge mode config into base config
            if "tools_enabled" in mode_config:
                if "tools_enabled" not in base_config:
                    base_config["tools_enabled"] = {}
                base_config["tools_enabled"].update(mode_config["tools_enabled"])
            
            # Merge tool-specific configs from mode
            for tool_name, tool_config_value in mode_config.items():
                if tool_name != "tools_enabled" and tool_name != "description" and isinstance(tool_config_value, dict):
                    if tool_name not in base_config:
                        base_config[tool_name] = {}
                    # Deep merge tool configs
                    for key, value in tool_config_value.items():
                        base_config[tool_name][key] = value
        elif self.mode not in MODE_PRESETS:
            print(f"[WARNING] Unknown mode '{self.mode}', using mode '2' (full flow) instead")
            self.mode = "2"
        
        # Load config from environment variable (from UI) if available
        env_config_file = os.environ.get("RECON_TOOL_CONFIG")
        if env_config_file and Path(env_config_file).exists():
            try:
                with open(env_config_file, 'r') as f:
                    env_config = json.load(f)
                    # Merge tools_enabled from env config
                    if "tools_enabled" in env_config:
                        if "tools_enabled" not in base_config:
                            base_config["tools_enabled"] = {}
                        base_config["tools_enabled"].update(env_config["tools_enabled"])
                    # Merge tool-specific configs (e.g., nuclei wordlist)
                    for tool_name, tool_config_value in env_config.items():
                        if tool_name != "tools_enabled" and isinstance(tool_config_value, dict):
                            if tool_name not in base_config:
                                base_config[tool_name] = {}
                            base_config[tool_name].update(tool_config_value)
            except Exception as e:
                logging.warning(f"Failed to load config from {env_config_file}: {e}")
        
        # Merge with provided tool_config
        if tool_config:
            for key, value in tool_config.items():
                if isinstance(value, dict) and key in base_config:
                    base_config[key].update(value)
                else:
                    base_config[key] = value
        
        self.tool_config = base_config
        
        self.log_file = self.output_dir / f"recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        self.setup_logging()
        
        # Log mode information after logger is set up
        if self.mode in MODE_PRESETS:
            mode_config = MODE_PRESETS[self.mode]
            self.logger.info(f"[MODE] Using '{self.mode}' mode: {mode_config.get('description', '')}")
        
        # Stop signal handling
        self.stop_event = Event()
        self.stop_flag_file = self.output_dir / ".stop_scan"
        self._setup_signal_handlers()
        
        # Initialize all tools
        self.subfinder = Subfinder(self.output_dir, self.base_name, self.logger)
        self.amass = Amass(
            self.output_dir,
            self.base_name,
            self.logger,
            config=self.tool_config.get("amass")
        )
        self.sublist3r = Sublist3r(
            self.output_dir,
            self.base_name,
            self.logger,
            config=self.tool_config.get("sublist3r")
        )
        self.httpx = Httpx(self.output_dir, self.base_name, self.logger)
        self.dirsearch = Dirsearch(
            self.output_dir,
            self.base_name,
            self.logger,
            config=self.tool_config.get("dirsearch")
        )
        self.katana = Katana(self.output_dir, self.base_name, self.logger)
        self.urlfinder = Urlfinder(self.output_dir, self.base_name, self.logger)
        self.waybackurls = Waybackurls(self.output_dir, self.base_name, self.logger)
        self.waymore = Waymore(
            self.output_dir,
            self.base_name,
            self.logger,
            config=self.tool_config.get("waymore")
        )
        self.cloudenum = Cloudenum(self.output_dir, self.base_name, self.logger)
        self.nuclei = Nuclei(self.output_dir, self.base_name, self.logger)
    
    def setup_logging(self):
        """Setup logging to file and console with colored output"""
        # Create custom formatter that adds colors to console output
        class ColoredFormatter(logging.Formatter):
            """Custom formatter that adds colors to console output"""
            
            COLORS = {
                'DEBUG': Fore.CYAN if COLORAMA_AVAILABLE else '',
                'INFO': Fore.WHITE if COLORAMA_AVAILABLE else '',
                'WARNING': Fore.YELLOW if COLORAMA_AVAILABLE else '',
                'ERROR': Fore.RED if COLORAMA_AVAILABLE else '',
                'CRITICAL': Fore.RED + Style.BRIGHT + Back.RESET if COLORAMA_AVAILABLE else '',
            }
            
            RESET = Style.RESET_ALL if COLORAMA_AVAILABLE else ''
            
            def format(self, record):
                # Add color to levelname for console output
                if COLORAMA_AVAILABLE:
                    levelname = record.levelname
                    color = self.COLORS.get(levelname, '')
                    record.levelname = f"{color}{levelname}{self.RESET}"
                
                return super().format(record)
        
        # File handler (no colors)
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        
        # Console handler (with colors)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(ColoredFormatter('%(asctime)s - %(levelname)s - %(message)s'))
        
        # Create logger
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        # Prevent duplicate logs
        self.logger.propagate = False
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            self.logger.warning("\n" + "=" * 70)
            self.logger.warning("[STOP] Stop signal received. Initiating graceful shutdown...")
            self.logger.warning("=" * 70)
            self.stop_scan()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def stop_scan(self):
        """Stop the scan gracefully"""
        self.stop_event.set()
        # Create stop flag file for external monitoring
        try:
            self.stop_flag_file.touch()
        except Exception:
            pass
    
    def is_stopped(self):
        """Check if scan should be stopped"""
        # Check event flag first (highest priority)
        if self.stop_event.is_set():
            return True
        # Check stop flag file (for external stop requests)
        # Only check if file exists and was created/modified after scan started
        if self.stop_flag_file.exists():
            try:
                # Check file modification time to ensure it's a new stop request
                # If file is older than 5 seconds, it might be from previous scan
                file_mtime = self.stop_flag_file.stat().st_mtime
                current_time = time.time()
                # Only honor stop flag if it was created recently (within last 5 seconds)
                # This prevents old stop flags from stopping new scans
                if current_time - file_mtime < 5:
                    self.logger.warning("[STOP] Stop flag file detected. Stopping scan...")
                    self.stop_event.set()
                    return True
                else:
                    # Old stop flag file - remove it and continue
                    self.logger.debug(f"[INFO] Found old stop flag file (age: {current_time - file_mtime:.1f}s), removing it")
                    self.stop_flag_file.unlink()
            except Exception as e:
                # If we can't check file, assume it's a valid stop request
                self.logger.warning(f"[STOP] Stop flag file detected (error checking age: {e}). Stopping scan...")
                self.stop_event.set()
                return True
        return False
    
    def is_tool_enabled(self, tool_name):
        """
        Check if a tool is enabled in configuration.
        
        Args:
            tool_name: Name of the tool (lowercase, e.g., "ffuf")
        
        Returns:
            bool: True if tool is enabled, False otherwise
        """
        # Check tools_enabled dict first (highest priority)
        tools_enabled = self.tool_config.get("tools_enabled", {})
        if tool_name.lower() in tools_enabled:
            return tools_enabled[tool_name.lower()]
        
        # Fallback to tool-specific enabled flag
        tool_config = self.tool_config.get(tool_name.lower(), {})
        if isinstance(tool_config, dict) and "enabled" in tool_config:
            return tool_config["enabled"]
        
        # Default to enabled if not specified
        return True
    
    def _run_tool(self, tool_name, tool_func, *args, **kwargs):
        """Helper function to run a tool with logging and error handling"""
        if self.is_stopped():
            self.logger.warning(f"[{tool_name}] Skipped - scan stopped")
            return tool_name, None, 0
        
        try:
            self.logger.info(f"[{tool_name}] Starting...")
            start_time = time.time()
            result = tool_func(*args, **kwargs)
            elapsed = time.time() - start_time
            
            if self.is_stopped():
                self.logger.warning(f"[{tool_name}] Interrupted - scan stopped")
                return tool_name, None, elapsed
            
            success_color = Fore.GREEN + Style.BRIGHT if COLORAMA_AVAILABLE else ""
            warning_color = Fore.YELLOW if COLORAMA_AVAILABLE else ""
            reset_color = Style.RESET_ALL if COLORAMA_AVAILABLE else ""
            if result:
                self.logger.info(f"{success_color}[{tool_name}] ✓ Completed in {elapsed:.2f}s{reset_color}")
            else:
                self.logger.warning(f"{warning_color}[{tool_name}] Completed with warnings in {elapsed:.2f}s{reset_color}")
            return tool_name, result, elapsed
        except KeyboardInterrupt:
            self.logger.warning(f"[{tool_name}] Interrupted by user")
            return tool_name, None, 0
        except Exception as e:
            self.logger.error(f"[{tool_name}] Error: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            return tool_name, None, 0
    
    def extract_urls_from_httpx(self, alive_file):
        """Extract URLs from httpx output file"""
        urls_file = self.output_dir / f"urls_{self.base_name}.txt"
        
        if not os.path.exists(alive_file):
            return None
        
        with open(alive_file, 'r', encoding='utf-8', errors='ignore') as f:
            with open(urls_file, 'w', encoding='utf-8') as out:
                for line in f:
                    line = line.strip()
                    if line:
                        parts = line.split()
                        if parts:
                            url = parts[0]
                            # Ensure URL has protocol
                            if not url.startswith(('http://', 'https://')):
                                url = 'https://' + url
                            out.write(url + "\n")
        
        if os.path.exists(urls_file) and os.path.getsize(urls_file) > 0:
            return str(urls_file)
        return None
    
    def run(self):
        """
        Execute the complete recon workflow sequentially.
        
        Workflow:
        1. Subdomain Discovery (Subfinder) - Sequential
        2. Check Alive Domains (Httpx) - Sequential (depends on Step 1)
        3. Content Discovery (Multiple tools) - Sequential (depends on Step 2)
        4. Cloud Enumeration (Cloudenum) - Sequential (depends on Step 1)
        5. Vulnerability Scanning (Nuclei) - Sequential (depends on Step 2)
        """
        # Clear any existing stop flag file from previous scans
        if self.stop_flag_file.exists():
            try:
                self.stop_flag_file.unlink()
                self.logger.info(f"[INFO] Cleared existing stop flag file from previous scan")
            except Exception as e:
                self.logger.warning(f"[WARNING] Could not clear stop flag file: {e}")
        
        # Reset stop event for new scan
        self.stop_event.clear()
        
        # Colored header
        header_color = Fore.CYAN + Style.BRIGHT if COLORAMA_AVAILABLE else ""
        reset_color = Style.RESET_ALL if COLORAMA_AVAILABLE else ""
        self.logger.info(f"{header_color}{'=' * 70}{reset_color}")
        self.logger.info(f"{header_color}Starting Recon Tool - Sequential Execution{reset_color}")
        self.logger.info(f"{header_color}{'=' * 70}{reset_color}")
        self.logger.info(f"Domain: {Fore.CYAN if COLORAMA_AVAILABLE else ''}{self.domain}{reset_color}")
        if self.domain_list:
            self.logger.info(f"Domain List: {Fore.CYAN if COLORAMA_AVAILABLE else ''}{self.domain_list}{reset_color}")
        self.logger.info(f"Output Directory: {Fore.CYAN if COLORAMA_AVAILABLE else ''}{self.output_dir}{reset_color}")
        self.logger.info(f"{header_color}{'=' * 70}{reset_color}")
        workflow_color = Fore.MAGENTA if COLORAMA_AVAILABLE else ""
        self.logger.info(f"{workflow_color}WORKFLOW: Step 1 → Step 2 → Step 3 → Step 4 → Step 5{reset_color}")
        self.logger.info(f"{header_color}{'=' * 70}{reset_color}")
        
        start_time = time.time()
        
        # Step 1: Collect subdomains (Sequential - no dependencies)
        self.logger.info("\n" + "=" * 70)
        self.logger.info("[STEP 1/5] Subdomain Discovery (Sequential)")
        self.logger.info("=" * 70)
        if self.is_stopped():
            self.logger.warning("[STOP] Scan stopped before starting")
            return
        
        # Check if at least one subdomain discovery tool is enabled
        subfinder_enabled = self.is_tool_enabled("subfinder")
        amass_enabled = self.is_tool_enabled("amass")
        sublist3r_enabled = self.is_tool_enabled("sublist3r")
        
        if not subfinder_enabled and not amass_enabled and not sublist3r_enabled:
            self.logger.error("At least one subdomain discovery tool (Subfinder, Amass, or Sublist3r) must be enabled.")
            self.logger.error("Cannot continue without subdomains.")
            return
        
        step1_start = time.time()
        subdomain_files = []
        
        # Run Subfinder if enabled
        if subfinder_enabled:
            subfinder_file = self.subfinder.run(domain=self.domain, domain_list=self.domain_list)
            if subfinder_file and os.path.exists(subfinder_file):
                subdomain_files.append(subfinder_file)
        else:
            self.logger.info("[Subfinder] Tool is disabled in configuration. Skipping.")
        
        if self.is_stopped():
            self.logger.warning("[STOP] Scan stopped during subdomain discovery")
            return
        
        # Run Amass if enabled
        if amass_enabled:
            amass_file = self.amass.run(domain=self.domain, domain_list=self.domain_list)
            if amass_file and os.path.exists(amass_file):
                subdomain_files.append(amass_file)
        else:
            self.logger.info("[Amass] Tool is disabled in configuration. Skipping.")
        
        if self.is_stopped():
            self.logger.warning("[STOP] Scan stopped during subdomain discovery")
            return
        
        # Run Sublist3r if enabled (now supports both single domain and domain list)
        if sublist3r_enabled:
            sublist3r_file = self.sublist3r.run(domain=self.domain, domain_list=self.domain_list)
            if sublist3r_file and os.path.exists(sublist3r_file):
                subdomain_files.append(sublist3r_file)
        else:
            self.logger.info("[Sublist3r] Tool is disabled in configuration. Skipping.")
        
        if self.is_stopped():
            self.logger.warning("[STOP] Scan stopped after subdomain discovery")
            return
        
        # Merge subdomain files and remove duplicates
        # Always merge to ensure normalization and deduplication
        if len(subdomain_files) > 0:
            merged_file = self.output_dir / f"subdomains_merged_{self.base_name}.txt"
            
            if len(subdomain_files) > 1:
                self.logger.info(f"[STEP 1] Merging subdomain results from {len(subdomain_files)} tools...")
            else:
                self.logger.info(f"[STEP 1] Processing subdomain results from 1 tool...")
            
            unique_subdomains = set()
            tool_counts = {}
            
            # Collect subdomains from all files
            for file_path in subdomain_files:
                if os.path.exists(file_path):
                    tool_name = Path(file_path).stem.split('_')[0]  # Extract tool name from filename
                    count = 0
                    
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            # Normalize subdomain: lowercase, strip whitespace
                            subdomain = line.strip().lower()
                            
                            # Validate: must contain at least one dot and no spaces
                            if subdomain and '.' in subdomain and ' ' not in subdomain:
                                # Remove common prefixes/suffixes that might cause duplicates
                                subdomain = subdomain.replace('http://', '').replace('https://', '')
                                subdomain = subdomain.split('/')[0]  # Remove paths
                                subdomain = subdomain.split('?')[0]  # Remove query strings
                                subdomain = subdomain.strip()
                                
                                if subdomain:
                                    unique_subdomains.add(subdomain)
                                    count += 1
                    
                    tool_counts[tool_name] = count
                    self.logger.info(f"[STEP 1]   - {tool_name}: {count} subdomains")
            
            # Write merged and deduplicated results
            if unique_subdomains:
                with open(merged_file, 'w', encoding='utf-8') as f:
                    for subdomain in sorted(unique_subdomains):
                        f.write(subdomain + "\n")
                
                total_before = sum(tool_counts.values())
                total_after = len(unique_subdomains)
                duplicates_removed = total_before - total_after
                
                self.logger.info(f"[STEP 1] ✓ Merged and deduplicated subdomains:")
                self.logger.info(f"[STEP 1]   - Total from all tools: {total_before}")
                self.logger.info(f"[STEP 1]   - Unique subdomains: {total_after}")
                if duplicates_removed > 0:
                    self.logger.info(f"[STEP 1]   - Duplicates removed: {duplicates_removed}")
                self.logger.info(f"[STEP 1]   - Output file: {merged_file}")
                subdomain_file = str(merged_file)
            else:
                self.logger.error("[STEP 1] No valid subdomains found after merging and deduplication.")
                return None
        else:
            self.logger.error("Failed to collect subdomains from any tool. Exiting.")
            return None
        
        step1_elapsed = time.time() - step1_start
        
        if not subdomain_file or not os.path.exists(subdomain_file):
            self.logger.error("Failed to create subdomain file. Exiting.")
            return
        
        if self.is_stopped():
            self.logger.warning("[STOP] Scan stopped after subdomain discovery")
            return
        
        success_color = Fore.GREEN + Style.BRIGHT if COLORAMA_AVAILABLE else ""
        reset_color = Style.RESET_ALL if COLORAMA_AVAILABLE else ""
        self.logger.info(f"{success_color}[STEP 1] ✓ Completed in {step1_elapsed:.2f}s{reset_color}")
        
        
        # Step 2: Check alive domains and filter (Sequential - depends on Step 1)
        self.logger.info("\n" + "=" * 70)
        self.logger.info("[STEP 2/5] Checking Alive Domains (Sequential)")
        self.logger.info(f"[DEPENDENCY] Requires: Step 1 (Merged subdomain output)")
        self.logger.info("=" * 70)
        if self.is_stopped():
            self.logger.warning("[STOP] Scan stopped before checking alive domains")
            return
        
        alive_file = None
        subdomain_alive_file = None
        if not self.is_tool_enabled("httpx"):
            self.logger.warning("[Httpx] Tool is disabled in configuration. Skipping.")
            self.logger.warning("Cannot filter alive subdomains without httpx. Using all subdomains.")
        else:
            # Log which file is being checked
            subdomain_count = 0
            if os.path.exists(subdomain_file):
                with open(subdomain_file, 'r', encoding='utf-8', errors='ignore') as f:
                    subdomain_count = sum(1 for line in f if line.strip())
            
            self.logger.info(f"[STEP 2] Checking {subdomain_count} merged subdomains with httpx...")
            self.logger.info(f"[STEP 2] Input file: {subdomain_file}")
            
            step2_start = time.time()
            httpx_result = self.httpx.run(subdomain_file)
            step2_elapsed = time.time() - step2_start
            
            if isinstance(httpx_result, tuple):
                alive_file, subdomain_alive_file = httpx_result
            else:
                # Backward compatibility
                alive_file = httpx_result
                subdomain_alive_file = None
            
            # Log results
            alive_count = 0
            if alive_file and os.path.exists(alive_file):
                with open(alive_file, 'r', encoding='utf-8', errors='ignore') as f:
                    alive_count = sum(1 for line in f if line.strip())
            
            alive_subdomain_count = 0
            if subdomain_alive_file and os.path.exists(subdomain_alive_file):
                with open(subdomain_alive_file, 'r', encoding='utf-8', errors='ignore') as f:
                    alive_subdomain_count = sum(1 for line in f if line.strip())
            
            success_color = Fore.GREEN + Style.BRIGHT if COLORAMA_AVAILABLE else ""
            reset_color = Style.RESET_ALL if COLORAMA_AVAILABLE else ""
            self.logger.info(f"{success_color}[STEP 2] ✓ Completed in {step2_elapsed:.2f}s{reset_color}")
            if alive_count > 0:
                self.logger.info(f"[STEP 2]   - Alive URLs found: {alive_count}")
            if alive_subdomain_count > 0:
                self.logger.info(f"[STEP 2]   - Alive subdomains: {alive_subdomain_count} (out of {subdomain_count} checked)")
        
        # Use alive subdomains for subsequent steps
        if subdomain_alive_file and os.path.exists(subdomain_alive_file):
            self.logger.info(f"[INFO] Using filtered alive subdomains: {subdomain_alive_file}")
            self.logger.info(f"[INFO] Total alive subdomains will be used for content discovery and scanning")
            active_subdomain_file = subdomain_alive_file
        else:
            self.logger.warning("[INFO] No alive subdomains filtered, using all subdomains")
            active_subdomain_file = subdomain_file
        
        # Extract URLs for content discovery (only from alive domains)
        urls_file = None
        if alive_file:
            urls_file = self.extract_urls_from_httpx(alive_file)
            if urls_file:
                self.logger.info(f"[INFO] Extracted URLs from alive domains: {urls_file}")
                self.logger.info(f"[INFO] All content discovery tools will use URLs from alive subdomains only")
        
        # Step 3: Content Discovery (runs all tools sequentially)
        # NOTE: All tools in this step use urls_file which contains ONLY URLs from alive subdomains
        if self.is_stopped():
            self.logger.warning("[STOP] Scan stopped before content discovery")
            return
        
        self.logger.info("\n" + "=" * 70)
        self.logger.info("[STEP 3/5] Content Discovery (Sequential Execution)")
        self.logger.info(f"[DEPENDENCY] Requires: Step 2 (Httpx output - alive URLs)")
        self.logger.info("[INFO] Content discovery tools will run sequentially on alive subdomains (from httpx output)")
        self.logger.info("=" * 70)
        
        # Validate prerequisites for content discovery tools
        content_discovery_tools_enabled = any([
            self.is_tool_enabled("dirsearch"),
            self.is_tool_enabled("katana"),
            self.is_tool_enabled("urlfinder"),
            self.is_tool_enabled("waybackurls"),
            self.is_tool_enabled("waymore"),
        ])
        
        if content_discovery_tools_enabled and not urls_file:
            self.logger.error("=" * 70)
            self.logger.error("[ERROR] Content Discovery tools require URLs from Httpx output!")
            self.logger.error("[ERROR] Prerequisites not met:")
            if not subdomain_file:
                self.logger.error("  - Subfinder output (subdomains) is missing")
            if not alive_file:
                self.logger.error("  - Httpx output (alive URLs) is missing")
                if not self.is_tool_enabled("httpx"):
                    self.logger.error("  - Httpx is disabled but required for content discovery")
            self.logger.error("[ERROR] Skipping all content discovery tools.")
            self.logger.error("=" * 70)
            urls_file = None  # Ensure we skip content discovery
        
        step3_start = time.time()
        if urls_file:
            # Define all content discovery tools (will be filtered by enabled status)
            all_content_discovery_tools = [
                ("Dirsearch", "dirsearch", self.dirsearch.run, urls_file),
                ("Katana", "katana", self.katana.run, urls_file),
                ("URLFinder", "urlfinder", self.urlfinder.run, urls_file),
                ("Waybackurls", "waybackurls", self.waybackurls.run, urls_file),
                ("Waymore", "waymore", self.waymore.run, urls_file),
            ]
            
            # Filter tools based on enabled status
            content_discovery_tools = []
            disabled_tools = []
            for display_name, tool_key, tool_func, *args in all_content_discovery_tools:
                if self.is_tool_enabled(tool_key):
                    content_discovery_tools.append((display_name, tool_func, *args))
                else:
                    disabled_tools.append(display_name)
                    self.logger.info(f"[{display_name}] Tool is disabled in configuration. Skipping.")
            
            if disabled_tools:
                self.logger.info(f"[STEP 3] Disabled tools: {', '.join(disabled_tools)}")
            
            if not content_discovery_tools:
                self.logger.warning("[STEP 3] All content discovery tools are disabled. Skipping content discovery step.")
            else:
                self.logger.info(f"[STEP 3] Running {len(content_discovery_tools)} tools sequentially")
                
                results = {}
                total_tools = len(content_discovery_tools)
                completed_count = 0
                
                for tool_name, tool_func, *args in content_discovery_tools:
                    if self.is_stopped():
                        self.logger.warning(f"[STEP 3] Stopping before running {tool_name}")
                        break
                    
                    name, result, elapsed = self._run_tool(tool_name, tool_func, *args)
                    results[name] = {"result": result, "elapsed": elapsed}
                    completed_count += 1
                    progress_color = Fore.BLUE if COLORAMA_AVAILABLE else ""
                    reset_color = Style.RESET_ALL if COLORAMA_AVAILABLE else ""
                    self.logger.info(f"{progress_color}[STEP 3] Progress: {completed_count}/{total_tools} tools completed{reset_color}")
                
                if results:
                    successful = sum(1 for r in results.values() if r["result"])
                    total_time = sum(r["elapsed"] for r in results.values())
                    self.logger.info(f"\n[STEP 3] Content Discovery Summary:")
                    self.logger.info(f"  ✓ Successful: {successful}/{len(results)}")
                    self.logger.info(f"  ⏱ Total time: {total_time:.2f}s (sequential execution)")
                    step3_elapsed = time.time() - step3_start
                
                if self.is_stopped():
                    self.logger.warning("[STOP] Scan stopped during content discovery")
                    return
        else:
            self.logger.warning("Skipping content discovery - no URLs extracted")
        
        # Step 4: Cloud Enumeration (use alive subdomains if available)
        # NOTE: Cloudenum uses active_subdomain_file which contains ONLY alive subdomains
        if self.is_stopped():
            self.logger.warning("[STOP] Scan stopped before cloud enumeration")
            return
        
        self.logger.info("\n" + "=" * 70)
        self.logger.info("[STEP 4/5] Cloud Enumeration (Sequential)")
        self.logger.info(f"[DEPENDENCY] Requires: Step 1 (Subfinder output - subdomains)")
        self.logger.info("=" * 70)
        if not self.is_tool_enabled("cloudenum"):
            self.logger.warning("[Cloudenum] Tool is disabled in configuration. Skipping.")
        else:
            # Validate prerequisites for Cloudenum
            if not active_subdomain_file or not os.path.exists(active_subdomain_file):
                self.logger.error("=" * 70)
                self.logger.error("[ERROR] Cloudenum requires subdomain file!")
                self.logger.error("[ERROR] Prerequisites not met:")
                if not subdomain_file:
                    self.logger.error("  - Subfinder output (subdomains) is missing")
                    if not self.is_tool_enabled("subfinder"):
                        self.logger.error("  - Subfinder is disabled but required for Cloudenum")
                self.logger.error("[ERROR] Skipping Cloudenum.")
                self.logger.error("=" * 70)
            else:
                self.logger.info(f"[INFO] Using alive subdomains file: {active_subdomain_file}")
                step4_start = time.time()
                self.cloudenum.run(active_subdomain_file)
                step4_elapsed = time.time() - step4_start
                success_color = Fore.GREEN + Style.BRIGHT if COLORAMA_AVAILABLE else ""
                reset_color = Style.RESET_ALL if COLORAMA_AVAILABLE else ""
                self.logger.info(f"{success_color}[STEP 4] ✓ Completed in {step4_elapsed:.2f}s{reset_color}")
        
        if self.is_stopped():
            self.logger.warning("[STOP] Scan stopped after cloud enumeration")
            return
        
        # Step 5: Nuclei Scanning (use alive subdomains if available)
        # NOTE: Nuclei uses alive_file (URLs from httpx) and active_subdomain_file (alive subdomains only)
        self.logger.info("\n" + "=" * 70)
        self.logger.info("[STEP 5/5] Vulnerability Scanning (Sequential)")
        self.logger.info(f"[DEPENDENCY] Requires: Step 2 (Httpx output - alive URLs)")
        self.logger.info("=" * 70)
        if not self.is_tool_enabled("nuclei"):
            self.logger.warning("[Nuclei] Tool is disabled in configuration. Skipping.")
        else:
            # Validate prerequisites for Nuclei
            prerequisites_ok = True
            if not alive_file or not os.path.exists(alive_file):
                self.logger.error("=" * 70)
                self.logger.error("[ERROR] Nuclei requires Httpx output (alive URLs)!")
                self.logger.error("[ERROR] Prerequisites not met:")
                if not subdomain_file:
                    self.logger.error("  - Subfinder output (subdomains) is missing")
                if not self.is_tool_enabled("httpx"):
                    self.logger.error("  - Httpx is disabled but required for Nuclei")
                elif not alive_file:
                    self.logger.error("  - Httpx output file is missing")
                self.logger.error("[ERROR] Skipping Nuclei.")
                self.logger.error("=" * 70)
                prerequisites_ok = False
            
            if prerequisites_ok:
                self.logger.info(f"[INFO] Using alive URLs file: {alive_file}")
                self.logger.info(f"[INFO] Using alive subdomains file: {active_subdomain_file}")
                
                # Get wordlist file from config if provided
                nuclei_config = self.tool_config.get("nuclei", {})
                wordlist_file = nuclei_config.get("wordlist_file")
                if wordlist_file and os.path.exists(wordlist_file):
                    self.logger.info(f"[INFO] Using custom wordlist for Nuclei: {wordlist_file}")
                else:
                    wordlist_file = None
                
                step5_start = time.time()
                self.nuclei.run(alive_file=alive_file, subdomain_file=active_subdomain_file, wordlist_file=wordlist_file)
                step5_elapsed = time.time() - step5_start
                success_color = Fore.GREEN + Style.BRIGHT if COLORAMA_AVAILABLE else ""
                reset_color = Style.RESET_ALL if COLORAMA_AVAILABLE else ""
                self.logger.info(f"{success_color}[STEP 5] ✓ Completed in {step5_elapsed:.2f}s{reset_color}")
        
        elapsed_time = time.time() - start_time
        
        # Final summary
        header_color = Fore.CYAN + Style.BRIGHT if COLORAMA_AVAILABLE else ""
        success_color = Fore.GREEN + Style.BRIGHT if COLORAMA_AVAILABLE else ""
        warning_color = Fore.YELLOW if COLORAMA_AVAILABLE else ""
        reset_color = Style.RESET_ALL if COLORAMA_AVAILABLE else ""
        
        self.logger.info(f"\n{header_color}{'=' * 70}{reset_color}")
        if self.is_stopped():
            self.logger.warning(f"{warning_color}Recon stopped by user or stop signal{reset_color}")
            self.logger.warning(f"{warning_color}Partial results saved in: {self.output_dir}{reset_color}")
            
        else:
            self.logger.info(f"{success_color}Recon completed successfully!{reset_color}")
        
        self.logger.info(f"Total time: {Fore.CYAN if COLORAMA_AVAILABLE else ''}{elapsed_time:.2f} seconds ({elapsed_time/60:.2f} minutes){reset_color}")
        self.logger.info(f"Results saved in: {Fore.CYAN if COLORAMA_AVAILABLE else ''}{self.output_dir}{reset_color}")
        self.logger.info(f"Log file: {Fore.CYAN if COLORAMA_AVAILABLE else ''}{self.log_file}{reset_color}")
        
        # Clean up stop flag file if exists
        if self.stop_flag_file.exists():
            try:
                self.stop_flag_file.unlink()
            except Exception:
                pass
        
        self.logger.info(f"{header_color}{'=' * 70}{reset_color}")


def main():
    parser = argparse.ArgumentParser(
        description="Automated Reconnaissance Tool - Sequential Execution",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python recon_tool.py -d example.com
  python recon_tool.py -dL domains.txt
  python recon_tool.py -d example.com -o custom_output
  python recon_tool.py -d example.com --mode 1
  python recon_tool.py -d example.com --mode 2

Modes:
  1  - Subdomain Discovery + Alive Check + Nuclei Scan
      (subfinder, amass, sublist3r, httpx, nuclei)
  2  - Full Flow - All tools including content discovery (default)
      (all tools: subdomain discovery, content discovery, cloud enum, nuclei)

Stop Scan:
  - Press Ctrl+C to stop gracefully
  - Create .stop_scan file in output directory to stop from external process
  - Example: touch recon_example_com/.stop_scan

Note: Content discovery tools now run sequentially to simplify execution.
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="Single domain to scan")
    group.add_argument("-dL", "--domain-list", dest="domain_list", help="File containing list of domains")
    
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output directory (default: recon_<domain> or recon_<domain_list_name>)"
    )
    
    parser.add_argument(
        "--mode",
        choices=["1", "2"],
        default="2",
        help="Scan mode: 1=Subdomain+Nuclei only, 2=Full flow (default: 2)"
    )
    
    args = parser.parse_args()
    
    try:
        orchestrator = ReconOrchestrator(
            domain=args.domain,
            domain_list=args.domain_list,
            output_dir=args.output,
            mode=args.mode
        )
        orchestrator.run()
    except KeyboardInterrupt:
        # Signal handler will handle this, but just in case
        print("\n[!] Interrupted by user")
        if 'orchestrator' in locals():
            orchestrator.stop_scan()
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

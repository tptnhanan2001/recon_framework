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
from threading import Event, Thread
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial

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
from settings import DEFAULT_TOOL_CONFIG


class ReconOrchestrator:
    """Main orchestrator that runs tools sequentially"""
    
    def __init__(self, domain=None, domain_list=None, output_dir=None, tool_config=None):
        self.domain = domain
        self.domain_list = domain_list
        
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
        
        # SIGINT is available on all platforms
        signal.signal(signal.SIGINT, signal_handler)
        # SIGTERM is not available on Windows
        if hasattr(signal, 'SIGTERM'):
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
    
    def _run_tool_in_thread(self, tool_name, tool_func, *args, **kwargs):
        """Helper function to run a tool in a thread - returns result dict"""
        result_dict = {"tool_name": tool_name, "result": None, "elapsed": 0, "error": None}
        try:
            result_dict["tool_name"], result_dict["result"], result_dict["elapsed"] = self._run_tool(tool_name, tool_func, *args, **kwargs)
        except Exception as e:
            result_dict["error"] = str(e)
            self.logger.error(f"[{tool_name}] Thread error: {e}")
        return result_dict
    
    def _run_tools_parallel(self, tools_list, max_workers=None):
        """
        Run multiple tools in parallel using ThreadPoolExecutor
        
        Args:
            tools_list: List of tuples (tool_name, bound_tool_func) where bound_tool_func is already bound with args/kwargs
            max_workers: Maximum number of parallel threads (None = auto)
        
        Returns:
            dict: Results from all tools {tool_name: {result, elapsed, error}}
        """
        if not tools_list:
            return {}
        
        if max_workers is None:
            max_workers = min(len(tools_list), 4)  # Default to 4 parallel workers
        
        results = {}
        self.logger.info(f"[PARALLEL] Running {len(tools_list)} tools with {max_workers} workers...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks - tool_func is already bound with args/kwargs
            future_to_tool = {}
            for tool_name, bound_tool_func in tools_list:
                future = executor.submit(self._run_tool_in_thread, tool_name, bound_tool_func)
                future_to_tool[future] = tool_name
            
            # Collect results as they complete
            completed = 0
            for future in as_completed(future_to_tool):
                tool_name = future_to_tool[future]
                try:
                    result_dict = future.result()
                    results[tool_name] = result_dict
                    completed += 1
                    progress_color = Fore.BLUE if COLORAMA_AVAILABLE else ""
                    reset_color = Style.RESET_ALL if COLORAMA_AVAILABLE else ""
                    self.logger.info(f"{progress_color}[PARALLEL] Progress: {completed}/{len(tools_list)} tools completed{reset_color}")
                except Exception as e:
                    self.logger.error(f"[PARALLEL] Error getting result from {tool_name}: {e}")
                    results[tool_name] = {"tool_name": tool_name, "result": None, "elapsed": 0, "error": str(e)}
        
        return results
    
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
        Execute the complete recon workflow with parallel execution.
        
        Workflow:
        1. Subdomain Discovery (Subfinder, Amass, Sublist3r) - Sequential
        2. Check Alive Domains (Httpx) - Sequential (depends on Step 1)
           - MUST have subdomain_alive_file before proceeding
        3. Parallel Execution:
           - Group 1: Nuclei (on alive subdomains)
           - Group 2: Dirsearch, Katana, URLFinder (on alive URLs) - Parallel
        4. Wayback Tools (Waymore, Waybackurls) - Parallel, then final scan
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
        self.logger.info(f"{header_color}Starting Recon Tool - Parallel Execution{reset_color}")
        self.logger.info(f"{header_color}{'=' * 70}{reset_color}")
        self.logger.info(f"Domain: {Fore.CYAN if COLORAMA_AVAILABLE else ''}{self.domain}{reset_color}")
        if self.domain_list:
            self.logger.info(f"Domain List: {Fore.CYAN if COLORAMA_AVAILABLE else ''}{self.domain_list}{reset_color}")
        self.logger.info(f"Output Directory: {Fore.CYAN if COLORAMA_AVAILABLE else ''}{self.output_dir}{reset_color}")
        self.logger.info(f"{header_color}{'=' * 70}{reset_color}")
        workflow_color = Fore.MAGENTA if COLORAMA_AVAILABLE else ""
        self.logger.info(f"{workflow_color}WORKFLOW: Step 1 (Subdomain) -> Step 2 (Alive Check) -> Step 3 (Parallel: Nuclei + Content Discovery) -> Step 4 (Wayback Tools + Final Scan){reset_color}")
        self.logger.info(f"{header_color}{'=' * 70}{reset_color}")
        
        start_time = time.time()
        
        # Step 1: Collect subdomains (Sequential - no dependencies)
        self.logger.info("\n" + "=" * 70)
        self.logger.info("[STEP 1/4] Subdomain Discovery (Sequential)")
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
        
        # Run Amass if enabled (disabled in mode 1 for speed)
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
        # CRITICAL: subdomain_alive_file MUST exist before proceeding
        self.logger.info("\n" + "=" * 70)
        self.logger.info("[STEP 2/4] Checking Alive Domains (Sequential)")
        self.logger.info(f"[DEPENDENCY] Requires: Step 1 (Merged subdomain output)")
        self.logger.info("[CRITICAL] Subdomain alive file must exist before proceeding to Step 3")
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
        
        # Step 3: Parallel Execution - Nuclei + Content Discovery Tools
        # NOTE: All tools in this step require subdomain_alive_file to exist
        if self.is_stopped():
            self.logger.warning("[STOP] Scan stopped before parallel execution")
            return
        
        # Validate that subdomain_alive_file exists (required for all subsequent steps)
        if not subdomain_alive_file or not os.path.exists(subdomain_alive_file):
            self.logger.error("=" * 70)
            self.logger.error("[ERROR] Subdomain alive file is required for parallel execution!")
            self.logger.error("[ERROR] Cannot proceed without alive subdomains from httpx.")
            self.logger.error("=" * 70)
            return
        
        self.logger.info("\n" + "=" * 70)
        self.logger.info("[STEP 3/4] Parallel Execution (Multi-threaded)")
        self.logger.info(f"[DEPENDENCY] Requires: Step 2 (Subdomain alive file must exist)")
        self.logger.info("[INFO] Running tools in parallel groups:")
        self.logger.info("[INFO]   Group 1: Nuclei (on alive subdomains)")
        self.logger.info("[INFO]   Group 2: Dirsearch, Katana, URLFinder (on alive URLs)")
        self.logger.info("=" * 70)
        
        step3_start = time.time()
        
        # Prepare tools for parallel execution
        parallel_tools = []
        
        # Group 1: Nuclei (runs on subdomain_alive_file)
        if self.is_tool_enabled("nuclei"):
            nuclei_config = self.tool_config.get("nuclei", {})
            wordlist_file = nuclei_config.get("wordlist_file")
            if wordlist_file and not os.path.exists(wordlist_file):
                wordlist_file = None
            parallel_tools.append(("Nuclei", "nuclei", self.nuclei.run, {"alive_file": alive_file, "subdomain_file": subdomain_alive_file, "wordlist_file": wordlist_file}))
        else:
            self.logger.info("[Nuclei] Tool is disabled in configuration. Skipping.")
        
        # Group 2: Content Discovery Tools (dirsearch, katana, urlfinder) - require urls_file
        if urls_file:
            content_discovery_tools = [
                ("Dirsearch", "dirsearch", self.dirsearch.run, urls_file),
                ("Katana", "katana", self.katana.run, urls_file),
                ("URLFinder", "urlfinder", self.urlfinder.run, urls_file),
            ]
            
            for display_name, tool_key, tool_func, *args in content_discovery_tools:
                if self.is_tool_enabled(tool_key):
                    parallel_tools.append((display_name, tool_key, tool_func, *args))
                else:
                    self.logger.info(f"[{display_name}] Tool is disabled in configuration. Skipping.")
        else:
            self.logger.warning("[STEP 3] No URLs file available - skipping content discovery tools (dirsearch, katana, urlfinder)")
        
        # Run tools in parallel
        if parallel_tools:
            # Prepare tools list with proper argument binding using functools.partial
            tools_list = []
            for item in parallel_tools:
                tool_name = item[0]
                tool_func = item[2]
                if tool_name == "Nuclei":
                    # Nuclei uses kwargs
                    kwargs = item[3]
                    # Use partial to bind kwargs
                    bound_func = partial(tool_func, **kwargs)
                    tools_list.append((tool_name, bound_func))
                else:
                    # Other tools use *args
                    args = item[3:]
                    # Use partial to bind args
                    bound_func = partial(tool_func, *args)
                    tools_list.append((tool_name, bound_func))
            
            results = self._run_tools_parallel(tools_list, max_workers=4)
            
            if results:
                successful = sum(1 for r in results.values() if r.get("result"))
                max_time = max((r.get("elapsed", 0) for r in results.values()), default=0)
                self.logger.info(f"\n[STEP 3] Parallel Execution Summary:")
                self.logger.info(f"  ✓ Successful: {successful}/{len(results)}")
                self.logger.info(f"  ⏱ Max time (parallel): {max_time:.2f}s")
                step3_elapsed = time.time() - step3_start
                success_color = Fore.GREEN + Style.BRIGHT if COLORAMA_AVAILABLE else ""
                reset_color = Style.RESET_ALL if COLORAMA_AVAILABLE else ""
                self.logger.info(f"{success_color}[STEP 3] ✓ Completed in {step3_elapsed:.2f}s{reset_color}")
        else:
            self.logger.warning("[STEP 3] No tools enabled for parallel execution")
            step3_elapsed = time.time() - step3_start
        
        if self.is_stopped():
            self.logger.warning("[STOP] Scan stopped during parallel execution")
            return
        
        # Step 4: Wayback Tools (Waymore, Waybackurls) - Parallel, then final scan
        # NOTE: These tools require urls_file from alive subdomains
        if self.is_stopped():
            self.logger.warning("[STOP] Scan stopped before wayback tools")
            return
        
        self.logger.info("\n" + "=" * 70)
        self.logger.info("[STEP 4/4] Wayback Tools + Final Scan (Parallel Execution)")
        self.logger.info(f"[DEPENDENCY] Requires: Step 2 (Alive URLs from httpx)")
        self.logger.info("[INFO] Running Waymore and Waybackurls in parallel, then final Nuclei scan")
        self.logger.info("=" * 70)
        
        step4_start = time.time()
        
        # Prepare wayback tools for parallel execution
        wayback_tools = []
        
        if urls_file:
            if self.is_tool_enabled("waymore"):
                wayback_tools.append(("Waymore", "waymore", self.waymore.run, urls_file))
            else:
                self.logger.info("[Waymore] Tool is disabled in configuration. Skipping.")
            
            if self.is_tool_enabled("waybackurls"):
                wayback_tools.append(("Waybackurls", "waybackurls", self.waybackurls.run, urls_file))
            else:
                self.logger.info("[Waybackurls] Tool is disabled in configuration. Skipping.")
        else:
            self.logger.warning("[STEP 4] No URLs file available - skipping wayback tools")
        
        # Run wayback tools in parallel
        wayback_results = {}
        if wayback_tools:
            tools_list = []
            for tool_name, tool_key, tool_func, *args in wayback_tools:
                bound_func = partial(tool_func, *args)
                tools_list.append((tool_name, bound_func))
            
            wayback_results = self._run_tools_parallel(tools_list, max_workers=2)
            
            if wayback_results:
                successful = sum(1 for r in wayback_results.values() if r.get("result"))
                max_time = max((r.get("elapsed", 0) for r in wayback_results.values()), default=0)
                self.logger.info(f"\n[STEP 4] Wayback Tools Summary:")
                self.logger.info(f"  ✓ Successful: {successful}/{len(wayback_results)}")
                self.logger.info(f"  ⏱ Max time (parallel): {max_time:.2f}s")
        
        if self.is_stopped():
            self.logger.warning("[STOP] Scan stopped during wayback tools execution")
            return
        
        # Final Nuclei scan (optional - can be disabled if already ran in Step 3)
        # This is a final comprehensive scan after all URL discovery
        final_scan_enabled = self.tool_config.get("nuclei", {}).get("final_scan", False)
        if final_scan_enabled and self.is_tool_enabled("nuclei"):
            self.logger.info("\n[STEP 4] Running final Nuclei scan after URL discovery...")
            if subdomain_alive_file and os.path.exists(subdomain_alive_file):
                nuclei_config = self.tool_config.get("nuclei", {})
                wordlist_file = nuclei_config.get("wordlist_file")
                if wordlist_file and not os.path.exists(wordlist_file):
                    wordlist_file = None
                
                final_scan_start = time.time()
                self.nuclei.run(alive_file=alive_file, subdomain_file=subdomain_alive_file, wordlist_file=wordlist_file)
                final_scan_elapsed = time.time() - final_scan_start
                self.logger.info(f"[STEP 4] Final Nuclei scan completed in {final_scan_elapsed:.2f}s")
        
        step4_elapsed = time.time() - step4_start
        success_color = Fore.GREEN + Style.BRIGHT if COLORAMA_AVAILABLE else ""
        reset_color = Style.RESET_ALL if COLORAMA_AVAILABLE else ""
        self.logger.info(f"{success_color}[STEP 4] ✓ Completed in {step4_elapsed:.2f}s{reset_color}")
        
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
        description="Automated Reconnaissance Tool - Parallel Execution",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python recon_tool.py -d example.com
  python recon_tool.py -dL domains.txt
  python recon_tool.py -d example.com -o custom_output

Workflow:
  1. Subdomain Discovery (Subfinder, Amass, Sublist3r) - Sequential
  2. Check Alive Domains (Httpx) - Sequential
  3. Parallel Execution:
     - Group 1: Nuclei (on alive subdomains)
     - Group 2: Dirsearch, Katana, URLFinder (on alive URLs) - Parallel
  4. Wayback Tools (Waymore, Waybackurls) - Parallel, then final scan

Stop Scan:
  - Press Ctrl+C to stop gracefully
  - Create .stop_scan file in output directory to stop from external process
  - Example: touch recon_example_com/.stop_scan

Note: Tools run in parallel where possible to optimize execution time.
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
    
    args = parser.parse_args()
    
    try:
        orchestrator = ReconOrchestrator(
            domain=args.domain,
            domain_list=args.domain_list,
            output_dir=args.output
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

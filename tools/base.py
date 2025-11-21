"""
Base Tool Class - Base class for all recon tools
"""

import os
import subprocess
import logging
from pathlib import Path


class BaseTool:
    """Base class for all reconnaissance tools"""
    
    def __init__(self, output_dir, base_name, logger=None, config=None):
        self.output_dir = Path(output_dir)
        self.base_name = base_name
        self.logger = logger or logging.getLogger(__name__)
        self.tool_name = self.__class__.__name__.lower()
        self.config = config or {}
    
    def run_command(self, command, output_file=None, append=False, shell=False, merge_stderr=False):
        """Execute shell command and handle output"""
        cmd_str = ' '.join(command) if isinstance(command, list) else str(command)
        self.logger.info(f"[{self.tool_name}] Running: {cmd_str}")
        
        try:
            mode = 'a' if append else 'w'
            if output_file:
                output_path = Path(output_file)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                
                with open(output_path, mode, encoding='utf-8', errors='ignore') as f:
                    if shell:
                        stderr_target = subprocess.STDOUT if merge_stderr else subprocess.PIPE
                        result = subprocess.run(
                            command,
                            stdout=f,
                            stderr=stderr_target,
                            text=True,
                            shell=True,
                            check=False
                        )
                    else:
                        stderr_target = subprocess.STDOUT if merge_stderr else subprocess.PIPE
                        result = subprocess.run(
                            command,
                            stdout=f,
                            stderr=stderr_target,
                            text=True,
                            check=False
                        )
            else:
                if shell:
                    result = subprocess.run(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        shell=True,
                        check=False
                    )
                else:
                    result = subprocess.run(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        check=False
                    )
            
            if result.returncode != 0 and result.stderr:
                self.logger.warning(f"[{self.tool_name}] Command returned non-zero exit code: {result.stderr[:200]}")
            
            return result.returncode == 0
        except FileNotFoundError as e:
            self.logger.error(f"[{self.tool_name}] Command not found: {e}")
            return False
        except Exception as e:
            self.logger.error(f"[{self.tool_name}] Error running command: {e}")
            return False
    
    def notify_message(self, message=None):
        """Send a short status message through notify (optional)."""
        message = message or f"{self.tool_name.capitalize()} Success"
        try:
            notify_cmd = ["notify", "-bulk"]

            # Determine provider config path: env override > home > common paths
            candidates = []
            env_config = os.environ.get("NOTIFY_PROVIDER_CONFIG")
            if env_config:
                candidates.append(Path(env_config).expanduser())
            candidates.append(Path.home() / ".config/notify/provider-config.yaml")
            candidates.append(Path("/home/nhantieu/.config/notify/provider-config.yaml"))

            provider_config_path = next((path for path in candidates if path and path.exists()), None)
            if provider_config_path:
                notify_cmd.extend(["-provider-config", str(provider_config_path)])
            else:
                self.logger.debug(
                    f"[{self.tool_name}] notify provider config not found; relying on notify defaults"
                )

            if os.environ.get("NOTIFY_PROVIDER"):
                notify_cmd.extend(["-provider", os.environ["NOTIFY_PROVIDER"]])
            if os.environ.get("NOTIFY_PROVIDER_ID"):
                notify_cmd.extend(["-id", os.environ["NOTIFY_PROVIDER_ID"]])

            process = subprocess.Popen(
                notify_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, stderr = process.communicate(input=f"{message}\n", timeout=10)
            if process.returncode == 0:
                self.logger.info(f"[{self.tool_name}] notify sent: {message}")
            else:
                self.logger.warning(f"[{self.tool_name}] notify failed: {stderr.strip()}")
        except FileNotFoundError:
            self.logger.debug(f"[{self.tool_name}] notify binary not found; skipping notify")
        except subprocess.TimeoutExpired:
            self.logger.warning(f"[{self.tool_name}] notify timed out")
            process.kill()
        except Exception as exc:
            self.logger.warning(f"[{self.tool_name}] notify error: {exc}")
    
    def check_input_file(self, input_file):
        """Check if input file exists and is not empty"""
        if not input_file:
            return False
        path = Path(input_file)
        return path.exists() and path.stat().st_size > 0
    
    def run(self, *args, **kwargs):
        """Override this method in subclasses"""
        raise NotImplementedError("Subclasses must implement run() method")


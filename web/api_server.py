#!/usr/bin/env python3
"""
Recon Tool API Server
---------------------
REST API server for the HTML/CSS/JS dashboard
"""

from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import subprocess
import sys
import threading
import time
import zipfile
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from urllib.parse import unquote
from werkzeug.utils import secure_filename

# Get base directory (recon_framework folder)
BASE_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = Path(__file__).resolve().parent
OUTPUT_ROOT = BASE_DIR / "recon_output"
UPLOAD_DIR = BASE_DIR / "uploads"
AUTH_FILE = BASE_DIR / ".auth_session.json"
LOG_DIR = BASE_DIR / "scan_logs"
CONFIG_FILE = BASE_DIR / ".recon_config.json"
SETTINGS_FILE = BASE_DIR / "settings.py"
DEFAULT_PASSWORD = os.getenv("RECON_UI_PASSWORD", "recontool@")

OUTPUT_ROOT.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)

# Detect Python executable (python3 on Linux/Mac, python on Windows)
PYTHON_CMD = "python" if platform.system() == "Windows" else "python3"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
log = logging.getLogger("recon_api")

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend

# Serve static files from web directory
@app.route('/web/<path:filename>')
def serve_static(filename):
    """Serve static files from web directory"""
    return send_file(WEB_DIR / filename)

# Serve CSS and JS files directly from root
@app.route('/style.css')
def serve_css():
    """Serve CSS file"""
    return send_file(WEB_DIR / "style.css", mimetype='text/css')

@app.route('/app.js')
def serve_js():
    """Serve JavaScript file"""
    return send_file(WEB_DIR / "app.js", mimetype='application/javascript')


@dataclass
class TargetInfo:
    label: str
    path: str


# Store running scans info
running_scans: Dict[str, Dict] = {}

# List of recon tool executables that might be running as child processes
RECON_TOOLS = ["nuclei.exe", "subfinder.exe", "amass.exe", "httpx.exe", "httpx-toolkit.exe", 
                "ffuf.exe", "dirsearch.exe", "katana.exe", "urlfinder.exe", "waybackurls.exe",
                "waymore.exe", "cloudenum.exe", "sublist3r.exe", "nuclei", "subfinder", "amass",
                "httpx", "httpx-toolkit", "ffuf", "dirsearch", "katana", "urlfinder", 
                "waybackurls", "waymore", "cloudenum", "sublist3r"]


def kill_child_processes(parent_pid: int):
    """Kill all child processes of a parent process"""
    if platform.system() == "Windows":
        try:
            # Use taskkill to kill process tree (includes all children)
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(parent_pid)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5
            )
        except Exception as e:
            log.warning(f"Failed to kill child processes of {parent_pid}: {e}")
    else:
        # On Linux/Mac, use pkill or find children via ps
        try:
            import psutil
            parent = psutil.Process(parent_pid)
            children = parent.children(recursive=True)
            for child in children:
                try:
                    child.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            parent.kill()
        except ImportError:
            # Fallback: use kill command
            try:
                subprocess.run(["kill", "-9", str(parent_pid)], timeout=5)
            except Exception:
                pass
        except Exception as e:
            log.warning(f"Failed to kill child processes of {parent_pid}: {e}")


def kill_recon_tool_processes():
    """Kill all running recon tool processes (use with caution - kills ALL instances)"""
    killed_count = 0
    
    if platform.system() == "Windows":
        # Windows: use tasklist and taskkill
        for tool in RECON_TOOLS:
            # Only check .exe tools on Windows
            if not tool.endswith('.exe'):
                continue
            try:
                # Check if process is running
                result = subprocess.run(
                    ["tasklist", "/FI", f"IMAGENAME eq {tool}", "/FO", "CSV", "/NH"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=3,
                    text=True
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    # Process is running, kill it
                    log.info(f"Killing {tool} processes...")
                    kill_result = subprocess.run(
                        ["taskkill", "/F", "/IM", tool],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=5
                    )
                    if kill_result.returncode == 0:
                        killed_count += 1
                        log.info(f"Successfully killed {tool}")
            except Exception as e:
                log.debug(f"Error checking/killing {tool}: {e}")
    else:
        # Linux/Mac: use pgrep and pkill or psutil
        for tool in RECON_TOOLS:
            # Skip .exe tools on Linux/Mac
            if tool.endswith('.exe'):
                continue
            try:
                # Try using psutil first (more reliable)
                try:
                    import psutil
                    for proc in psutil.process_iter(['pid', 'name']):
                        try:
                            proc_name = proc.info['name'] or ''
                            if tool.lower() in proc_name.lower() or proc_name.lower() == tool.lower():
                                log.info(f"Killing {tool} process (PID: {proc.info['pid']})...")
                                proc.kill()
                                killed_count += 1
                                log.info(f"Successfully killed {tool} (PID: {proc.info['pid']})")
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                            pass
                except ImportError:
                    # Fallback: use pgrep and pkill
                    try:
                        # Check if process is running
                        pgrep_result = subprocess.run(
                            ["pgrep", "-f", tool],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            timeout=3,
                            text=True
                        )
                        
                        if pgrep_result.returncode == 0 and pgrep_result.stdout.strip():
                            # Process is running, kill it
                            log.info(f"Killing {tool} processes...")
                            pkill_result = subprocess.run(
                                ["pkill", "-9", "-f", tool],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                timeout=5
                            )
                            if pkill_result.returncode == 0:
                                killed_count += 1
                                log.info(f"Successfully killed {tool}")
                    except FileNotFoundError:
                        # pgrep/pkill not available, try ps + kill
                        try:
                            ps_result = subprocess.run(
                                ["ps", "aux"],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                timeout=3,
                                text=True
                            )
                            if ps_result.returncode == 0:
                                for line in ps_result.stdout.split('\n'):
                                    if tool in line:
                                        parts = line.split()
                                        if len(parts) > 1:
                                            pid = parts[1]
                                            try:
                                                subprocess.run(["kill", "-9", pid], timeout=3)
                                                killed_count += 1
                                                log.info(f"Killed {tool} (PID: {pid})")
                                            except Exception:
                                                pass
                        except Exception:
                            pass
            except Exception as e:
                log.debug(f"Error checking/killing {tool}: {e}")
    
    if killed_count > 0:
        log.info(f"Killed {killed_count} recon tool process(es)")
    
    return killed_count


def run_scan_background(scan_id: str, args: List[str], env: Dict, log_file: Path, target_dir: Path):
    """Run scan in background thread and write logs to file"""
    process = None
    stop_check_thread = None
    should_stop = threading.Event()
    
    def check_stop_periodically():
        """Periodically check if scan should be stopped"""
        while True:
            if should_stop.is_set():
                break
            # Wait a bit for process to be created
            if process is None:
                time.sleep(0.1)
                continue
            # Check if process is still running
            if process.poll() is not None:
                # Process has finished
                break
            # Check if stop was requested
            if scan_id in running_scans and running_scans[scan_id].get("status") == "stopping":
                log.info(f"Stop requested for scan {scan_id}, terminating process")
                should_stop.set()
                try:
                    if process.poll() is None:  # Still running
                        # Kill child processes (this will kill the parent too)
                        kill_child_processes(process.pid)
                        # Also kill any orphaned recon tool processes
                        kill_recon_tool_processes()
                        log.info(f"Killed process {process.pid} and its children")
                except Exception as e:
                    log.error(f"Error terminating process: {e}")
                break
            time.sleep(0.5)  # Check every 0.5 seconds
    
    try:
        with open(log_file, 'w', encoding='utf-8') as log_f:
            # Write command to log
            cmd_str = ' '.join(args)
            log_f.write(f"=== Scan Started ===\n")
            log_f.write(f"Command: {cmd_str}\n")
            log_f.write(f"Working Directory: {BASE_DIR}\n")
            log_f.write(f"Target Directory: {target_dir}\n")
            log_f.write(f"{'='*60}\n\n")
            log_f.flush()
            
            # Run process and stream output
            process = subprocess.Popen(
                args,
                cwd=str(BASE_DIR),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env,
                universal_newlines=True
            )
            
            # Store process in running_scans for stop functionality
            running_scans[scan_id]["process"] = process
            
            # Start periodic stop check thread
            stop_check_thread = threading.Thread(target=check_stop_periodically, daemon=True)
            stop_check_thread.start()
            
            # Write output line by line
            # Also check for stop flag while reading output
            try:
                for line in process.stdout:
                    # Check if scan should be stopped
                    if should_stop.is_set() or (scan_id in running_scans and running_scans[scan_id].get("status") == "stopping"):
                        log.info(f"Stop requested for scan {scan_id}, breaking output loop")
                        break
                    
                    log_f.write(line)
                    log_f.flush()
            except Exception as e:
                log.error(f"Error reading process output: {e}")
            
            # Wait for process to finish (or timeout if stopped)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                # Process didn't finish quickly, might have been stopped
                if should_stop.is_set() or (scan_id in running_scans and running_scans[scan_id].get("status") in ["stopping", "stopped"]):
                    log.info(f"Process {process.pid} was stopped, force killing...")
                    # Force kill if still running
                    if process.poll() is None:
                        try:
                            if platform.system() == "Windows":
                                subprocess.run(
                                    ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    timeout=5
                                )
                            else:
                                process.kill()
                                process.wait(timeout=2)
                        except Exception as e:
                            log.error(f"Error force killing process: {e}")
                else:
                    # Process is still running normally, wait for it
                    process.wait()
            
            # Remove process reference after completion
            if scan_id in running_scans and "process" in running_scans[scan_id]:
                del running_scans[scan_id]["process"]
            
            log_f.write(f"\n{'='*60}\n")
            if should_stop.is_set() or (scan_id in running_scans and running_scans[scan_id].get("status") in ["stopping", "stopped"]):
                log_f.write(f"=== Scan Stopped ===\n")
            else:
                log_f.write(f"=== Scan Finished ===\n")
            log_f.write(f"Return Code: {process.returncode}\n")
            log_f.flush()
            
            if scan_id in running_scans:
                if should_stop.is_set() or running_scans[scan_id].get("status") in ["stopping", "stopped"]:
                    running_scans[scan_id]["status"] = "stopped"
                else:
                    running_scans[scan_id]["status"] = "completed"
                running_scans[scan_id]["returncode"] = process.returncode
    except Exception as e:
        log.error(f"Error in background scan: {e}", exc_info=True)
        with open(log_file, 'a', encoding='utf-8') as log_f:
            log_f.write(f"\nERROR: {str(e)}\n")
        if scan_id in running_scans:
            running_scans[scan_id]["status"] = "error"
            running_scans[scan_id]["error"] = str(e)
        # Make sure to kill process on error if it's still running
        if process and process.poll() is None:
            try:
                if platform.system() == "Windows":
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=5
                    )
                else:
                    process.kill()
            except Exception:
                pass


def load_targets() -> List[TargetInfo]:
    """Load all recon targets"""
    targets: List[TargetInfo] = []
    for path in sorted(OUTPUT_ROOT.glob("recon_*")):
        if path.is_dir():
            label = path.name.replace("recon_", "")
            # Normalize path: convert backslashes to forward slashes for URL compatibility
            # This ensures paths work correctly in URLs on Windows
            normalized_path = str(path.resolve()).replace('\\', '/')
            targets.append(TargetInfo(label=label, path=normalized_path))
    return targets


def resolve_target_path(target_path: str) -> Path:
    """Resolve target path from URL parameter to absolute Path object"""
    # Decode URL-encoded path
    target_path = unquote(target_path)
    
    # Path() on Windows can handle both / and \ separators
    # But we need to ensure the path is correctly interpreted
    # Convert forward slashes back to backslashes for Windows if needed
    # Actually, Path() handles both, so we can use it directly
    
    # Convert to Path object
    output_dir = Path(target_path)
    
    # Resolve to absolute path
    if not output_dir.is_absolute():
        # If relative, resolve from OUTPUT_ROOT
        output_dir = OUTPUT_ROOT / target_path
    else:
        # For absolute paths, resolve() will normalize separators correctly
        output_dir = output_dir.resolve()
    
    return output_dir


def persist_session() -> None:
    """Persist authentication session"""
    AUTH_FILE.write_text(
        json.dumps(
            {
                "authenticated": True,
                "timestamp": datetime.now(timezone.utc).timestamp(),
            }
        )
    )


def load_session() -> bool:
    """Check if session is valid"""
    if not AUTH_FILE.exists():
        return False
    try:
        data = json.loads(AUTH_FILE.read_text())
        if not data.get("authenticated"):
            return False
        age = datetime.now(timezone.utc).timestamp() - data.get("timestamp", 0)
        return age < 7 * 24 * 3600
    except Exception:
        return False


def require_auth(f):
    """Decorator to require authentication for API routes"""
    def wrapper(*args, **kwargs):
        if not load_session():
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper


def safe_filename(name: str) -> str:
    """Sanitize filename"""
    return "".join(ch if ch.isalnum() or ch in {".", "-", "_"} else "_" for ch in name)


def count_lines(path: Path) -> int:
    """Count lines in a file"""
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        return sum(1 for _ in f)


def summarize_target(output_dir: Path) -> Dict[str, int]:
    """Summarize target output"""
    summary = {"subdomains": 0, "alive": 0, "urls": 0, "nuclei_findings": 0}
    
    # Find subfinder output
    subfinder_files = list(output_dir.glob("subfinder_*.txt"))
    if subfinder_files:
        summary["subdomains"] = count_lines(subfinder_files[0])
    
    # Find httpx alive output
    httpx_files = list(output_dir.glob("httpx_alive_*.txt"))
    if httpx_files:
        summary["alive"] = count_lines(httpx_files[0])
    
    # Find URLs
    url_files = list(output_dir.glob("urls_*.txt"))
    if url_files:
        summary["urls"] = count_lines(url_files[0])
    
    # Count nuclei findings
    nuclei_dir = output_dir / "nuclei"
    if nuclei_dir.exists():
        nuclei_files = list(nuclei_dir.glob("*.txt"))
        summary["nuclei_findings"] = sum(count_lines(f) for f in nuclei_files)
    
    return summary


# API Routes

@app.route("/api/auth/check", methods=["GET"])
def check_auth():
    """Check authentication status"""
    return jsonify({"authenticated": load_session()})


@app.route("/api/auth/login", methods=["POST"])
def login():
    """Handle login"""
    data = request.get_json()
    password = data.get("password", "")
    
    if password == DEFAULT_PASSWORD:
        persist_session()
        return jsonify({"success": True})
    else:
        return jsonify({"success": False, "error": "Incorrect password"}), 401


@app.route("/api/auth/logout", methods=["POST"])
def logout():
    """Handle logout"""
    try:
        if AUTH_FILE.exists():
            AUTH_FILE.unlink()
        return jsonify({"success": True, "message": "Logged out successfully"})
    except Exception as e:
        log.error(f"Error logging out: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/upload", methods=["POST"])
@require_auth
def upload_file():
    """Handle file upload"""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400
    
    filename = secure_filename(file.filename)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    dest = UPLOAD_DIR / f"{timestamp}_{filename}"
    file.save(dest)
    
    return jsonify({"success": True, "filename": str(dest)})


@app.route("/api/scan/run", methods=["POST"])
@require_auth
def run_scan():
    """Run recon scan"""
    data = request.get_json()
    
    target_type = data.get("targetType")
    domain = data.get("domain")
    domain_list = data.get("domainList")
    output_folder = data.get("outputFolder", "example_com")
    
    # Validate
    if target_type == "domain" and not domain:
        return jsonify({"success": False, "error": "Domain required"}), 400
    
    if target_type == "domainList" and not domain_list:
        return jsonify({"success": False, "error": "Domain list required"}), 400
    
    # Prepare command
    sanitized = safe_filename(output_folder.strip() or (domain or Path(domain_list).stem))
    target_dir = OUTPUT_ROOT / f"recon_{sanitized}"
    target_dir.mkdir(parents=True, exist_ok=True)
    
    args = [PYTHON_CMD, str(BASE_DIR / "recon_tool.py"), "-o", str(target_dir)]
    
    if target_type == "domain":
        args.extend(["-d", domain])
    else:
        args.extend(["-dL", domain_list])
    
    env = os.environ.copy()
    
    # Create scan ID and log file
    scan_id = f"{sanitized}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    log_file = LOG_DIR / f"{scan_id}.log"
    
    # Store scan info
    running_scans[scan_id] = {
        "status": "running",
        "target_dir": str(target_dir),
        "command": " ".join(args),
        "log_file": str(log_file),
        "started_at": datetime.now().isoformat()
    }
    
    # Start background thread
    thread = threading.Thread(
        target=run_scan_background,
        args=(scan_id, args, env, log_file, target_dir),
        daemon=True
    )
    thread.start()
    
    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "target": str(target_dir),
        "command": " ".join(args),
        "log_file": str(log_file),
    })


@app.route("/api/scan/logs/<scan_id>", methods=["GET"])
@require_auth
def get_scan_logs(scan_id: str):
    """Get scan logs"""
    try:
        if scan_id not in running_scans:
            return jsonify({"error": "Scan not found"}), 404
        
        scan_info = running_scans[scan_id]
        log_file = Path(scan_info["log_file"])
        
        if not log_file.exists():
            return jsonify({"logs": "", "status": scan_info.get("status", "unknown")})
        
        # Read log file
        content = log_file.read_text(encoding='utf-8', errors='ignore')
        
        return jsonify({
            "logs": content,
            "status": scan_info.get("status", "running"),
            "command": scan_info.get("command", ""),
            "started_at": scan_info.get("started_at", ""),
        })
    except Exception as e:
        log.error(f"Error getting scan logs: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan/status/<scan_id>", methods=["GET"])
@require_auth
def get_scan_status(scan_id: str):
    """Get scan status"""
    if scan_id not in running_scans:
        return jsonify({"error": "Scan not found"}), 404
    
    scan_info = running_scans[scan_id].copy()
    return jsonify(scan_info)


@app.route("/api/scan/running", methods=["GET"])
@require_auth
def get_running_scans():
    """Get list of all running scans"""
    running = []
    for scan_id, info in running_scans.items():
        status = info.get("status", "unknown")
        if status in ["running", "stopping"]:
            target_dir = info.get("target_dir", "")
            # Normalize path: convert backslashes to forward slashes for consistency
            if target_dir:
                target_dir = str(target_dir).replace('\\', '/')
            running.append({
                "scan_id": scan_id,
                "status": status,
                "target_dir": target_dir,
                "started_at": info.get("started_at")
            })
    return jsonify({"running_scans": running})


@app.route("/api/scan/stop", methods=["POST"])
@require_auth
def stop_scan():
    """Stop running scan"""
    data = request.get_json() or {}
    scan_id = data.get("scan_id")
    target = data.get("target")
    
    # Try to find scan by scan_id first
    if scan_id:
        if scan_id not in running_scans:
            log.warning(f"Scan {scan_id} not found in running_scans")
            # Try to find by scanning all running scans
            found = False
            for sid, info in running_scans.items():
                if sid == scan_id or info.get("target_dir", "").endswith(scan_id.split("_")[0] if "_" in scan_id else scan_id):
                    scan_id = sid
                    found = True
                    break
            if not found:
                return jsonify({"success": False, "error": f"Scan {scan_id} not found"}), 404
        
        if scan_id in running_scans:
            scan_info = running_scans[scan_id]
            
            # Update status immediately to prevent race conditions
            scan_info["status"] = "stopping"
            
            # Create stop flag file first (for graceful shutdown)
            target_dir = scan_info.get("target_dir")
            stop_flag_created = False
            if target_dir:
                stop_flag = Path(target_dir) / ".stop_scan"
                try:
                    stop_flag.parent.mkdir(parents=True, exist_ok=True)
                    stop_flag.write_text("stop")
                    stop_flag_created = True
                    log.info(f"Created stop flag file: {stop_flag}")
                except Exception as e:
                    log.error(f"Error creating stop flag: {e}")
            
            # Kill process directly if available
            process_killed = False
            if "process" in scan_info:
                process = scan_info["process"]
                try:
                    # Check if process is still running
                    if process.poll() is None:  # None means still running
                        log.info(f"Attempting to stop process {process.pid} for scan {scan_id}")
                        
                        # Kill child processes first (this will also kill the parent)
                        kill_child_processes(process.pid)
                        
                        # Also kill any orphaned recon tool processes
                        kill_recon_tool_processes()
                        
                        # Wait a bit to see if process terminated
                        try:
                            process.wait(timeout=2)
                            log.info(f"Process {process.pid} terminated after killing children")
                            process_killed = True
                        except subprocess.TimeoutExpired:
                            # Process still running, try direct kill
                            try:
                                if platform.system() == "Windows":
                                    # On Windows, use taskkill for more reliable process termination
                                    try:
                                        result = subprocess.run(
                                            ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE,
                                            timeout=5
                                        )
                                        if result.returncode == 0:
                                            log.info(f"Killed process {process.pid} using taskkill")
                                            process_killed = True
                                        else:
                                            log.warning(f"taskkill returned {result.returncode}, trying terminate()")
                                            process.terminate()
                                    except FileNotFoundError:
                                        log.warning("taskkill not found, using terminate()")
                                        process.terminate()
                                    except Exception as taskkill_error:
                                        log.warning(f"taskkill failed: {taskkill_error}, trying terminate()")
                                        process.terminate()
                                else:
                                    # On Linux/Mac, use terminate/kill
                                    process.terminate()
                                
                                # Wait a bit for graceful shutdown
                                try:
                                    process.wait(timeout=3)
                                    log.info(f"Process {process.pid} terminated gracefully")
                                    process_killed = True
                                except subprocess.TimeoutExpired:
                                    # Force kill if still running
                                    if platform.system() != "Windows":
                                        process.kill()
                                        process.wait(timeout=2)
                                    log.info(f"Process {process.pid} force killed")
                                    process_killed = True
                            except ProcessLookupError:
                                log.info(f"Process {process.pid} already terminated")
                                process_killed = True
                            except Exception as kill_error:
                                log.error(f"Error killing process {process.pid}: {kill_error}")
                    else:
                        log.info(f"Process {process.pid} already finished (returncode: {process.returncode})")
                        process_killed = True
                except Exception as e:
                    log.error(f"Error stopping process: {e}", exc_info=True)
            
            # Even if main process is killed, check for orphaned recon tool processes
            # Only kill them if we're sure the scan was stopped
            if process_killed or scan_info.get("status") == "stopping":
                log.info("Checking for orphaned recon tool processes...")
                # Wait a moment for processes to terminate naturally
                time.sleep(1)
                # Check if any recon tools are still running
                orphaned_killed = kill_recon_tool_processes()
                if orphaned_killed > 0:
                    log.info(f"Killed {orphaned_killed} orphaned recon tool process(es)")
            
            # Update status to stopped
            scan_info["status"] = "stopped"
            scan_info["stopped_at"] = datetime.now().isoformat()
            
            if process_killed or stop_flag_created:
                return jsonify({
                    "success": True, 
                    "message": "Scan stopped successfully",
                    "process_killed": process_killed,
                    "stop_flag_created": stop_flag_created
                })
            else:
                return jsonify({
                    "success": True,
                    "message": "Stop signal sent (process may have already finished)",
                    "process_killed": False,
                    "stop_flag_created": stop_flag_created
                })
    
    # Fallback to old method using target directory
    if target:
        # Normalize target path for comparison
        normalized_target = str(target).replace('\\', '/')
        
        stop_flag = Path(target) / ".stop_scan"
        try:
            stop_flag.parent.mkdir(parents=True, exist_ok=True)
            stop_flag.write_text("stop")
            log.info(f"Created stop flag file: {stop_flag}")
        except Exception as e:
            log.error(f"Error creating stop flag: {e}")
        
        # Try to find and kill process by target_dir (with path normalization)
        found_scan = False
        process_killed = False
        
        for sid, info in running_scans.items():
            # Normalize both paths for comparison
            info_target_dir = str(info.get("target_dir", "")).replace('\\', '/')
            if info_target_dir == normalized_target or info_target_dir.endswith(normalized_target) or normalized_target.endswith(info_target_dir):
                found_scan = True
                info["status"] = "stopping"
                
                if "process" in info:
                    process = info["process"]
                    try:
                        if process.poll() is None:  # Still running
                            log.info(f"Found scan {sid} by target directory, killing process {process.pid}")
                            # Kill child processes first
                            kill_child_processes(process.pid)
                            
                            if platform.system() == "Windows":
                                try:
                                    result = subprocess.run(
                                        ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        timeout=5
                                    )
                                    if result.returncode == 0:
                                        process_killed = True
                                except Exception:
                                    process.terminate()
                            else:
                                process.terminate()
                            try:
                                process.wait(timeout=3)
                                process_killed = True
                            except subprocess.TimeoutExpired:
                                if platform.system() != "Windows":
                                    process.kill()
                                process_killed = True
                            info["status"] = "stopped"
                            log.info(f"Stopped scan {sid} by target directory")
                    except Exception as e:
                        log.error(f"Error killing process: {e}")
                else:
                    # No process reference, but mark as stopped
                    info["status"] = "stopped"
        
        # Always try to kill orphaned recon tool processes when stopping by target
        # This handles cases where processes are orphaned or not in running_scans
        log.info("Killing any orphaned recon tool processes...")
        time.sleep(0.5)  # Brief wait for processes to terminate naturally
        orphaned_killed = kill_recon_tool_processes()
        
        if found_scan:
            if process_killed or orphaned_killed > 0:
                return jsonify({
                    "success": True, 
                    "message": f"Scan stopped successfully (killed {orphaned_killed} orphaned processes)" if orphaned_killed > 0 else "Scan stopped successfully"
                })
            else:
                return jsonify({"success": True, "message": "Stop signal sent"})
        else:
            # No scan found in running_scans, but we created stop flag and killed orphaned processes
            if orphaned_killed > 0:
                return jsonify({
                    "success": True, 
                    "message": f"Stop flag created and killed {orphaned_killed} orphaned recon tool process(es)"
                })
            else:
                return jsonify({"success": True, "message": "Stop flag created (no running process found in memory)"})
    
    # If no scan_id or target provided, try to stop all running scans
    if not scan_id and not target:
        log.warning("Stop scan called without scan_id or target, attempting to stop all running scans")
        stopped_count = 0
        for sid, info in list(running_scans.items()):
            if info.get("status") == "running" and "process" in info:
                try:
                    process = info["process"]
                    if process.poll() is None:
                        if platform.system() == "Windows":
                            try:
                                subprocess.run(
                                    ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    timeout=5
                                )
                            except Exception:
                                process.terminate()
                        else:
                            process.terminate()
                        info["status"] = "stopped"
                        stopped_count += 1
                except Exception as e:
                    log.error(f"Error stopping scan {sid}: {e}")
        
        if stopped_count > 0:
            return jsonify({"success": True, "message": f"Stopped {stopped_count} scan(s)"})
    
    return jsonify({"success": False, "error": "No running scan found with provided scan_id or target"}), 404


@app.route("/api/scan-logs", methods=["GET"])
@require_auth
def get_scan_logs_list():
    """Get list of all scan log files"""
    try:
        logs = []
        if not LOG_DIR.exists():
            log.warning(f"LOG_DIR does not exist: {LOG_DIR}")
            return jsonify({"logs": []})
        
        log_files = list(LOG_DIR.glob("*.log"))
        log.info(f"Found {len(log_files)} log files in {LOG_DIR}")
        
        for log_file in sorted(log_files, key=lambda x: x.stat().st_mtime, reverse=True):
            try:
                logs.append({
                    "name": log_file.name,
                    "path": str(log_file),
                    "size": log_file.stat().st_size,
                    "modified": datetime.fromtimestamp(log_file.stat().st_mtime).isoformat()
                })
            except Exception as e:
                log.warning(f"Error processing log file {log_file}: {e}")
                continue
        
        return jsonify({"logs": logs})
    except Exception as e:
        log.error(f"Error getting scan logs list: {e}", exc_info=True)
        return jsonify({"error": str(e), "logs": []}), 500


@app.route("/api/scan-logs/<path:log_name>", methods=["GET"])
@require_auth
def get_scan_log_content(log_name: str):
    """Get content of a scan log file"""
    try:
        # Decode URL-encoded log name
        log_name = unquote(log_name)
        # Ensure we only use the filename, not full path (security)
        log_name = Path(log_name).name
        log_file = LOG_DIR / log_name
        
        if not log_file.exists() or not log_file.is_file():
            return jsonify({"error": "Log file not found"}), 404
        
        content = log_file.read_text(encoding='utf-8', errors='ignore')
        size = log_file.stat().st_size
        
        return jsonify({
            "content": content,
            "size": size,
            "name": log_file.name,
            "path": str(log_file)
        })
    except Exception as e:
        log.error(f"Error reading log file: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/targets", methods=["GET"])
@require_auth
def get_targets():
    """Get all targets"""
    targets = load_targets()
    return jsonify({"targets": [asdict(t) for t in targets]})


@app.route("/api/targets/<path:target_path>/summary", methods=["GET"])
@require_auth
def get_target_summary(target_path: str):
    """Get target summary"""
    try:
        output_dir = resolve_target_path(target_path)
        
        if not output_dir.exists() or not output_dir.is_dir():
            log.warning(f"Target not found: {target_path} (resolved: {output_dir})")
            return jsonify({"error": "Target not found"}), 404
        
        summary = summarize_target(output_dir)
        return jsonify({"summary": summary})
    except Exception as e:
        log.error(f"Error getting target summary: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/targets/<path:target_path>/files", methods=["GET"])
@require_auth
def get_target_files(target_path: str):
    """Get list of files in target"""
    try:
        output_dir = resolve_target_path(target_path)
        
        if not output_dir.exists() or not output_dir.is_dir():
            log.warning(f"Target not found: {target_path} (resolved: {output_dir})")
            return jsonify({"error": "Target not found", "path": str(output_dir)}), 404
        
        files = []
        for path in sorted(output_dir.rglob("*")):
            if path.is_file():
                # Use forward slashes for relative paths (URL-friendly)
                rel_path = str(path.relative_to(output_dir)).replace('\\', '/')
                files.append({
                    "path": rel_path,
                    "size": path.stat().st_size,
                })
        
        return jsonify({"files": files})
    except Exception as e:
        log.error(f"Error getting target files: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/targets/<path:target_path>/files/<path:file_path>", methods=["GET"])
def get_file_content(target_path: str, file_path: str):
    """Get file content"""
    try:
        output_dir = resolve_target_path(target_path)
        file_path = unquote(file_path)
        
        # Path() handles both / and \ separators correctly
        file_full_path = output_dir / file_path
        
        if not file_full_path.exists() or not file_full_path.is_file():
            log.warning(f"File not found: {file_full_path}")
            return jsonify({"error": "File not found", "path": str(file_full_path)}), 404
        
        file_stat = file_full_path.stat()
        
        file_size = file_stat.st_size
        
        content = file_full_path.read_text(encoding="utf-8", errors="ignore")
        # Limit content size
        if len(content) > 8000:
            content = content[-8000:]
        
        return jsonify({
            "content": content,
            "size": file_size,
            "path": file_path,
        })
    except Exception as e:
        log.error(f"Error reading file: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/targets/<path:target_path>/files/<path:file_path>/download", methods=["GET"])
@require_auth
def download_file(target_path: str, file_path: str):
    """Download a file"""
    try:
        output_dir = resolve_target_path(target_path)
        file_path = unquote(file_path)
        
        file_full_path = output_dir / file_path
        
        if not file_full_path.exists() or not file_full_path.is_file():
            return jsonify({"error": "File not found"}), 404
    
        return send_file(
            file_full_path,
            as_attachment=True,
            download_name=file_full_path.name,
        )
    except Exception as e:
        log.error(f"Error downloading file: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/targets/<path:target_path>/download", methods=["GET"])
@require_auth
def download_target(target_path: str):
    """Download target as ZIP"""
    try:
        output_dir = resolve_target_path(target_path)
        
        if not output_dir.exists() or not output_dir.is_dir():
            return jsonify({"error": "Target not found"}), 404
        
        zip_path = output_dir.with_suffix(".zip")
        
        try:
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
                for file_path in output_dir.rglob("*"):
                    if file_path.is_file():
                        arcname = file_path.relative_to(output_dir)
                        zipf.write(file_path, arcname)
            
            return send_file(
                zip_path,
                as_attachment=True,
                download_name=zip_path.name,
            )
        finally:
            if zip_path.exists():
                zip_path.unlink()
    except Exception as e:
        log.error(f"Error downloading target: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/targets/<path:target_path>", methods=["DELETE"])
@require_auth
def delete_target(target_path: str):
    """Delete target"""
    try:
        output_dir = resolve_target_path(target_path)
        
        if not output_dir.exists() or not output_dir.is_dir():
            return jsonify({"error": "Target not found"}), 404
        
        shutil.rmtree(output_dir, ignore_errors=True)
        return jsonify({"success": True})
    except Exception as e:
        log.error(f"Error deleting target: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/")
def index():
    """Serve main dashboard"""
    return send_file(WEB_DIR / "index.html")

@app.route("/web")
def web_index():
    """Alternative route for web dashboard"""
    return send_file(WEB_DIR / "index.html")


@app.route("/api/config", methods=["GET"])
@require_auth
def get_config():
    """Get current settings.py file content"""
    try:
        log.info(f"Loading settings.py from: {SETTINGS_FILE}")
        log.info(f"File exists: {SETTINGS_FILE.exists()}")
        log.info(f"File absolute path: {SETTINGS_FILE.resolve()}")
        
        if not SETTINGS_FILE.exists():
            error_msg = f"settings.py not found at: {SETTINGS_FILE.resolve()}"
            log.error(error_msg)
            return jsonify({"success": False, "error": error_msg}), 404
        
        try:
            content = SETTINGS_FILE.read_text(encoding='utf-8')
            log.info(f"Successfully read settings.py ({len(content)} characters)")
            return jsonify({"success": True, "content": content})
        except UnicodeDecodeError as e:
            log.error(f"Encoding error reading settings.py: {e}")
            # Try with different encoding
            try:
                content = SETTINGS_FILE.read_text(encoding='latin-1')
                return jsonify({"success": True, "content": content})
            except Exception as e2:
                log.error(f"Failed to read with latin-1 encoding: {e2}")
                return jsonify({"success": False, "error": f"Encoding error: {str(e)}"}), 500
    except Exception as e:
        log.error(f"Error reading settings.py: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/config", methods=["POST"])
@require_auth
def update_config():
    """Update settings.py file"""
    try:
        data = request.get_json()
        if not data or "content" not in data:
            return jsonify({"success": False, "error": "Content required"}), 400
        
        content = data["content"]
        
        # Validate Python syntax
        try:
            compile(content, SETTINGS_FILE.name, 'exec')
        except SyntaxError as e:
            return jsonify({
                "success": False, 
                "error": f"Python syntax error: {e.msg} at line {e.lineno}",
                "line": e.lineno,
                "offset": e.offset
            }), 400
        
        # Create backup
        backup_file = SETTINGS_FILE.with_suffix('.py.backup')
        if SETTINGS_FILE.exists():
            backup_file.write_text(SETTINGS_FILE.read_text(encoding='utf-8'), encoding='utf-8')
            log.info(f"Created backup: {backup_file}")
        
        # Save new content
        SETTINGS_FILE.write_text(content, encoding='utf-8')
        log.info(f"Settings.py updated successfully")
        
        return jsonify({
            "success": True, 
            "message": "settings.py updated successfully",
            "backup": str(backup_file)
        })
    except Exception as e:
        log.error(f"Error updating settings.py: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/config/backup", methods=["GET"])
@require_auth
def get_backup():
    """Get backup file if exists"""
    try:
        backup_file = SETTINGS_FILE.with_suffix('.py.backup')
        if backup_file.exists():
            content = backup_file.read_text(encoding='utf-8')
            return jsonify({"success": True, "content": content, "exists": True})
        else:
            return jsonify({"success": True, "exists": False})
    except Exception as e:
        log.error(f"Error reading backup: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("=" * 70)
    print("Recon Tool API Server")
    print("=" * 70)
    print(f"Starting server on http://localhost:5000")
    print(f"Open http://localhost:5000 in your browser")
    print("=" * 70)
    app.run(host="0.0.0.0", port=5000, debug=True)


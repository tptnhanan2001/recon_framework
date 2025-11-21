"""
Recon Tool Visual Dashboard
---------------------------

Streamlit UI that wraps `recon_tool.py`:
- Launch new scans for domains or uploaded lists
- Visualize recon output (subdomains, alive hosts, nuclei findings, files)
- Manage existing targets (download/delete)
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd
import streamlit as st

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_ROOT = BASE_DIR / "recon_output"
UPLOAD_DIR = BASE_DIR / "uploads"
AUTH_FILE = BASE_DIR / ".auth_session.json"
DEFAULT_PASSWORD = os.getenv("RECON_UI_PASSWORD", "recontool@")

OUTPUT_ROOT.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(BASE_DIR / "auth.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("recon_ui")


@dataclass
class TargetInfo:
    label: str
    output_dir: Path


def load_targets() -> List[TargetInfo]:
    targets: List[TargetInfo] = []
    for path in sorted(OUTPUT_ROOT.glob("recon_*")):
        if path.is_dir():
            label = path.name.replace("recon_", "")
            targets.append(TargetInfo(label=label, output_dir=path))
    return targets


def ensure_state() -> None:
    defaults = {
        "authenticated": False,
        "tools_enabled": None,
        "last_run": None,
        "active_target": None,
    }
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)


def persist_session() -> None:
    AUTH_FILE.write_text(
        json.dumps(
            {
                "authenticated": True,
                "timestamp": datetime.utcnow().timestamp(),
            }
        )
    )


def load_session() -> bool:
    if not AUTH_FILE.exists():
        return False
    try:
        data = json.loads(AUTH_FILE.read_text())
        if not data.get("authenticated"):
            return False
        age = datetime.utcnow().timestamp() - data.get("timestamp", 0)
        return age < 7 * 24 * 3600
    except Exception:
        return False


def login_view() -> None:
    st.title("🔐 Recon Tool Dashboard")
    st.subheader("Authentication required")
    with st.form("login_form"):
        pwd = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login", use_container_width=True)
        if submit:
            if pwd == DEFAULT_PASSWORD:
                st.session_state.authenticated = True
                persist_session()
                st.success("Authenticated")
                st.experimental_rerun()
            else:
                st.error("Incorrect password")


def safe_filename(name: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {".", "-", "_"} else "_" for ch in name)


def save_upload(upload) -> Optional[Path]:
    if not upload:
        return None
    dest = UPLOAD_DIR / f"{datetime.utcnow():%Y%m%d_%H%M%S}_{safe_filename(upload.name)}"
    dest.write_bytes(upload.getbuffer())
    return dest


def default_tools(existing: Optional[Dict[str, bool]]) -> Dict[str, bool]:
    defaults = {
        "subfinder": True,
        "amass": True,
        "sublist3r": True,
        "httpx": True,
        "dirsearch": True,
        "katana": True,
        "urlfinder": True,
        "waybackurls": True,
        "waymore": True,
        "cloudenum": True,
        "nuclei": True,
    }
    if not existing:
        return defaults
    merged = defaults.copy()
    merged.update(existing)
    return merged


def run_orchestrator(args: List[str], tools_enabled: Dict[str, bool]) -> subprocess.CompletedProcess[str]:
    command = ["python3", str(BASE_DIR / "recon_tool.py")] + args
    config_path = BASE_DIR / ".recon_ui_tmp.json"
    config_path.write_text(json.dumps({"tools_enabled": tools_enabled}))
    env = os.environ.copy()
    env["RECON_TOOL_CONFIG"] = str(config_path)
    try:
        result = subprocess.run(
            command,
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
    finally:
        config_path.unlink(missing_ok=True)
    return result


def read_lines(path: Path, limit: Optional[int] = None) -> List[str]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        lines = handle.readlines()
    return lines if limit is None else lines[:limit]


def count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        return sum(1 for _ in handle)


def summarize_target(output_dir: Path) -> Dict[str, int]:
    summary = {"subdomains": 0, "alive": 0, "urls": 0, "nuclei_findings": 0}
    summary["subdomains"] = count_lines(next(output_dir.glob("subfinder_*.txt"), Path()))
    summary["alive"] = count_lines(next(output_dir.glob("httpx_alive_*.txt"), Path()))
    summary["urls"] = count_lines(next(output_dir.glob("urls_*.txt"), Path()))
    nuclei_files = list((output_dir / "nuclei").glob("*.txt"))
    summary["nuclei_findings"] = sum(count_lines(f) for f in nuclei_files)
    return summary


def files_dataframe(output_dir: Path, limit: int = 200) -> pd.DataFrame:
    rows = []
    for path in sorted(output_dir.rglob("*")):
        if path.is_file():
            rows.append(
                {
                    "path": str(path.relative_to(output_dir)),
                    "size_kb": round(path.stat().st_size / 1024, 2),
                    "modified": datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                }
            )
        if len(rows) >= limit:
            break
    return pd.DataFrame(rows)


def parse_nuclei_table(output_dir: Path, limit: int = 200) -> pd.DataFrame:
    nuclei_dir = output_dir / "nuclei"
    rows: List[Tuple[str, str]] = []
    for file in sorted(nuclei_dir.glob("*.txt")):
        for line in read_lines(file):
            line = line.strip()
            if line:
                rows.append((file.name, line))
                if len(rows) >= limit:
                    break
        if len(rows) >= limit:
            break
    if not rows:
        return pd.DataFrame(columns=["file", "finding"])
    return pd.DataFrame(rows, columns=["file", "finding"])


def render_run_panel():
    st.subheader("🚀 Start new scan")
    tools_enabled = default_tools(st.session_state.tools_enabled)

    mode = st.radio("Target type", ["Domain", "Domain list"], horizontal=True, key="target_mode")
    
    with st.form("run_form"):
        domain_value = None
        list_file = None

        if mode == "Domain":
            domain_value = st.text_input("Domain (example.com)", placeholder="example.com", key="domain_input")
        else:
            st.markdown("---")
            st.markdown("### 📤 Upload Domain List")
            st.info("📝 Upload a text file (.txt or .lst) containing one domain per line")
            uploaded = st.file_uploader(
                "Choose file to upload",
                type=["txt", "lst"],
                help="File format: one domain per line\nExample:\nexample.com\ntest.com\nsubdomain.example.com",
                key="domain_list_upload"
            )
            if uploaded:
                list_file = save_upload(uploaded)
                if list_file:
                    st.success(f"✅ **File uploaded successfully!**\n- Filename: `{uploaded.name}`\n- Saved to: `{list_file}`")
                    # Preview first few lines
                    try:
                        preview_lines = uploaded.getvalue().decode('utf-8', errors='ignore').splitlines()[:5]
                        if preview_lines:
                            with st.expander("📋 Preview (first 5 lines)", expanded=False):
                                st.code("\n".join(preview_lines), language="text")
                                st.caption(f"Total file size: {uploaded.size:,} bytes")
                    except Exception as e:
                        st.warning(f"Could not preview file: {e}")
            else:
                st.warning("⚠️ Please upload a domain list file (.txt or .lst)")
            st.markdown("---")

        output_name = st.text_input(
            "Output folder name",
            value=(domain_value or "example_com"),
            help="Will be saved under recon_<name>",
        )

        st.caption("Tool toggles")
        cols = st.columns(2)
        updated = {}
        for idx, tool in enumerate(tools_enabled.keys()):
            with cols[idx % 2]:
                updated[tool] = st.checkbox(
                    tool.capitalize(),
                    value=tools_enabled[tool],
                    key=f"tool_{tool}",
                )

        col_run, col_stop = st.columns([1, 1])
        submit = col_run.form_submit_button("Run recon", use_container_width=True)
        requested_stop = col_stop.form_submit_button("Stop running scan", use_container_width=True)

    if requested_stop:
        selected_target = st.session_state.get("active_target")
        if not selected_target:
            st.warning("Select a target in the dashboard to stop its scan.")
        else:
            stop_flag = Path(selected_target) / ".stop_scan"
            stop_flag.parent.mkdir(parents=True, exist_ok=True)
            stop_flag.write_text("stop")
            st.success("Stop signal sent. Scan will stop shortly.")

    if submit:
        if mode == "Domain" and not domain_value:
            st.error("Please enter a domain")
            return
        if mode == "Domain list" and not list_file:
            st.error("Please upload a domain list")
            return

        sanitized = safe_filename(output_name.strip() or (domain_value or list_file.stem))
        target_dir = OUTPUT_ROOT / f"recon_{sanitized}"
        target_dir.mkdir(parents=True, exist_ok=True)

        args = ["-o", str(target_dir)]
        if mode == "Domain":
            args.extend(["-d", domain_value])
        else:
            args.extend(["-dL", str(list_file)])

        with st.spinner("Running recon_tool.py..."):
            result = run_orchestrator(args, updated)

        st.session_state.tools_enabled = updated
        st.session_state.last_run = {
            "returncode": result.returncode,
            "stdout": result.stdout[-4000:] if result.stdout else "",
            "stderr": result.stderr[-4000:] if result.stderr else "",
            "target": str(target_dir),
        }

        if result.returncode == 0:
            st.success("Recon completed successfully.")
        else:
            st.error("Recon finished with errors.")

        if result.stdout:
            st.code(result.stdout[-2000:], language="bash")
        if result.stderr:
            st.code(result.stderr[-2000:], language="bash")


def get_latest_log(output_dir: Path) -> Optional[Path]:
    logs = sorted(output_dir.glob("recon_*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
    return logs[0] if logs else None


def tail_file(path: Path, max_lines: int = 300) -> None:
    try:
        lines = read_lines(path)
        st.code("".join(lines[-max_lines:]), language="bash")
    except Exception as exc:
        st.warning(f"Unable to read log: {exc}")


def list_output_files(root: Path, limit: int = 60) -> None:
    df = files_dataframe(root, limit)
    if df.empty:
        st.info("No files yet.")
    else:
        st.dataframe(df, use_container_width=True, height=260)


def render_targets_panel():
    st.subheader("📁 Existing scans")
    targets = load_targets()
    if not targets:
        st.info("No recon results yet.")
        return

    labels = [f"{t.label} ({t.output_dir.name})" for t in targets]
    idx = st.selectbox("Choose target", range(len(labels)), format_func=lambda i: labels[i])
    target = targets[idx]
    st.session_state.active_target = target.output_dir
    st.write(f"Output directory: `{target.output_dir}`")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Download ZIP", use_container_width=True):
            archive_path = shutil.make_archive(str(target.output_dir), "zip", root_dir=target.output_dir)
            with open(archive_path, "rb") as data:
                st.download_button(
                    "Click to download",
                    data,
                    file_name=Path(archive_path).name,
                    mime="application/zip",
                    use_container_width=True,
                )
            os.remove(archive_path)
    with col2:
        if st.button("Delete output", use_container_width=True):
            shutil.rmtree(target.output_dir, ignore_errors=True)
            st.success("Output deleted")
            st.experimental_rerun()

    st.markdown("### Latest log")
    latest_log = get_latest_log(target.output_dir)
    if latest_log:
        st.caption(latest_log.name)
        with st.expander("View log", expanded=True):
            tail_file(latest_log)
    else:
        st.info("No logs yet.")

    st.markdown("### File preview")
    list_output_files(target.output_dir)


def render_visuals():
    output_dir = st.session_state.get("active_target")
    if not output_dir or not Path(output_dir).exists():
        st.info("Select a target to visualize results.")
        return

    output_dir = Path(output_dir)
    st.subheader(f"📊 Visualization — {output_dir.name}")
    tab_metrics, tab_files, tab_results = st.tabs(["📈 Metrics", "🗂 Completed files", "📄 Recon results"])

    with tab_metrics:
        summary = summarize_target(output_dir)
        cols = st.columns(4)
        cols[0].metric("Subdomains", summary["subdomains"])
        cols[1].metric("Alive hosts", summary["alive"])
        cols[2].metric("URLs extracted", summary["urls"])
        cols[3].metric("Nuclei findings", summary["nuclei_findings"])

        chart_df = pd.DataFrame(
            {
                "category": ["Subdomains", "Alive"],
                "count": [summary["subdomains"], summary["alive"]],
            }
        ).set_index("category")
        st.bar_chart(chart_df)

        st.markdown("#### Nuclei findings (preview)")
        nuclei_df = parse_nuclei_table(output_dir)
        if nuclei_df.empty:
            st.info("No nuclei findings yet.")
        else:
            st.dataframe(nuclei_df, use_container_width=True, height=250)

    with tab_files:
        df_files = files_dataframe(output_dir)
        if df_files.empty:
            st.info("No files yet.")
        else:
            st.dataframe(df_files, use_container_width=True, height=300)
            if len(df_files) >= 200:
                st.caption("Showing first 200 entries.")

    with tab_results:
        st.markdown("#### Key recon outputs")
        previews = [
            ("Subfinder results", next(output_dir.glob("subfinder_*.txt"), None)),
            ("Alive hosts (httpx)", next(output_dir.glob("httpx_alive_*.txt"), None)),
            ("Alive subdomains", next(output_dir.glob("subdomain_alive_*.txt"), None)),
            ("Extracted URLs", next(output_dir.glob("urls_*.txt"), None)),
        ]

        nuclei_files = sorted((output_dir / "nuclei").glob("*.txt"))
        if nuclei_files:
            previews.append(("Nuclei findings", nuclei_files[0]))

        for title, path in previews:
            st.markdown(f"**{title}**")
            if path and path.exists():
                lines = read_lines(path, limit=50)
                if lines:
                    st.code("".join(lines), language="text")
                    total = count_lines(path)
                    if total > 50:
                        st.caption(f"Showing first 50 lines out of {total:,}")
                else:
                    st.info("File exists but is empty.")
            else:
                st.info("No data yet.")


def render_output_viewer():
    st.subheader("📄 Output Viewer")
    targets = load_targets()
    if not targets:
        st.info("No recon results yet.")
        return

    labels = [f"{t.label} ({t.output_dir.name})" for t in targets]
    idx = st.selectbox("Choose target", range(len(labels)), format_func=lambda i: labels[i], key="output_view_target")
    target = targets[idx]

    files = [p for p in target.output_dir.rglob("*") if p.is_file()]
    if not files:
        st.info("Target has no output files yet.")
        return

    rel_paths = [str(p.relative_to(target.output_dir)) for p in files]
    file_idx = st.selectbox("Select file to view", range(len(rel_paths)), format_func=lambda i: rel_paths[i], key="output_view_file")
    selected_path = files[file_idx]

    st.caption(f"File: `{selected_path}` ({selected_path.stat().st_size:,} bytes)")
    content = selected_path.read_text(errors="ignore")
    st.code(content[-8000:] if len(content) > 8000 else content, language="text")

    if st.button("Download this file", use_container_width=True, key="download_selected_output"):
        with open(selected_path, "rb") as data:
            st.download_button(
                "Click to download",
                data,
                file_name=selected_path.name,
                mime="text/plain",
                use_container_width=True,
            )


def render_last_run():
    st.subheader("Last run summary")
    last = st.session_state.get("last_run")
    if not last:
        st.info("No runs yet.")
        return
    st.write(f"Return code: {last['returncode']}")
    st.write(f"Output directory: `{last['target']}`")
    if last["stdout"]:
        st.code(last["stdout"], language="bash")
    if last["stderr"]:
        st.code(last["stderr"], language="bash")


def dashboard():
    st.set_page_config(page_title="Recon Tool Dashboard", layout="wide")
    ensure_state()

    if not st.session_state.authenticated:
        if load_session():
            st.session_state.authenticated = True
        else:
            login_view()
            return

    st.title("Recon Tool Dashboard")
    st.caption("Visualize and orchestrate recon runs backed by recon_tool.py.")

    tab_dashboard, tab_output = st.tabs(["Dashboard", "📄 Output Viewer"])

    with tab_dashboard:
        left, right = st.columns([1.3, 1])
        with left:
            render_run_panel()
            st.markdown("---")
            render_visuals()
        with right:
            render_targets_panel()
            st.markdown("---")
            render_last_run()

    with tab_output:
        render_output_viewer()


if __name__ == "__main__":
    dashboard()

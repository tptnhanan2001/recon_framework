#!/usr/bin/env python3
"""
Report Generator - CSV Report for Bug Bounty / Red Team
Aggregates all recon data into a comprehensive CSV report
"""

import csv
import os
import re
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import logging


class ReportGenerator:
    """Generate comprehensive CSV reports from recon data"""
    
    def __init__(self, output_dir, base_name, logger=None):
        self.output_dir = Path(output_dir)
        self.base_name = base_name
        self.logger = logger or logging.getLogger(__name__)
        self.report_data = []
    
    def _read_file_lines(self, file_path):
        """Read lines from a file, return empty list if file doesn't exist"""
        if not file_path or not os.path.exists(file_path):
            return []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.logger.warning(f"Error reading {file_path}: {e}")
            return []
    
    def _extract_domain_from_url(self, url):
        """Extract domain from URL"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            parsed = urlparse(url)
            return parsed.netloc or parsed.path.split('/')[0]
        except Exception:
            return url.split('/')[0] if '/' in url else url
    
    def _extract_status_code(self, line):
        """Extract HTTP status code from line (for httpx, dirsearch output)"""
        # Try to find status code patterns like "200", "[200]", "Status: 200"
        patterns = [
            r'\b(\d{3})\b',  # Any 3-digit number
            r'\[(\d{3})\]',  # [200]
            r'Status[:\s]+(\d{3})',  # Status: 200
        ]
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                code = match.group(1)
                if code.startswith(('2', '3', '4', '5')):
                    return code
        return None
    
    def _parse_httpx_output(self, file_path):
        """Parse httpx alive output"""
        lines = self._read_file_lines(file_path)
        results = []
        
        for line in lines:
            parts = line.split()
            if not parts:
                continue
            
            url = parts[0]
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            domain = self._extract_domain_from_url(url)
            status_code = self._extract_status_code(line) or "N/A"
            
            # Try to extract additional info (title, size, etc.)
            title = None
            size = None
            for part in parts[1:]:
                if 'title:' in part.lower():
                    title = part.split(':', 1)[-1] if ':' in part else None
                elif '[' in part and ']' in part:
                    size_match = re.search(r'\[(\d+)\]', part)
                    if size_match:
                        size = size_match.group(1)
            
            results.append({
                'type': 'Alive URL',
                'domain': domain,
                'url': url,
                'status_code': status_code,
                'tool': 'httpx',
                'finding': f'Alive endpoint (Status: {status_code})',
                'severity': 'Info',
                'notes': f"Title: {title}" if title else f"Size: {size}" if size else ""
            })
        
        return results
    
    def _parse_nuclei_output(self, file_path):
        """Parse Nuclei output (JSON lines format)"""
        lines = self._read_file_lines(file_path)
        results = []
        
        import json
        for line in lines:
            try:
                data = json.loads(line)
                url = data.get('matched-at', data.get('url', ''))
                template_id = data.get('template-id', 'Unknown')
                info = data.get('info', {})
                name = info.get('name', template_id)
                severity = info.get('severity', 'unknown').capitalize()
                description = info.get('description', '')
                
                domain = self._extract_domain_from_url(url)
                
                results.append({
                    'type': 'Vulnerability',
                    'domain': domain,
                    'url': url,
                    'status_code': 'N/A',
                    'tool': 'nuclei',
                    'finding': name,
                    'severity': severity,
                    'notes': description[:200] if description else template_id
                })
            except (json.JSONDecodeError, Exception) as e:
                # Fallback: try to parse as plain text
                if 'http' in line.lower():
                    url_match = re.search(r'https?://[^\s]+', line)
                    if url_match:
                        url = url_match.group(0)
                        domain = self._extract_domain_from_url(url)
                        results.append({
                            'type': 'Vulnerability',
                            'domain': domain,
                            'url': url,
                            'status_code': 'N/A',
                            'tool': 'nuclei',
                            'finding': 'Potential vulnerability detected',
                            'severity': 'Medium',
                            'notes': line[:200]
                        })
        
        return results
    
    def _parse_dirsearch_output(self, file_path):
        """Parse Dirsearch output"""
        lines = self._read_file_lines(file_path)
        results = []
        
        for line in lines:
            # Dirsearch format: URL [STATUS] [SIZE]
            url_match = re.search(r'(https?://[^\s]+)', line)
            if url_match:
                url = url_match.group(1)
                domain = self._extract_domain_from_url(url)
                status_code = self._extract_status_code(line) or "N/A"
                
                results.append({
                    'type': 'Directory/File',
                    'domain': domain,
                    'url': url,
                    'status_code': status_code,
                    'tool': 'dirsearch',
                    'finding': f'Discovered path (Status: {status_code})',
                    'severity': 'Info',
                    'notes': ''
                })
        
        return results
    
    def _parse_katana_output(self, file_path):
        """Parse Katana output (URLs)"""
        lines = self._read_file_lines(file_path)
        results = []
        
        for line in lines:
            url = line.strip()
            if url.startswith(('http://', 'https://')):
                domain = self._extract_domain_from_url(url)
                results.append({
                    'type': 'Crawled URL',
                    'domain': domain,
                    'url': url,
                    'status_code': 'N/A',
                    'tool': 'katana',
                    'finding': 'URL discovered via crawling',
                    'severity': 'Info',
                    'notes': ''
                })
        
        return results
    
    def _parse_urlfinder_output(self, file_path):
        """Parse URLFinder output"""
        lines = self._read_file_lines(file_path)
        results = []
        
        for line in lines:
            url = line.strip()
            if url.startswith(('http://', 'https://')):
                domain = self._extract_domain_from_url(url)
                results.append({
                    'type': 'Discovered URL',
                    'domain': domain,
                    'url': url,
                    'status_code': 'N/A',
                    'tool': 'urlfinder',
                    'finding': 'URL discovered via URLFinder',
                    'severity': 'Info',
                    'notes': ''
                })
        
        return results
    
    def _parse_wayback_output(self, file_path):
        """Parse Wayback URLs output"""
        lines = self._read_file_lines(file_path)
        results = []
        
        for line in lines:
            url = line.strip()
            if url.startswith(('http://', 'https://')):
                domain = self._extract_domain_from_url(url)
                results.append({
                    'type': 'Wayback URL',
                    'domain': domain,
                    'url': url,
                    'status_code': 'N/A',
                    'tool': 'wayback',
                    'finding': 'Historical URL from Wayback Machine',
                    'severity': 'Info',
                    'notes': ''
                })
        
        return results
    
    def _parse_cloudenum_output(self, file_path):
        """Parse CloudEnum output"""
        lines = self._read_file_lines(file_path)
        results = []
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # CloudEnum format varies, try to extract URLs or cloud resources
            if 'http' in line.lower() or '.' in line:
                domain = line.split()[0] if ' ' in line else line
                results.append({
                    'type': 'Cloud Resource',
                    'domain': domain,
                    'url': domain if not domain.startswith(('http://', 'https://')) else domain,
                    'status_code': 'N/A',
                    'tool': 'cloudenum',
                    'finding': 'Cloud resource discovered',
                    'severity': 'Medium',
                    'notes': line
                })
        
        return results
    
    def _collect_subdomains(self):
        """Collect all discovered subdomains"""
        subdomain_files = [
            f"subfinder_{self.base_name}.txt",
            f"amass_{self.base_name}.txt",
            f"sublist3r_{self.base_name}.txt",
            f"subdomains_merged_{self.base_name}.txt",
            f"subdomain_alive_{self.base_name}.txt",
        ]
        
        subdomains = set()
        for filename in subdomain_files:
            file_path = self.output_dir / filename
            lines = self._read_file_lines(file_path)
            for line in lines:
                subdomain = line.strip().lower()
                if subdomain and '.' in subdomain:
                    # Clean up subdomain
                    subdomain = subdomain.replace('http://', '').replace('https://', '')
                    subdomain = subdomain.split('/')[0].split('?')[0]
                    if subdomain:
                        subdomains.add(subdomain)
        
        results = []
        for subdomain in sorted(subdomains):
            results.append({
                'type': 'Subdomain',
                'domain': subdomain,
                'url': f'https://{subdomain}',
                'status_code': 'N/A',
                'tool': 'subdomain_discovery',
                'finding': 'Discovered subdomain',
                'severity': 'Info',
                'notes': ''
            })
        
        return results
    
    def collect_data(self):
        """Collect all recon data from output directory"""
        self.logger.info("[Report] Collecting recon data...")
        
        # Collect subdomains
        self.report_data.extend(self._collect_subdomains())
        
        # Parse httpx output
        httpx_file = self.output_dir / f"httpx_alive_{self.base_name}.txt"
        if httpx_file.exists():
            self.report_data.extend(self._parse_httpx_output(httpx_file))
        
        # Parse Nuclei outputs
        nuclei_dir = self.output_dir / "nuclei"
        if nuclei_dir.exists():
            for nuclei_file in nuclei_dir.glob(f"nuclei_*_{self.base_name}.txt"):
                self.report_data.extend(self._parse_nuclei_output(nuclei_file))
        
        # Parse Dirsearch output
        dirsearch_file = self.output_dir / f"dirsearch_{self.base_name}.txt"
        if dirsearch_file.exists():
            self.report_data.extend(self._parse_dirsearch_output(dirsearch_file))
        
        # Parse Katana output
        katana_file = self.output_dir / f"katana_{self.base_name}.txt"
        if katana_file.exists():
            self.report_data.extend(self._parse_katana_output(katana_file))
        
        # Parse URLFinder output
        urlfinder_file = self.output_dir / f"urlfinder_{self.base_name}.txt"
        if urlfinder_file.exists():
            self.report_data.extend(self._parse_urlfinder_output(urlfinder_file))
        
        # Parse Wayback URLs
        wayback_file = self.output_dir / f"waybackurls_{self.base_name}.txt"
        if wayback_file.exists():
            self.report_data.extend(self._parse_wayback_output(wayback_file))
        
        # Parse Waymore output
        waymore_dir = self.output_dir / "waymore"
        if waymore_dir.exists():
            for waymore_file in waymore_dir.glob(f"waymore_*.txt"):
                self.report_data.extend(self._parse_wayback_output(waymore_file))
        
        # Parse CloudEnum output
        cloudenum_file = self.output_dir / f"cloudenum_{self.base_name}.txt"
        if cloudenum_file.exists():
            self.report_data.extend(self._parse_cloudenum_output(cloudenum_file))
        
        self.logger.info(f"[Report] Collected {len(self.report_data)} findings")
    
    def generate_csv(self):
        """Generate CSV report"""
        if not self.report_data:
            self.logger.warning("[Report] No data to generate report")
            return None
        
        csv_file = self.output_dir / f"recon_report_{self.base_name}.csv"
        
        # Define CSV columns
        fieldnames = [
            'Type',
            'Domain',
            'URL',
            'Status Code',
            'Tool',
            'Finding',
            'Severity',
            'Notes',
            'Timestamp'
        ]
        
        try:
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                for item in self.report_data:
                    writer.writerow({
                        'Type': item.get('type', ''),
                        'Domain': item.get('domain', ''),
                        'URL': item.get('url', ''),
                        'Status Code': item.get('status_code', ''),
                        'Tool': item.get('tool', ''),
                        'Finding': item.get('finding', ''),
                        'Severity': item.get('severity', ''),
                        'Notes': item.get('notes', ''),
                        'Timestamp': timestamp
                    })
            
            self.logger.info(f"[Report] ✓ CSV report generated: {csv_file}")
            self.logger.info(f"[Report]   Total findings: {len(self.report_data)}")
            
            # Print summary by type
            type_counts = {}
            severity_counts = {}
            for item in self.report_data:
                item_type = item.get('type', 'Unknown')
                severity = item.get('severity', 'Unknown')
                type_counts[item_type] = type_counts.get(item_type, 0) + 1
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            self.logger.info("[Report] Summary by type:")
            for item_type, count in sorted(type_counts.items()):
                self.logger.info(f"[Report]   - {item_type}: {count}")
            
            self.logger.info("[Report] Summary by severity:")
            for severity, count in sorted(severity_counts.items()):
                self.logger.info(f"[Report]   - {severity}: {count}")
            
            return str(csv_file)
        
        except Exception as e:
            self.logger.error(f"[Report] Error generating CSV: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            return None
    
    def run(self):
        """Run report generation"""
        self.collect_data()
        return self.generate_csv()


#!/usr/bin/env python3
"""
PHPMyAdmin Advanced Security Assessment Framework v2.0
Enterprise-Grade Security Testing Platform
Author: Sudeepa Wanigarathna
License: For Authorized Testing Only
"""

import asyncio
import aiohttp
import json
import yaml
import logging
import hashlib
import ssl
import csv
import re
import sys
import os
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
import xml.etree.ElementTree as ET
from pathlib import Path

# Third-party imports (install with: pip install aiohttp pyyaml colorama tqdm markdown)
try:
    from colorama import init, Fore, Back, Style
    from tqdm import tqdm
    import markdown
    init(autoreset=True)
except ImportError:
    # Fallback for missing dependencies
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Style:
        BRIGHT = DIM = NORMAL = ''
    class tqdm:
        def __init__(self, *args, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def update(self, *args): pass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pma_audit.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('PMA-Audit')

# ==================== Data Models ====================

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class Finding:
    """Security finding data structure"""
    id: str
    title: str
    description: str
    severity: Severity
    cvss_score: float = 0.0
    mitre_attack: List[str] = field(default_factory=list)
    remediation: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    cve: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

@dataclass
class ScanResult:
    """Complete scan result"""
    target: str
    timestamp: str
    duration: float
    version: str
    findings: List[Finding] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

# ==================== Plugin System ====================

class Plugin:
    """Base plugin class"""
    name: str = "base"
    description: str = "Base plugin"
    
    async def run(self, session: aiohttp.ClientSession, target: str, config: Dict) -> List[Finding]:
        raise NotImplementedError

class VersionDetectionPlugin(Plugin):
    name = "version_detection"
    description = "Detect PHPMyAdmin version and patch level"
    
    async def run(self, session: aiohttp.ClientSession, target: str, config: Dict) -> List[Finding]:
        findings = []
        
        # Version detection patterns
        patterns = {
            '4.8.0': r'phpMyAdmin v?4\.8\.0',
            '4.8.1': r'phpMyAdmin v?4\.8\.1',
            '4.8.2': r'phpMyAdmin v?4\.8\.2',
            '4.8.3': r'phpMyAdmin v?4\.8\.3',
            '4.8.4': r'phpMyAdmin v?4\.8\.4',
            '4.8.5': r'phpMyAdmin v?4\.8\.5',
            '4.9.0': r'phpMyAdmin v?4\.9\.0',
            '4.9.1': r'phpMyAdmin v?4\.9\.1',
            '4.9.2': r'phpMyAdmin v?4\.9\.2',
            '4.9.3': r'phpMyAdmin v?4\.9\.3',
            '4.9.4': r'phpMyAdmin v?4\.9\.4',
            '4.9.5': r'phpMyAdmin v?4\.9\.5',
            '5.0.0': r'phpMyAdmin v?5\.0\.0',
            '5.0.1': r'phpMyAdmin v?5\.0\.1',
            '5.0.2': r'phpMyAdmin v?5\.0\.2',
            '5.1.0': r'phpMyAdmin v?5\.1\.0',
            '5.1.1': r'phpMyAdmin v?5\.1\.1',
            '5.1.2': r'phpMyAdmin v?5\.1\.2',
            '5.1.3': r'phpMyAdmin v?5\.1\.3',
            '5.2.0': r'phpMyAdmin v?5\.2\.0',
            '5.2.1': r'phpMyAdmin v?5\.2\.1'
        }
        
        vulnerable_versions = {
            '4.8.0': 'CVE-2018-19968, CVE-2018-19969',
            '4.8.1': 'CVE-2018-19968, CVE-2018-19969',
            '4.8.2': 'CVE-2018-19968, CVE-2018-19969',
            '4.8.3': 'CVE-2018-19968, CVE-2018-19969',
            '4.8.4': 'CVE-2018-19968, CVE-2018-19969',
            '4.9.0': 'CVE-2019-11768',
            '4.9.1': 'CVE-2019-11768',
            '4.9.2': 'CVE-2019-11768',
            '5.0.0': 'CVE-2019-18622',
            '5.0.1': 'CVE-2019-18622'
        }
        
        try:
            async with session.get(target) as response:
                html = await response.text()
                
                # Check for version in page
                version_found = None
                for version, pattern in patterns.items():
                    if re.search(pattern, html):
                        version_found = version
                        break
                
                if version_found:
                    findings.append(Finding(
                        id="PMA-VER-001",
                        title="PHPMyAdmin Version Detected",
                        description=f"Detected version: {version_found}",
                        severity=Severity.INFO,
                        evidence={"version": version_found}
                    ))
                    
                    if version_found in vulnerable_versions:
                        findings.append(Finding(
                            id="PMA-VULN-001",
                            title="Vulnerable PHPMyAdmin Version Detected",
                            description=f"Version {version_found} has known vulnerabilities",
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            cve=vulnerable_versions[version_found].split(', '),
                            mitre_attack=["T1190", "T1068"],
                            remediation="Upgrade to the latest stable version",
                            evidence={"version": version_found}
                        ))
        except Exception as e:
            logger.error(f"Version detection failed: {e}")
        
        return findings

class SecurityHeadersPlugin(Plugin):
    name = "security_headers"
    description = "Check security headers configuration"
    
    async def run(self, session: aiohttp.ClientSession, target: str, config: Dict) -> List[Finding]:
        findings = []
        
        security_headers = {
            'Content-Security-Policy': {
                'critical': True,
                'description': 'Missing CSP header allows XSS attacks',
                'mitre': ['T1189'],
                'severity': Severity.HIGH
            },
            'Strict-Transport-Security': {
                'critical': True,
                'description': 'Missing HSTS header enables SSL stripping',
                'mitre': ['T1573'],
                'severity': Severity.MEDIUM
            },
            'X-Frame-Options': {
                'critical': True,
                'description': 'Missing X-Frame-Options allows clickjacking',
                'mitre': ['T1056'],
                'severity': Severity.MEDIUM
            },
            'X-Content-Type-Options': {
                'critical': True,
                'description': 'Missing X-Content-Type-Options allows MIME sniffing',
                'mitre': ['T1189'],
                'severity': Severity.MEDIUM
            },
            'Referrer-Policy': {
                'critical': False,
                'description': 'Missing Referrer-Policy exposes URL data',
                'severity': Severity.LOW
            },
            'Permissions-Policy': {
                'critical': False,
                'description': 'Missing Permissions-Policy allows feature abuse',
                'severity': Severity.LOW
            },
            'X-XSS-Protection': {
                'critical': True,
                'description': 'Missing X-XSS-Protection header',
                'severity': Severity.MEDIUM
            }
        }
        
        try:
            async with session.head(target) as response:
                headers = response.headers
                
                for header, info in security_headers.items():
                    if header not in headers:
                        findings.append(Finding(
                            id=f"PMA-HEADER-{header.replace('-', '')}",
                            title=f"Missing {header} Header",
                            description=info['description'],
                            severity=info['severity'],
                            cvss_score=5.3 if info['critical'] else 3.1,
                            mitre_attack=info.get('mitre', []),
                            remediation=f"Add '{header}' header with appropriate values",
                            evidence={"header": header, "present": False}
                        ))
                    else:
                        # Check for weak values
                        if header == 'X-Frame-Options' and headers[header] not in ['DENY', 'SAMEORIGIN']:
                            findings.append(Finding(
                                id="PMA-HEADER-WEAK",
                                title=f"Weak {header} Configuration",
                                description=f"Found: {headers[header]}. Should be DENY or SAMEORIGIN",
                                severity=Severity.MEDIUM,
                                remediation="Set X-Frame-Options to DENY or SAMEORIGIN",
                                evidence={"header": header, "value": headers[header]}
                            ))
        except Exception as e:
            logger.error(f"Header check failed: {e}")
        
        return findings

class ExposedInterfacesPlugin(Plugin):
    name = "exposed_interfaces"
    description = "Check for exposed administrative interfaces"
    
    async def run(self, session: aiohttp.ClientSession, target: str, config: Dict) -> List[Finding]:
        findings = []
        
        sensitive_paths = {
            '/setup/': 'Setup interface',
            '/setup/index.php': 'Setup interface',
            '/doc/': 'Documentation',
            '/ChangeLog': 'Changelog file',
            '/README': 'README file',
            '/sql/': 'SQL directory',
            '/examples/': 'Examples directory',
            '/test/': 'Test directory',
            '/phpinfo.php': 'PHP info page',
            '/info.php': 'PHP info page',
            '/.git/': 'Git repository',
            '/.env': 'Environment file',
            '/backup/': 'Backup directory',
            '/old/': 'Old installation',
            '/tmp/': 'Temporary directory',
            '/config.inc.php': 'Configuration file',
            '/config.sample.inc.php': 'Sample configuration',
            '/themes/': 'Themes directory',
            '/js/': 'JavaScript directory'
        }
        
        for path, description in sensitive_paths.items():
            try:
                full_url = urljoin(target, path)
                async with session.get(full_url, allow_redirects=True) as response:
                    if response.status == 200:
                        findings.append(Finding(
                            id="PMA-EXPOSE-001",
                            title="Exposed Sensitive Path",
                            description=f"{description} accessible at {full_url}",
                            severity=Severity.MEDIUM if 'setup' in path else Severity.LOW,
                            cvss_score=5.3 if 'setup' in path else 3.1,
                            mitre_attack=["T1083"],
                            remediation=f"Restrict access to {path}",
                            evidence={"path": path, "url": full_url, "status": response.status}
                        ))
            except Exception:
                pass
        
        return findings

class CookieSecurityPlugin(Plugin):
    name = "cookie_security"
    description = "Check cookie security attributes"
    
    async def run(self, session: aiohttp.ClientSession, target: str, config: Dict) -> List[Finding]:
        findings = []
        
        try:
            async with session.get(target) as response:
                cookies = response.cookies
                
                for cookie in cookies:
                    attrs = {}
                    missing = []
                    
                    if not cookie.secure:
                        missing.append("Secure")
                    if not cookie.httponly:
                        missing.append("HttpOnly")
                    if not cookie.has_nonstandard_attr('SameSite'):
                        missing.append("SameSite")
                    
                    if missing:
                        findings.append(Finding(
                            id="PMA-COOKIE-001",
                            title="Insecure Cookie Configuration",
                            description=f"Cookie {cookie.key} missing: {', '.join(missing)}",
                            severity=Severity.MEDIUM,
                            cvss_score=5.3,
                            mitre_attack=["T1539"],
                            remediation="Add Secure, HttpOnly, and SameSite attributes",
                            evidence={"cookie": cookie.key, "missing": missing}
                        ))
        except Exception as e:
            logger.error(f"Cookie check failed: {e}")
        
        return findings

class TLSConfigurationPlugin(Plugin):
    name = "tls_configuration"
    description = "Check TLS/SSL configuration"
    
    async def run(self, session: aiohttp.ClientSession, target: str, config: Dict) -> List[Finding]:
        findings = []
        
        parsed = urlparse(target)
        if parsed.scheme != 'https':
            findings.append(Finding(
                id="PMA-TLS-001",
                title="No HTTPS in Use",
                description="Connection is not using TLS/SSL encryption",
                severity=Severity.HIGH,
                cvss_score=7.5,
                mitre_attack=["T1573"],
                remediation="Enable HTTPS and enforce TLS 1.2+"
            ))
        else:
            try:
                connector = aiohttp.TCPConnector(
                    ssl=False,  # For testing only
                    verify_ssl=False
                )
                async with aiohttp.ClientSession(connector=connector) as temp_session:
                    async with temp_session.get(target) as response:
                        # Check cipher version
                        if response.connection.transport:
                            protocol = response.connection.transport.get_extra_info('ssl_object')
                            if protocol:
                                version = protocol.version()
                                if version in ['TLSv1', 'TLSv1.1']:
                                    findings.append(Finding(
                                        id="PMA-TLS-002",
                                        title="Weak TLS Version",
                                        description=f"Using {version}, which is deprecated",
                                        severity=Severity.HIGH,
                                        cvss_score=7.5,
                                        mitre_attack=["T1573"],
                                        remediation="Upgrade to TLS 1.2 or 1.3"
                                    ))
            except Exception:
                pass
        
        return findings

class DirectoryListingPlugin(Plugin):
    name = "directory_listing"
    description = "Check for directory listing exposure"
    
    async def run(self, session: aiohttp.ClientSession, target: str, config: Dict) -> List[Finding]:
        findings = []
        
        common_dirs = ['', 'images/', 'css/', 'js/', 'themes/', 'tmp/']
        
        for dir_path in common_dirs:
            try:
                full_url = urljoin(target, dir_path)
                async with session.get(full_url) as response:
                    html = await response.text()
                    
                    if 'Index of' in html or 'Parent Directory' in html:
                        findings.append(Finding(
                            id="PMA-DIR-001",
                            title="Directory Listing Exposed",
                            description=f"Directory listing enabled at {full_url}",
                            severity=Severity.MEDIUM,
                            cvss_score=5.3,
                            mitre_attack=["T1083"],
                            remediation="Disable directory listing in web server configuration",
                            evidence={"path": full_url}
                        ))
            except Exception:
                pass
        
        return findings

class WeakHTTPMethodsPlugin(Plugin):
    name = "weak_http_methods"
    description = "Check for insecure HTTP methods"
    
    async def run(self, session: aiohttp.ClientSession, target: str, config: Dict) -> List[Finding]:
        findings = []
        dangerous_methods = ['TRACE', 'TRACK', 'OPTIONS']
        
        try:
            for method in dangerous_methods:
                async with session.request(method, target) as response:
                    if response.status == 200:
                        findings.append(Finding(
                            id="PMA-HTTP-001",
                            title=f"HTTP {method} Method Enabled",
                            description=f"Dangerous HTTP method available",
                            severity=Severity.MEDIUM,
                            cvss_score=5.3,
                            mitre_attack=["T1046"],
                            remediation=f"Disable {method} method",
                            evidence={"method": method}
                        ))
        except Exception:
            pass
        
        return findings

class BackupFileExposurePlugin(Plugin):
    name = "backup_exposure"
    description = "Check for exposed backup files"
    
    async def run(self, session: aiohttp.ClientSession, target: str, config: Dict) -> List[Finding]:
        findings = []
        
        backup_patterns = [
            '*.bak', '*.backup', '*.old', '*.orig',
            '*.sql', '*.dump', '*.zip', '*.tar.gz',
            '*.conf', 'config.inc.php~', 'config.inc.php.bak'
        ]
        
        for pattern in backup_patterns:
            try:
                # Check common backup locations
                backup_paths = [
                    target + '/' + pattern.replace('*', 'config'),
                    target + '/' + pattern.replace('*', 'database'),
                    target + '/' + pattern.replace('*', 'backup')
                ]
                
                for backup_url in backup_paths:
                    async with session.get(backup_url) as response:
                        if response.status == 200:
                            findings.append(Finding(
                                id="PMA-BACKUP-001",
                                title="Backup File Exposed",
                                description=f"Backup file accessible at {backup_url}",
                                severity=Severity.HIGH,
                                cvss_score=6.5,
                                mitre_attack=["T1083"],
                                remediation="Remove backup files from web root",
                                evidence={"file": backup_url}
                            ))
            except Exception:
                pass
        
        return findings

class ServerBannerPlugin(Plugin):
    name = "server_banner"
    description = "Extract server information from headers"
    
    async def run(self, session: aiohttp.ClientSession, target: str, config: Dict) -> List[Finding]:
        findings = []
        
        sensitive_headers = ['Server', 'X-Powered-By']
        
        try:
            async with session.head(target) as response:
                for header in sensitive_headers:
                    if header in response.headers:
                        findings.append(Finding(
                            id="PMA-INFO-001",
                            title="Information Disclosure",
                            description=f"{header} header reveals: {response.headers[header]}",
                            severity=Severity.LOW,
                            cvss_score=2.1,
                            mitre_attack=["T1592"],
                            remediation=f"Remove or obfuscate {header} header",
                            evidence={"header": header, "value": response.headers[header]}
                        ))
        except Exception:
            pass
        
        return findings

# ==================== Main Scanner ====================

class PHPSecurityAudit:
    """Main security audit engine"""
    
    def __init__(self, target: str, config_path: str = None, output_dir: str = "reports"):
        self.target = target.rstrip('/')
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.plugins = []
        self.config = self.load_config(config_path) if config_path else {}
        self.results = ScanResult(
            target=target,
            timestamp=datetime.now().isoformat(),
            duration=0,
            version="2.0"
        )
        
        # Register plugins
        self.register_plugins()
    
    def load_config(self, config_path: str) -> Dict:
        """Load configuration from YAML or JSON"""
        with open(config_path, 'r') as f:
            if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                return yaml.safe_load(f)
            elif config_path.endswith('.json'):
                return json.load(f)
        return {}
    
    def register_plugins(self):
        """Register all enabled plugins"""
        plugins = [
            VersionDetectionPlugin(),
            SecurityHeadersPlugin(),
            ExposedInterfacesPlugin(),
            CookieSecurityPlugin(),
            TLSConfigurationPlugin(),
            DirectoryListingPlugin(),
            WeakHTTPMethodsPlugin(),
            BackupFileExposurePlugin(),
            ServerBannerPlugin()
        ]
        
        # Filter plugins based on config
        if 'enabled_plugins' in self.config:
            enabled = self.config['enabled_plugins']
            self.plugins = [p for p in plugins if p.name in enabled]
        else:
            self.plugins = plugins
        
        logger.info(f"Registered {len(self.plugins)} plugins")
    
    async def scan(self):
        """Execute full security audit"""
        start_time = time.time()
        logger.info(f"Starting audit of {self.target}")
        
        # Progress tracking
        progress = tqdm(total=len(self.plugins), desc="Scanning", unit="plugins")
        
        # Configure session
        connector = aiohttp.TCPConnector(
            limit=10,
            ttl_dns_cache=300,
            ssl=False if self.target.startswith('http://') else True
        )
        
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5'
            }
        ) as session:
            
            # Run plugins in parallel
            tasks = []
            for plugin in self.plugins:
                task = self.run_plugin(plugin, session)
                tasks.append(task)
            
            # Collect results
            for future in asyncio.as_completed(tasks):
                try:
                    findings = await future
                    self.results.findings.extend(findings)
                    progress.update(1)
                except Exception as e:
                    logger.error(f"Plugin execution failed: {e}")
                    progress.update(1)
        
        progress.close()
        
        # Calculate summary
        self.results.duration = time.time() - start_time
        self.results.summary = self.calculate_summary()
        
        # Save results
        self.save_results()
        self.generate_reports()
        
        logger.info(f"Audit complete in {self.results.duration:.2f}s")
        logger.info(f"Found {len(self.results.findings)} issues")
    
    async def run_plugin(self, plugin: Plugin, session: aiohttp.ClientSession) -> List[Finding]:
        """Run a single plugin with retry logic"""
        max_retries = 3
        backoff = 1
        
        for attempt in range(max_retries):
            try:
                return await plugin.run(session, self.target, self.config)
            except Exception as e:
                if attempt < max_retries - 1:
                    logger.warning(f"Plugin {plugin.name} failed, retrying in {backoff}s")
                    await asyncio.sleep(backoff)
                    backoff *= 2
                else:
                    logger.error(f"Plugin {plugin.name} failed after {max_retries} attempts: {e}")
                    return []
    
    def calculate_summary(self) -> Dict[str, int]:
        """Calculate severity summary"""
        summary = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }
        
        for finding in self.results.findings:
            summary[finding.severity.value] += 1
        
        return summary
    
    def save_results(self):
        """Save results in multiple formats"""
        # JSON
        json_path = self.output_dir / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_path, 'w') as f:
            json.dump({
                'target': self.results.target,
                'timestamp': self.results.timestamp,
                'duration': self.results.duration,
                'summary': self.results.summary,
                'findings': [asdict(f) for f in self.results.findings]
            }, f, indent=2, default=str)
        
        # CSV
        csv_path = self.output_dir / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(csv_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['ID', 'Title', 'Severity', 'CVSS', 'MITRE', 'Description', 'Remediation'])
            for finding in self.results.findings:
                writer.writerow([
                    finding.id,
                    finding.title,
                    finding.severity.value,
                    finding.cvss_score,
                    ', '.join(finding.mitre_attack),
                    finding.description,
                    finding.remediation
                ])
        
        logger.info(f"Results saved to {self.output_dir}")
    
    def generate_reports(self):
        """Generate HTML and Markdown reports"""
        # Markdown
        md_content = self.generate_markdown()
        md_path = self.output_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(md_path, 'w') as f:
            f.write(md_content)
        
        # HTML
        html_content = self.generate_html(md_content)
        html_path = self.output_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(html_path, 'w') as f:
            f.write(html_content)
    
    def generate_markdown(self) -> str:
        """Generate Markdown report"""
        md = f"""# PHPMyAdmin Security Assessment Report

## Executive Summary

- **Target:** {self.results.target}
- **Date:** {self.results.timestamp}
- **Duration:** {self.results.duration:.2f} seconds
- **Total Findings:** {len(self.results.findings)}

### Risk Summary

| Severity | Count |
|----------|-------|
| CRITICAL | {self.results.summary.get('CRITICAL', 0)} |
| HIGH     | {self.results.summary.get('HIGH', 0)} |
| MEDIUM   | {self.results.summary.get('MEDIUM', 0)} |
| LOW      | {self.results.summary.get('LOW', 0)} |
| INFO     | {self.results.summary.get('INFO', 0)} |

## Detailed Findings

"""
        
        for finding in self.results.findings:
            md += f"""
### {finding.id}: {finding.title}

- **Severity:** {finding.severity.value}
- **CVSS Score:** {finding.cvss_score}
- **MITRE ATT&CK:** {', '.join(finding.mitre_attack)}
- **Description:** {finding.description}
- **Remediation:** {finding.remediation}
- **Evidence:** {json.dumps(finding.evidence, indent=2)}

---
"""
        
        return md
    
    def generate_html(self, md_content: str) -> str:
        """Generate HTML report from Markdown"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>PHPMyAdmin Security Assessment Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
            color: #333;
        }}
        .container {{
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .severity-CRITICAL {{ color: #721c24; background: #f8d7da; }}
        .severity-HIGH {{ color: #856404; background: #fff3cd; }}
        .severity-MEDIUM {{ color: #0c5460; background: #d1ecf1; }}
        .severity-LOW {{ color: #383d41; background: #e2e3e5; }}
        .severity-INFO {{ color: #004085; background: #cce5ff; }}
        .finding {{
            margin-bottom: 20px;
            padding: 15px;
            border-radius: 4px;
            border-left: 4px solid #ccc;
        }}
        .finding.CRITICAL {{ border-left-color: #dc3545; }}
        .finding.HIGH {{ border-left-color: #ffc107; }}
        .finding.MEDIUM {{ border-left-color: #17a2b8; }}
        .finding.LOW {{ border-left-color: #6c757d; }}
        .finding.INFO {{ border-left-color: #007bff; }}
        h1, h2 {{ color: #2c3e50; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #f8f9fa;
            font-weight: 600;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="container">
        {markdown.markdown(md_content, extensions=['extra', 'tables'])}
    </div>
</body>
</html>"""
        return html

# ==================== CLI Interface ====================

def main():
    """Command-line interface"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='PHPMyAdmin Advanced Security Assessment Framework v1.0',
        epilog='For authorized testing only'
    )
    
    parser.add_argument('target', help='Target URL (e.g., https://example.com/phpmyadmin)')
    parser.add_argument('-c', '--config', help='Configuration file (YAML/JSON)')
    parser.add_argument('-o', '--output', default='reports', help='Output directory')
    parser.add_argument('--quick', action='store_true', help='Quick scan mode')
    parser.add_argument('--full', action='store_true', help='Full scan mode')
    parser.add_argument('--plugins', help='Comma-separated list of plugins to run')
    
    # Import Nmap XML
    parser.add_argument('--nmap', help='Import targets from Nmap XML file')
    parser.add_argument('--burp', help='Import targets from Burp Suite export')
    
    args = parser.parse_args()
    
    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║  PHPMyAdmin Advanced Security Assessment Framework v1.0     ║
║  Author | Sudeepa Wanigarathna                              ║
║  For Authorized Testing Only                                ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """)
    
    # Security disclaimer
    print(f"{Fore.YELLOW}⚠  SECURITY NOTICE{Style.RESET_ALL}")
    print("This tool is for AUTHORIZED SECURITY TESTING ONLY.")
    print("You must have EXPLICIT WRITTEN PERMISSION to test the target.")
    
    if input("\nConfirm authorization (yes/no): ").lower() != 'yes':
        print(f"{Fore.RED}[!] Authorization required. Exiting...{Style.RESET_ALL}")
        sys.exit(1)
    
    # Handle Nmap import
    if args.nmap:
        try:
            tree = ET.parse(args.nmap)
            root = tree.getroot()
            hosts = []
            for host in root.findall('.//host'):
                addr = host.find('.//address')
                if addr is not None:
                    hosts.append(addr.get('addr'))
            
            print(f"{Fore.GREEN}[+] Loaded {len(hosts)} targets from Nmap{Style.RESET_ALL}")
            
            # Run scans sequentially
            for host in hosts:
                scanner = PHPSecurityAudit(f"http://{host}/phpmyadmin", args.config, args.output)
                asyncio.run(scanner.scan())
        except Exception as e:
            logger.error(f"Failed to parse Nmap XML: {e}")
    
    # Normal scan
    else:
        scanner = PHPSecurityAudit(args.target, args.config, args.output)
        
        if args.plugins:
            scanner.plugins = [p for p in scanner.plugins if p.name in args.plugins.split(',')]
        
        asyncio.run(scanner.scan())

if __name__ == "__main__":
    main()

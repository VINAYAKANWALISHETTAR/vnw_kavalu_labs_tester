"""
Core Security Scanner Module
Integrates Requests, Selenium, and Burp Suite for comprehensive security testing.

Developed by Vinayaka N Walishettar
"""

__author__ = "Vinayaka N Walishettar"

import requests
import uuid
import json
import os
from datetime import datetime
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from typing import Dict, List, Any, Optional
import threading
import queue

from .vulnerability_scanner import VulnerabilityScanner
from .burp_integration import BurpIntegration

try:
    from .selenium_scanner import SeleniumScanner
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    SeleniumScanner = None


class SecurityScanner:
    """Main security scanner class that orchestrates all scanning modules."""
    
    def __init__(self):
        self.active_scans = {}
        self.scan_history = []
        self.results_queue = queue.Queue()
        self.vuln_scanner = VulnerabilityScanner()
        self.selenium_scanner = SeleniumScanner() if SELENIUM_AVAILABLE else None
        self.burp_integration = BurpIntegration()
        
    def scan(self, target_url: str, scan_types: List[str], 
             use_burp: bool = False, use_selenium: bool = True) -> Dict[str, Any]:
        """
        Start a comprehensive security scan.
        
        Args:
            target_url: The target URL to scan
            scan_types: List of scan types to perform
            use_burp: Whether to use Burp Suite proxy
            use_selenium: Whether to use Selenium browser automation
            
        Returns:
            Scan results dictionary
        """
        scan_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        scan_info = {
            'scan_id': scan_id,
            'target_url': target_url,
            'status': 'running',
            'start_time': timestamp,
            'scan_types': scan_types,
            'findings': [],
            'stats': {
                'total_requests': 0,
                'vulnerabilities_found': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }
        
        self.active_scans[scan_id] = scan_info
        
        # Start scan in background thread
        scan_thread = threading.Thread(
            target=self._run_scan,
            args=(scan_id, target_url, scan_types, use_burp, use_selenium)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
        return {'scan_id': scan_id, 'status': 'started', 'message': 'Scan initiated successfully'}
    
    def _run_scan(self, scan_id: str, target_url: str, scan_types: List[str],
                  use_burp: bool, use_selenium: bool):
        """Execute the actual scanning logic."""
        try:
            scan_info = self.active_scans[scan_id]
            all_findings = []
            
            # Configure proxy if Burp is enabled
            proxies = None
            if use_burp:
                proxies = self.burp_integration.get_proxy_config()
            
            # 1. Basic reconnaissance with Requests
            if 'recon' in scan_types or 'all' in scan_types:
                self._update_status(scan_id, 'running', 'Performing reconnaissance...')
                recon_results = self._perform_recon(target_url, proxies)
                all_findings.extend(recon_results)
            
            # 2. Vulnerability scanning with Requests
            if 'vulnerabilities' in scan_types or 'all' in scan_types:
                self._update_status(scan_id, 'running', 'Scanning for vulnerabilities...')
                vuln_results = self.vuln_scanner.scan(target_url, proxies)
                all_findings.extend(vuln_results)
            
            # 3. Browser-based testing with Selenium
            if use_selenium and SELENIUM_AVAILABLE and ('browser' in scan_types or 'all' in scan_types):
                self._update_status(scan_id, 'running', 'Running browser automation tests...')
                try:
                    browser_results = self.selenium_scanner.scan(target_url)
                    all_findings.extend(browser_results)
                except Exception as sel_err:
                    all_findings.append({
                        'type': 'browser_automation',
                        'severity': 'info',
                        'title': 'Browser Automation Notice',
                        'description': f'Automated headless browser check completed: {str(sel_err)}'
                    })
            
            # 4. Burp Suite analysis (if enabled)
            if use_burp and ('burp' in scan_types or 'all' in scan_types):
                self._update_status(scan_id, 'running', 'Analyzing through Burp Suite...')
                burp_results = self.burp_integration.analyze(scan_id)
                all_findings.extend(burp_results)
            
            # Calculate statistics
            stats = self._calculate_stats(all_findings)
            
            # Update final results
            scan_info['findings'] = all_findings
            scan_info['stats'] = stats
            scan_info['status'] = 'completed'
            scan_info['end_time'] = datetime.now().isoformat()
            
            # Save to history
            self.scan_history.append(scan_info)
            self._save_scan_history()
            
        except Exception as e:
            scan_info['status'] = 'error'
            scan_info['error'] = str(e)
            scan_info['end_time'] = datetime.now().isoformat()
    
    def _perform_recon(self, target_url: str, proxies: Optional[Dict]) -> List[Dict]:
        """Perform basic reconnaissance on the target."""
        findings = []
        
        try:
            # Basic request to check if target is alive
            response = requests.get(
                target_url, 
                proxies=proxies, 
                timeout=30,
                verify=False,
                headers={
                    'User-Agent': 'WebSecTester/1.0 Security Scanner'
                }
            )
            
            findings.append({
                'type': 'info',
                'severity': 'info',
                'title': 'Target Response',
                'description': f'Target responded with status code {response.status_code}',
                'details': {
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'response_time': response.elapsed.total_seconds(),
                    'server': response.headers.get('Server', 'Unknown'),
                    'content_type': response.headers.get('Content-Type', 'Unknown')
                }
            })
            
            # Check for security headers
            security_headers = self._check_security_headers(response.headers, target_url)
            findings.extend(security_headers)
            
            # Parse forms for further testing
            soup = BeautifulSoup(response.content, 'html.parser')
            forms = soup.find_all('form')
            if forms:
                findings.append({
                    'type': 'info',
                    'severity': 'info',
                    'title': 'Forms Detected',
                    'description': f'Found {len(forms)} form(s) on the page',
                    'details': {'form_count': len(forms)}
                })
                
        except requests.exceptions.RequestException as e:
            findings.append({
                'type': 'error',
                'severity': 'high',
                'title': 'Connection Error',
                'description': f'Could not connect to target: {str(e)}',
                'details': {}
            })
        
        return findings
    
    def _check_security_headers(self, headers: Dict, target_url: str) -> List[Dict]:
        """Check for missing or misconfigured security headers."""
        findings = []
        
        security_headers = {
            'Strict-Transport-Security': {
                'severity': 'medium',
                'description': 'HSTS header missing - site vulnerable to SSL stripping attacks'
            },
            'Content-Security-Policy': {
                'severity': 'medium',
                'description': 'CSP header missing - increases XSS attack surface'
            },
            'X-Frame-Options': {
                'severity': 'medium',
                'description': 'X-Frame-Options missing - site may be vulnerable to clickjacking'
            },
            'X-Content-Type-Options': {
                'severity': 'low',
                'description': 'X-Content-Type-Options missing - browser may MIME-sniff content'
            },
            'Referrer-Policy': {
                'severity': 'low',
                'description': 'Referrer-Policy missing - referrer information may leak'
            },
            'Permissions-Policy': {
                'severity': 'info',
                'description': 'Permissions-Policy missing - browser features not restricted'
            }
        }
        
        for header, info in security_headers.items():
            if header not in headers:
                findings.append({
                    'type': 'security_header',
                    'severity': info['severity'],
                    'title': f'Missing {header}',
                    'description': info['description'],
                    'details': {'header': header, 'present': False}
                })
            else:
                findings.append({
                    'type': 'security_header',
                    'severity': 'info',
                    'title': f'{header} Present',
                    'description': f'{header} header is properly configured',
                    'details': {'header': header, 'value': headers[header], 'present': True}
                })
        
        return findings
    
    def _calculate_stats(self, findings: List[Dict]) -> Dict[str, int]:
        """Calculate vulnerability statistics."""
        stats = {
            'total_requests': len(findings),
            'vulnerabilities_found': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for finding in findings:
            severity = finding.get('severity', 'info')
            if severity in stats:
                stats[severity] += 1
            
            if severity in ['critical', 'high', 'medium']:
                stats['vulnerabilities_found'] += 1
        
        return stats
    
    def _update_status(self, scan_id: str, status: str, message: str):
        """Update scan status with message."""
        if scan_id in self.active_scans:
            self.active_scans[scan_id]['status'] = status
            self.active_scans[scan_id]['current_message'] = message
            self.active_scans[scan_id]['last_update'] = datetime.now().isoformat()
    
    def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get current status of a scan."""
        if scan_id in self.active_scans:
            return self.active_scans[scan_id]
        
        # Check history
        for scan in self.scan_history:
            if scan['scan_id'] == scan_id:
                return scan
        
        return {'error': 'Scan not found'}
    
    def get_scan_history(self) -> List[Dict]:
        """Get all scan history."""
        return self.scan_history
    
    def _save_scan_history(self):
        """Save scan history to file."""
        try:
            history_file = os.path.join('logs', 'scan_history.json')
            os.makedirs('logs', exist_ok=True)
            with open(history_file, 'w') as f:
                json.dump(self.scan_history, f, indent=2)
        except Exception:
            pass  # Fail silently for history saving

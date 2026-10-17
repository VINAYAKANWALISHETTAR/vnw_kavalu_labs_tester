"""
Burp Suite Integration Module
Provides integration with Burp Suite proxy and API.

Developed by Vinayaka N Walishettar
"""

__author__ = "Vinayaka N Walishettar"

import requests
import json
from typing import Dict, List, Any, Optional


class BurpIntegration:
    """Integration with Burp Suite Professional/Community Edition."""
    
    def __init__(self, proxy_host: str = '127.0.0.1', proxy_port: int = 8080):
        """
        Initialize Burp Suite integration.
        
        Args:
            proxy_host: Burp proxy host
            proxy_port: Burp proxy port
        """
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.api_url = None  # For Burp Professional API
        self.api_key = None
        
    def get_proxy_config(self) -> Dict[str, str]:
        """
        Get proxy configuration for requests.
        
        Returns:
            Dictionary with http and https proxy URLs
        """
        proxy_url = f"http://{self.proxy_host}:{self.proxy_port}"
        return {
            'http': proxy_url,
            'https': proxy_url
        }
    
    def set_api_credentials(self, api_url: str, api_key: str):
        """
        Set Burp Professional API credentials.
        
        Args:
            api_url: Burp API URL (e.g., http://localhost:1337/v0.1/)
            api_key: API key for authentication
        """
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
    
    def is_proxy_running(self) -> bool:
        """Check if Burp proxy is accessible."""
        try:
            # Try to connect through the proxy
            proxies = self.get_proxy_config()
            response = requests.get(
                'http://httpbin.org/get',
                proxies=proxies,
                timeout=5
            )
            return True
        except requests.exceptions.RequestException:
            return False
    
    def analyze(self, scan_id: str) -> List[Dict]:
        """
        Analyze scan through Burp Suite.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            List of findings from Burp analysis
        """
        findings = []
        
        # Check if Burp proxy is available
        if not self.is_proxy_running():
            findings.append({
                'type': 'burp',
                'severity': 'info',
                'title': 'Burp Suite Proxy Not Available',
                'description': f'Could not connect to Burp proxy at {self.proxy_host}:{self.proxy_port}',
                'details': {
                    'proxy_host': self.proxy_host,
                    'proxy_port': self.proxy_port
                },
                'remediation': 'Ensure Burp Suite is running and proxy is configured correctly.'
            })
            return findings
        
        findings.append({
            'type': 'burp',
            'severity': 'info',
            'title': 'Burp Suite Proxy Connected',
            'description': f'Successfully connected to Burp proxy at {self.proxy_host}:{self.proxy_port}',
            'details': {
                'proxy_host': self.proxy_host,
                'proxy_port': self.proxy_port
            }
        })
        
        # If API is configured, try to get scan results
        if self.api_url and self.api_key:
            api_results = self._fetch_api_results(scan_id)
            findings.extend(api_results)
        
        return findings
    
    def _fetch_api_results(self, scan_id: str) -> List[Dict]:
        """Fetch scan results from Burp API."""
        findings = []
        
        try:
            headers = {'Authorization': f'Bearer {self.api_key}'}
            
            # Get scan issues
            response = requests.get(
                f'{self.api_url}/scan/{scan_id}/issues',
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                issues = response.json()
                
                for issue in issues:
                    severity_map = {
                        'high': 'high',
                        'medium': 'medium',
                        'low': 'low',
                        'information': 'info'
                    }
                    
                    findings.append({
                        'type': 'burp_issue',
                        'severity': severity_map.get(issue.get('severity', 'info'), 'info'),
                        'title': issue.get('name', 'Burp Issue'),
                        'description': issue.get('description', 'No description available'),
                        'details': {
                            'issue_type': issue.get('type', 'unknown'),
                            'host': issue.get('host', ''),
                            'path': issue.get('path', ''),
                            'confidence': issue.get('confidence', 'unknown')
                        },
                        'remediation': issue.get('remediation', 'See Burp Suite documentation for remediation advice.')
                    })
            else:
                findings.append({
                    'type': 'burp',
                    'severity': 'info',
                    'title': 'Burp API Response',
                    'description': f'API returned status code: {response.status_code}',
                    'details': {'status_code': response.status_code}
                })
                
        except requests.exceptions.RequestException as e:
            findings.append({
                'type': 'burp',
                'severity': 'info',
                'title': 'Burp API Error',
                'description': f'Could not fetch results from Burp API: {str(e)}',
                'details': {}
            })
        
        return findings
    
    def start_scan(self, target_url: str) -> Dict[str, Any]:
        """
        Start a new scan using Burp Enterprise/Professional.
        
        Args:
            target_url: URL to scan
            
        Returns:
            Scan initiation result
        """
        if not self.api_url or not self.api_key:
            return {
                'error': 'Burp API not configured',
                'message': 'Set API credentials first using set_api_credentials()'
            }
        
        try:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            data = {
                'urls': [target_url],
                'scan_configurations': ['Lightweight']
            }
            
            response = requests.post(
                f'{self.api_url}/scan',
                headers=headers,
                json=data,
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                result = response.json()
                return {
                    'success': True,
                    'scan_id': result.get('scan_id'),
                    'message': 'Scan started successfully'
                }
            else:
                return {
                    'error': 'Failed to start scan',
                    'status_code': response.status_code,
                    'response': response.text
                }
                
        except requests.exceptions.RequestException as e:
            return {
                'error': 'Request failed',
                'message': str(e)
            }
    
    def get_proxy_ca_cert(self) -> Optional[str]:
        """
        Get Burp CA certificate for SSL verification.
        
        Returns:
            Path to CA certificate or None
        """
        # Burp CA cert can be downloaded from http://burpsuite/cert when proxy is running
        try:
            proxies = self.get_proxy_config()
            response = requests.get(
                'http://burpsuite/cert',
                proxies=proxies,
                timeout=5
            )
            
            if response.status_code == 200:
                # Save certificate
                cert_path = 'burp_ca_cert.der'
                with open(cert_path, 'wb') as f:
                    f.write(response.content)
                return cert_path
                
        except requests.exceptions.RequestException:
            pass
        
        return None
    
    def configure_proxy_in_browser(self, driver):
        """
        Configure Selenium WebDriver to use Burp proxy.
        
        Args:
            driver: Selenium WebDriver instance
        """
        # This would configure the driver's proxy settings
        # Implementation depends on the browser/driver type
        pass

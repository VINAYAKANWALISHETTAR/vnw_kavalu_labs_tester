"""
Selenium Scanner Module
Browser-based security testing using Selenium WebDriver.

Developed by Vinayaka N Walishettar
"""

__author__ = "Vinayaka N Walishettar"

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import TimeoutException, NoAlertPresentException, UnexpectedAlertPresentException
from typing import Dict, List, Any, Optional
import time
import re


class SeleniumScanner:
    """Browser-based security scanner using Selenium."""
    
    def __init__(self):
        self.driver = None
        self.timeout = 10
        
    def _init_driver(self, proxy: Optional[str] = None):
        """Initialize Chrome WebDriver with options."""
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--window-size=1920,1080')
        chrome_options.add_argument('--user-agent=WebSecTester/1.0 Security Scanner')
        chrome_options.add_argument('--ignore-certificate-errors')
        chrome_options.add_argument('--allow-insecure-localhost')
        
        if proxy:
            chrome_options.add_argument(f'--proxy-server={proxy}')
        
        # Disable logging
        chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
        
        try:
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
            self.driver.set_page_load_timeout(30)
        except Exception as e:
            raise Exception(f"Failed to initialize Chrome driver: {str(e)}")
    
    def scan(self, target_url: str, proxy: Optional[str] = None) -> List[Dict]:
        """
        Perform browser-based security scan.
        
        Args:
            target_url: URL to scan
            proxy: Optional proxy URL
            
        Returns:
            List of findings
        """
        findings = []
        
        try:
            self._init_driver(proxy)
            
            # 1. DOM-based XSS testing
            dom_xss_results = self._test_dom_xss(target_url)
            findings.extend(dom_xss_results)
            
            # 2. Check for mixed content
            mixed_content_results = self._check_mixed_content(target_url)
            findings.extend(mixed_content_results)
            
            # 3. Check for insecure forms
            insecure_forms_results = self._check_insecure_forms(target_url)
            findings.extend(insecure_forms_results)
            
            # 4. Test for clickjacking protection
            clickjacking_results = self._test_clickjacking(target_url)
            findings.extend(clickjacking_results)
            
            # 5. Client-side storage check
            storage_results = self._check_client_storage(target_url)
            findings.extend(storage_results)
            
        except Exception as e:
            findings.append({
                'type': 'error',
                'severity': 'info',
                'title': 'Selenium Scan Error',
                'description': f'Error during browser scan: {str(e)}',
                'details': {}
            })
        finally:
            if self.driver:
                try:
                    self.driver.quit()
                except:
                    pass
                self.driver = None
        
        return findings
    
    def _test_dom_xss(self, target_url: str) -> List[Dict]:
        """Test for DOM-based XSS vulnerabilities."""
        findings = []
        
        try:
            # Test with hash-based XSS
            test_url = f"{target_url}#<img src=x onerror=alert(1)>"
            self.driver.get(test_url)
            time.sleep(2)
            
            # Check if alert was triggered
            try:
                alert = self.driver.switch_to.alert
                alert_text = alert.text
                alert.accept()
                findings.append({
                    'type': 'dom_xss',
                    'severity': 'critical',
                    'title': 'DOM-based XSS Vulnerability',
                    'description': 'DOM-based XSS detected - JavaScript executed from URL hash',
                    'details': {
                        'payload': '<img src=x onerror=alert(1)>',
                        'url': test_url,
                        'alert_text': alert_text
                    },
                    'remediation': 'Sanitize all user input before inserting into DOM. Use textContent instead of innerHTML.'
                })
            except NoAlertPresentException:
                pass
            
            # Test location.hash manipulation
            hash_payloads = [
                "#'-alert(1)-'",
                "#<script>alert(1)</script>",
                "#javascript:alert(1)"
            ]
            
            for payload in hash_payloads:
                try:
                    test_url = f"{target_url}{payload}"
                    self.driver.get(test_url)
                    time.sleep(1)
                    
                    try:
                        alert = self.driver.switch_to.alert
                        alert.accept()
                        findings.append({
                            'type': 'dom_xss',
                            'severity': 'critical',
                            'title': 'DOM-based XSS via Location Hash',
                            'description': f'XSS payload executed from URL hash',
                            'details': {
                                'payload': payload,
                                'url': test_url
                            },
                            'remediation': 'Validate and sanitize location.hash before using in DOM operations.'
                        })
                        break
                    except NoAlertPresentException:
                        continue
                        
                except Exception:
                    continue
                    
        except Exception as e:
            findings.append({
                'type': 'info',
                'severity': 'info',
                'title': 'DOM XSS Test Incomplete',
                'description': f'Could not complete DOM XSS testing: {str(e)}',
                'details': {}
            })
        
        return findings
    
    def _check_mixed_content(self, target_url: str) -> List[Dict]:
        """Check for mixed content (HTTP resources on HTTPS page)."""
        findings = []
        
        try:
            self.driver.get(target_url)
            time.sleep(2)
            
            # Get current URL protocol
            current_url = self.driver.current_url
            is_https = current_url.startswith('https')
            
            if not is_https:
                findings.append({
                    'type': 'info',
                    'severity': 'info',
                    'title': 'Not HTTPS',
                    'description': 'Target is not using HTTPS',
                    'details': {'url': current_url}
                })
                return findings
            
            # Check for HTTP resources
            http_resources = []
            
            # Check images
            images = self.driver.find_elements(By.TAG_NAME, 'img')
            for img in images:
                src = img.get_attribute('src')
                if src and src.startswith('http:'):
                    http_resources.append({'type': 'image', 'src': src})
            
            # Check scripts
            scripts = self.driver.find_elements(By.TAG_NAME, 'script')
            for script in scripts:
                src = script.get_attribute('src')
                if src and src.startswith('http:'):
                    http_resources.append({'type': 'script', 'src': src})
            
            # Check stylesheets
            links = self.driver.find_elements(By.TAG_NAME, 'link')
            for link in links:
                rel = link.get_attribute('rel')
                href = link.get_attribute('href')
                if rel == 'stylesheet' and href and href.startswith('http:'):
                    http_resources.append({'type': 'stylesheet', 'href': href})
            
            # Check iframes
            iframes = self.driver.find_elements(By.TAG_NAME, 'iframe')
            for iframe in iframes:
                src = iframe.get_attribute('src')
                if src and src.startswith('http:'):
                    http_resources.append({'type': 'iframe', 'src': src})
            
            if http_resources:
                findings.append({
                    'type': 'mixed_content',
                    'severity': 'medium',
                    'title': 'Mixed Content Detected',
                    'description': f'Found {len(http_resources)} HTTP resource(s) on HTTPS page',
                    'details': {
                        'count': len(http_resources),
                        'resources': http_resources[:5]  # Limit to first 5
                    },
                    'remediation': 'Load all resources over HTTPS. Use protocol-relative URLs or always use HTTPS.'
                })
            
        except Exception as e:
            findings.append({
                'type': 'info',
                'severity': 'info',
                'title': 'Mixed Content Check Incomplete',
                'description': f'Could not complete mixed content check: {str(e)}',
                'details': {}
            })
        
        return findings
    
    def _check_insecure_forms(self, target_url: str) -> List[Dict]:
        """Check for forms submitting to HTTP on HTTPS pages."""
        findings = []
        
        try:
            self.driver.get(target_url)
            time.sleep(2)
            
            current_url = self.driver.current_url
            is_https = current_url.startswith('https')
            
            forms = self.driver.find_elements(By.TAG_NAME, 'form')
            insecure_forms = []
            
            for form in forms:
                action = form.get_attribute('action') or ''
                if action.startswith('http:') or (not action and not is_https):
                    form_html = form.get_attribute('outerHTML')[:200]
                    insecure_forms.append({
                        'action': action or 'Current page (insecure)',
                        'html_snippet': form_html
                    })
            
            if insecure_forms:
                findings.append({
                    'type': 'insecure_form',
                    'severity': 'high',
                    'title': 'Insecure Form Submission',
                    'description': f'Found {len(insecure_forms)} form(s) submitting to HTTP',
                    'details': {
                        'count': len(insecure_forms),
                        'forms': insecure_forms[:3]
                    },
                    'remediation': 'Ensure all forms submit to HTTPS endpoints.'
                })
            
            # Check for password/autocomplete on sensitive fields
            password_inputs = self.driver.find_elements(By.XPATH, "//input[@type='password']")
            for pwd_input in password_inputs:
                autocomplete = pwd_input.get_attribute('autocomplete')
                if not autocomplete or autocomplete == 'on':
                    findings.append({
                        'type': 'password_security',
                        'severity': 'low',
                        'title': 'Password Field Autocomplete',
                        'description': 'Password field may have autocomplete enabled',
                        'details': {'autocomplete': autocomplete or 'not set'},
                        'remediation': 'Set autocomplete="new-password" or autocomplete="current-password" appropriately.'
                    })
            
        except Exception as e:
            findings.append({
                'type': 'info',
                'severity': 'info',
                'title': 'Form Security Check Incomplete',
                'description': f'Could not complete form security check: {str(e)}',
                'details': {}
            })
        
        return findings
    
    def _test_clickjacking(self, target_url: str) -> List[Dict]:
        """Test for clickjacking vulnerability."""
        findings = []
        
        try:
            # Check if we can iframe the target
            test_html = f"""
            <!DOCTYPE html>
            <html>
            <head><title>Clickjacking Test</title></head>
            <body>
                <iframe src="{target_url}" style="width:100%;height:500px;"></iframe>
            </body>
            </html>
            """
            
            # We can't directly test this, but we can check for X-Frame-Options
            self.driver.get(target_url)
            
            # Try to execute script to check frame busting
            frame_busting = self.driver.execute_script("""
                if (window.top !== window.self) {
                    return 'frame-busting-detected';
                }
                return 'no-frame-busting';
            """)
            
            # Since we're not in a frame, this won't help much
            # Instead, we'll rely on the security headers check
            
            findings.append({
                'type': 'clickjacking',
                'severity': 'info',
                'title': 'Clickjacking Test',
                'description': 'Clickjacking protection should be verified via security headers',
                'details': {'note': 'Check X-Frame-Options and CSP frame-ancestors in security headers scan'},
                'remediation': 'Implement X-Frame-Options: DENY or SAMEORIGIN, or CSP frame-ancestors directive.'
            })
            
        except Exception as e:
            findings.append({
                'type': 'info',
                'severity': 'info',
                'title': 'Clickjacking Test Incomplete',
                'description': f'Could not complete clickjacking test: {str(e)}',
                'details': {}
            })
        
        return findings
    
    def _check_client_storage(self, target_url: str) -> List[Dict]:
        """Check for sensitive data in client-side storage."""
        findings = []
        
        try:
            self.driver.get(target_url)
            time.sleep(2)
            
            # Check localStorage
            local_storage = self.driver.execute_script("""
                var items = {};
                for (var i = 0; i < localStorage.length; i++) {
                    var key = localStorage.key(i);
                    items[key] = localStorage.getItem(key);
                }
                return items;
            """)
            
            # Check sessionStorage
            session_storage = self.driver.execute_script("""
                var items = {};
                for (var i = 0; i < sessionStorage.length; i++) {
                    var key = sessionStorage.key(i);
                    items[key] = sessionStorage.getItem(key);
                }
                return items;
            """)
            
            # Check for sensitive data patterns
            sensitive_patterns = ['password', 'token', 'secret', 'key', 'auth', 'credential', 'session']
            
            for key, value in {**local_storage, **session_storage}.items():
                lower_key = key.lower()
                for pattern in sensitive_patterns:
                    if pattern in lower_key:
                        findings.append({
                            'type': 'client_storage',
                            'severity': 'medium',
                            'title': 'Potentially Sensitive Data in Client Storage',
                            'description': f'Key "{key}" in storage may contain sensitive data',
                            'details': {
                                'storage_type': 'localStorage' if key in local_storage else 'sessionStorage',
                                'key': key,
                                'value_preview': str(value)[:50] + '...' if len(str(value)) > 50 else value
                            },
                            'remediation': 'Avoid storing sensitive data in client-side storage. Use secure, httpOnly cookies instead.'
                        })
                        break
            
            if local_storage or session_storage:
                findings.append({
                    'type': 'info',
                    'severity': 'info',
                    'title': 'Client Storage Detected',
                    'description': f'Found {len(local_storage)} localStorage and {len(session_storage)} sessionStorage items',
                    'details': {
                        'localStorage_keys': list(local_storage.keys()),
                        'sessionStorage_keys': list(session_storage.keys())
                    }
                })
            
        except Exception as e:
            findings.append({
                'type': 'info',
                'severity': 'info',
                'title': 'Client Storage Check Incomplete',
                'description': f'Could not complete client storage check: {str(e)}',
                'details': {}
            })
        
        return findings

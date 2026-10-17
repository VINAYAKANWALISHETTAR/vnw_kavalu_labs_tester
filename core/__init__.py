"""Core security scanning modules."""

__author__ = "Vinayaka N Walishettar"

from .scanner import SecurityScanner
from .vulnerability_scanner import VulnerabilityScanner
from .burp_integration import BurpIntegration
from .report_generator import ReportGenerator

try:
    from .selenium_scanner import SeleniumScanner
except ImportError:
    SeleniumScanner = None

__all__ = [
    'SecurityScanner',
    'VulnerabilityScanner',
    'BurpIntegration',
    'ReportGenerator'
]

if SeleniumScanner:
    __all__.append('SeleniumScanner')

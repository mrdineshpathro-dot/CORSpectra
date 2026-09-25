"""CORSpectra public API."""

from .models import ScanResult
from .scanner import CorsScanner

__version__ = "1.0.0"
__author__ = "Mr Dinesh Pathro"
__all__ = ["CorsScanner", "ScanResult", "__version__"]

"""
GTIC Version Information
"""

__version__ = "1.2.0"
__version_info__ = (1, 2, 0)
__sprint__ = "Sprint 27"
__release_date__ = "2026-01-09"

def get_version_info():
    """Get detailed version information"""
    return {
        "version": __version__,
        "version_info": __version_info__,
        "sprint": __sprint__,
        "release_date": __release_date__,
        "title": "Global Threat Intelligence Cache (GTIC)",
        "description": "Global Threat intelligence platform with IOC correlation and CVE tracking"
    }

def get_version_string():
    """Get formatted version string"""
    return f"GTIC v{__version__} ({__sprint__})"

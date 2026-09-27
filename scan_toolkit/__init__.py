"""scan_toolkit — local-first mobile app security assessment toolkit.

Runs deterministic scanners (Semgrep, MobSF, OSV/Grype, mitmproxy, ZAP)
against client-supplied APK/IPA binaries, normalizes the output into a
shared Finding schema, and layers LLM agents on top to correlate,
prioritize, and write reports. The LLM only explains/structures output
from the real tools; it never invents findings.
"""

__version__ = "0.1.0"
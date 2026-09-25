"""LLM agents — structured analysis of deterministic tool output.

Each agent takes IR (intermediate representation) data from the scanner
pipeline and returns structured JSON matching the Finding schema.  The LLM
never invents findings; it explains, deduplicates, and normalises output
from the real tools.
"""

from scan_toolkit.agents.api_agent import APIBackendAgent
from scan_toolkit.agents.sca import SCAAgent
from scan_toolkit.agents.static import StaticAnalysisAgent

__all__ = ["APIBackendAgent", "StaticAnalysisAgent", "SCAAgent"]

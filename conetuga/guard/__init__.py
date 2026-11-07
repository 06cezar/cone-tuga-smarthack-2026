"""Stream C: scope guardrail, live scan, MAC masking, CSV export.

The calls other streams use are `detect_network` and `check_scope` (contracts in specs/contracts.md)."""
from conetuga.guard.network import Network, NetworkNotFound, detect_network, wifi_ssid
from conetuga.guard.scope import HOTSPOT_SSID, ScopeDecision, check_scope

__all__ = ["HOTSPOT_SSID", "Network", "NetworkNotFound", "ScopeDecision", "check_scope", "detect_network",
           "wifi_ssid"]

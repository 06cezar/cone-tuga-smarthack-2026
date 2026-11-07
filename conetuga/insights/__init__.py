"""Stream A: local, opt-in statistics of the most common problems (contract "insights" in specs/contracts.md)."""
from conetuga.insights.store import (STATUS_OFF, STATUS_ON, STATUS_UNAVAILABLE, is_enabled, record, set_enabled,
                                     status, top_codes)

__all__ = ["STATUS_OFF", "STATUS_ON", "STATUS_UNAVAILABLE", "is_enabled", "record", "set_enabled", "status",
           "top_codes"]

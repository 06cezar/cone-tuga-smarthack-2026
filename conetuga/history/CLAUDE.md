# Rules for conetuga/history (stream D: scan history and before/after)

- History is stored only on this computer, in `.history/` (gitignored): one record per analysed scan, with masked MACs.
- The diff between two scans lists new and removed devices, opened and closed ports, resolved findings and the score
  trend (FR-10). A new device or a newly opened port is flagged as a change alert (FR-13).
- A device is the same device across scans when its IP and hostname match; never match by MAC. In the Validation Set,
  V6a and V6b show the same router and laptop (same IP and hostname) with different MACs.
- "Delete my history" removes everything in one action, with nothing left behind (NFR-02).

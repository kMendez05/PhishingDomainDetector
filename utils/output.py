# utils/output.py
from __future__ import annotations
from typing import List, Dict, Any

from rich.console import Console
from rich.table import Table
from rich.text import Text

console = Console()

STATUS_STYLE = {
    "Phishing": "bold red",
    "Suspicious": "yellow",
    "Safe": "green",
}

def print_domains_table(rows: List[Dict[str, Any]], verbose: bool = False) -> None:
    """
    Print results in a colored table.
    - verbose=False: truncates long reasons
    - verbose=True: shows full reasons
    """
    table = Table(title="Phishing Domain Detector Results", show_lines=False)
    table.add_column("Domain", style="bold", no_wrap=True)
    table.add_column("Status")
    table.add_column("Risk", justify="right")
    table.add_column("Reason", ratio=2)

    for r in rows:
        domain = str(r.get("domain", ""))
        status = str(r.get("status", ""))
        styled_status = Text(status, style=STATUS_STYLE.get(status, ""))
        risk = str(r.get("risk_score", ""))
        reason = r.get("reason", "") or ""
        if not verbose and len(reason) > 80:
            reason = reason[:77] + "..."
        table.add_row(domain, styled_status, risk, reason)

    console.print(table)
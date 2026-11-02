"""
Visualizer and Terminal Formatter.
Uses Rich to produce clear, structured, readable terminal output for each phase
of the Web Cache Poisoning simulation, detailing request headers, cache keys,
response reflection, and CVSS impact analysis.
Compatible across Windows, Linux, and macOS.
"""

import sys

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from typing import Optional

console = Console(legacy_windows=False)


def print_banner() -> None:
    banner_text = Text()
    banner_text.append("[*] WEB CACHE POISONING ATTACK SIMULATION FRAMEWORK [*]\n", style="bold red")
    banner_text.append("High-Severity Scenario: Unkeyed Header Injection & Cache Desynchronization\n", style="bold yellow")
    banner_text.append("Educational & Verification Testing Engine | Enterprise Defense Blueprint", style="cyan")

    console.print(Panel(banner_text, border_style="red", expand=False))


def print_scenario_briefing() -> None:
    briefing = """
[bold yellow]OPERATIONAL SCENARIO CASE FILE: OPERATION CANARY POISON[/bold yellow]

* [bold cyan]Target Organization:[/bold cyan] Apex Global Financial (Enterprise Banking & Trading)
* [bold cyan]Target Asset:[/bold cyan] Authenticated Banking Dashboard Homepage (/) on Port 8880
* [bold cyan]Traffic Profile:[/bold cyan] 65,000 active sessions/min during market open
* [bold cyan]Architecture:[/bold cyan] Edge Caching Proxy (Port 8880) fronting Cluster Upstream (Port 8881)
* [bold cyan]The Vulnerability:[/bold cyan]
  - Caching Policy: TTL=30s, Cache Key = METHOD + Host + Path
  - Backend Flaw: Dynamically derives <script src="..."> from unkeyed X-Forwarded-Host
  - Edge Flaw: Proxy ignores X-Forwarded-Host in key calculation, but forwards it upstream
* [bold cyan]Threat Actor:[/bold cyan] Mallory (FIN-7 Cybercrime Syndicate)
* [bold cyan]Objective:[/bold cyan] Mass session token hijacking across thousands of traders via a single cached request
    """
    console.print(Panel(briefing.strip(), title="Mission Briefing & Scenario Setup", border_style="yellow"))


def print_architecture() -> None:
    arch = """
[bold cyan]Target Architecture & Data Flow:[/bold cyan]

   [green]Client / Victim / Attacker[/green]
             |
             | HTTP Request (Port 8880)
             v
   +----------------------------------------+
   |        [bold yellow]Edge Caching Proxy[/bold yellow]             |
   |  * Key: METHOD + Host + Path           |
   |  * Unkeyed: X-Forwarded-Host (Ignored) |
   +------------------+---------------------+
                      | Cache Miss: Forward (Port 8881)
                      v
   +----------------------------------------+
   |         [bold blue]Upstream Web Server[/bold blue]            |
   |  * Renders dynamic script import       |
   |  * Reads untrusted X-Forwarded-Host    |
   +----------------------------------------+
                      ^
                      | (Victim loads asset)
   +------------------+---------------------+
   |       [bold red]Attacker Host (Port 8882)[/bold red]        |
   |  * Serves Hostile Verification Canary  |
   +----------------------------------------+
    """
    console.print(Panel(arch.strip(), title="Architecture Flow", border_style="blue"))


def print_phase_header(phase_num: int, title: str, description: str) -> None:
    phase_text = Text()
    phase_text.append(f"PHASE {phase_num}: {title}\n", style="bold green" if phase_num == 4 else "bold yellow")
    phase_text.append(f"Context: {description}", style="italic white")
    console.print()
    console.print(Panel(phase_text, border_style="bright_blue"))


def print_transaction(
    actor: str,
    method: str,
    url: str,
    headers: dict,
    cache_status: str,
    cache_key: str,
    status_code: int,
    script_source: str,
    verdict: str,
    csp_header: Optional[str] = None,
) -> None:
    table = Table(show_header=True, header_style="bold magenta", expand=True)
    table.add_column("Property", style="bold cyan", width=22)
    table.add_column("Details", style="white")

    # Format actor styling
    actor_style = "bold green" if "Alice" in actor or "Legitimate" in actor else "bold red" if "Attacker" in actor else "bold yellow"
    table.add_row("Client / Actor", f"[{actor_style}]{actor}[/{actor_style}]")
    table.add_row("Request", f"[bold white]{method} {url}[/bold white]")

    # Request headers
    hdr_str = ", ".join(f"[bold yellow]{k}[/bold yellow]: [white]{v}[/white]" for k, v in headers.items()) if headers else "[dim]Default standard headers only[/dim]"
    table.add_row("Sent Headers", hdr_str)

    # Cache Proxy Evaluation
    cache_color = "bold green" if cache_status == "HIT" else "bold yellow"
    table.add_row("Cache State", f"[{cache_color}]{cache_status}[/{cache_color}]")
    table.add_row("Computed Cache Key", f"[cyan]{cache_key}[/cyan]")
    table.add_row("Upstream Status", f"[bold green]{status_code} OK[/bold green]")

    # Script tag analysis
    if "8882" in script_source or "attacker" in script_source.lower():
        script_display = f"[bold red]{script_source} [POISONED][/bold red]"
    else:
        script_display = f"[bold green]{script_source} [LEGITIMATE][/bold green]"
    table.add_row("Resolved <script src>", script_display)

    if csp_header:
        table.add_row("Content-Security-Policy", f"[bold cyan]{csp_header}[/bold cyan]")

    verdict_color = "bold green" if "SAFE" in verdict or "PREVENTED" in verdict or "BLOCKED" in verdict else "bold red"
    table.add_row("Security Evaluation", f"[{verdict_color}]{verdict}[/{verdict_color}]")

    console.print(table)


def print_cvss_assessment() -> None:
    title = "[bold red]VULNERABILITY ASSESSMENT & THREAT METRICS[/bold red]"
    cvss_text = """
[bold]Vulnerability Classification:[/bold]
* CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling / Poisoning')
* CWE-79: Improper Neutralization of Input During Web Page Generation ('Stored Cross-Site Scripting')
* CWE-610: Externally Controlled Reference to a Resource in Another Sphere

[bold]CVSS v3.1 Base Score: [red]8.6 (HIGH / CRITICAL)[/red][/bold]
* Vector: [bold cyan]CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N[/bold cyan]
  - [bold]Attack Vector (AV):[/bold] Network (Remotely exploitable without physical/local access)
  - [bold]Attack Complexity (AC):[/bold] Low (Requires single unkeyed HTTP header injection)
  - [bold]Privileges Required (PR):[/bold] None (Unauthenticated public attacker)
  - [bold]User Interaction (UI):[/bold] Required (Victims simply browse legitimate homepage)
  - [bold]Scope (S):[/bold] Changed (Edge cache compromise directly impacts downstream browser security domains)
  - [bold]Confidentiality (C):[/bold] High (Session tokens, PII, DOM exfiltration via script injection)
  - [bold]Integrity (I):[/bold] High (Arbitrary client-side script execution on behalf of authenticated users)

[bold]Real-World Blast Radius:[/bold]
Any visitor requesting the targeted URL receives the poisoned response from the edge cache
until TTL expiration. A single crafted request can compromise hundreds of thousands of users.
    """
    console.print(Panel(cvss_text.strip(), title=title, border_style="red"))

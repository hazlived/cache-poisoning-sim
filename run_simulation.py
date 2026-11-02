"""
Main Entry Point for the Web Cache Poisoning Attack Simulation.
Launches and orchestrates the complete scenario, rendering visual telemetry
and impact analysis in the terminal.
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

import time
from config import SimulationConfig
from sim import visualizer
from sim.scenarios import SimulationScenarioRunner


def main() -> int:
    config = SimulationConfig()
    runner = SimulationScenarioRunner(config)

    visualizer.print_banner()
    visualizer.print_scenario_briefing()
    visualizer.print_architecture()

    try:
        visualizer.console.print("[bold yellow][*] Initializing local simulation infrastructure...[/bold yellow]")
        runner.start_servers(upstream_mode="vulnerable", proxy_strip_headers=False)
        visualizer.console.print(f"[bold green][OK] Edge Cache Proxy running on {config.cache_proxy_url}[/bold green]")
        visualizer.console.print(f"[bold green][OK] Upstream Application running on {config.upstream_url}[/bold green]")
        visualizer.console.print(f"[bold green][OK] Mock Attacker Origin running on {config.attacker_origin_url}[/bold green]")
        time.sleep(0.5)

        # Run Phase 1: Baseline
        runner.run_phase_1_baseline()
        time.sleep(1.0)

        # Run Phase 2: Poisoning
        runner.run_phase_2_poisoning()
        time.sleep(1.0)

        # Run Phase 3: Impact on Innocent Users
        impact_results = runner.run_phase_3_impact()
        time.sleep(1.0)

        # Run Phase 4: Remediation & Hardening
        runner.run_phase_4_remediation()
        time.sleep(0.5)

        visualizer.console.print()
        visualizer.console.print("[bold green]=========================================================================[/bold green]")
        visualizer.console.print("[bold green]          SIMULATION & HARDENING PROOF COMPLETED SUCCESSFULLY            [/bold green]")
        visualizer.console.print("[bold green]=========================================================================[/bold green]")
        visualizer.console.print("[cyan]Key Takeaway:[/cyan] Unkeyed inputs allow attackers to desynchronize cached content from expected origin behavior. Defense requires edge-level header filtering, strict canonical asset resolution, and defense-in-depth CSP.")

        return 0

    except KeyboardInterrupt:
        visualizer.console.print("\n[yellow][!] Simulation interrupted by user.[/yellow]")
        return 1
    except Exception as e:
        visualizer.console.print(f"\n[red][!] Error during simulation: {e}[/red]")
        import traceback
        traceback.print_exc()
        return 2
    finally:
        visualizer.console.print("[dim][*] Tearing down background simulation servers...[/dim]")
        runner.stop_servers()
        visualizer.console.print("[dim][OK] Clean shutdown complete.[/dim]")


if __name__ == "__main__":
    sys.exit(main())

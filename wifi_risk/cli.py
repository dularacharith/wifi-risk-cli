from typing import Any, Optional
import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.prompt import Confirm, Prompt
from rich.table import Table

from wifi_risk.services.assessment_service import (
    classify_assessment_type,
    clear_all_assessments,
    create_assessment,
    delete_assessment_by_id,
    delete_assessments_by_ids,
    get_all_assessments,
    get_assessment_by_id,
    get_assessments_by_category,
    update_assessment,
)
from wifi_risk.services.cwe_intelligence_service import (
    extract_cwes_from_items,
    load_cwe_catalog,
    normalize_cwe_id,
    query_cwe_intelligence,
    search_cwe_catalog,
    sync_all_catalog_cwes,
)
from wifi_risk.services.device_service import get_all_devices, get_device_by_id
from wifi_risk.services.dns_service import perform_dns_checks
from wifi_risk.services.finding_service import (
    count_findings_by_severity,
    get_all_findings,
    get_findings_by_assessment_id,
    get_findings_by_device_id,
)
from wifi_risk.services.firmware_service import (
    perform_firmware_discovery,
    perform_firmware_static_analysis,
    perform_online_firmware_discovery,
)
from wifi_risk.services.network_service import perform_network_discovery
from wifi_risk.services.quick_scan_service import run_standalone_quick_scan
from wifi_risk.services.report_service import (
    export_assessment_report,
    export_research_test_dataset,
    generate_research_audit_log,
    generate_research_dataset_txt,
)
from wifi_risk.services.runner_service import run_full_safe_assessment
from wifi_risk.services.scoring_service import evaluate_device_security
from wifi_risk.services.web_service import perform_web_checks
from wifi_risk.utils.network_detector import (
    detect_default_gateway,
    list_all_interfaces,
)

app = typer.Typer(
    help="WiFiRisk - Low-Cost Wi-Fi Repeater Security Assessment CLI Framework",
    no_args_is_help=False,
    invoke_without_command=True,
)
console = Console()

ASCII_ART = r"""
__        ___ _____ ___   ____  ___ ____  _  __
\ \      / (_)  ___|_ _| |  _ \|_ _/ ___|| |/ /
 \ \ /\ / /| | |_   | |  | |_) || |\___ \| ' /
  \ V  V / | |  _|  | |  |  _ < | | ___) | . \
   \_/\_/  |_|_|   |___| |_| \_\___|____/|_|\_\
"""


def clear_screen() -> None:
    console.clear()


def show_banner() -> None:
    console.print(ASCII_ART, style="bold cyan")
    console.print(
        Panel(
            "[bold white]WiFiRisk - Security Assessment & Risk Benchmarking CLI Framework[/bold white]\n"
            "[dim]A research toolkit for evaluating low-cost Wi-Fi repeaters[/dim]",
            border_style="cyan",
        )
    )


def is_back(user_input: str) -> bool:
    clean = user_input.strip().lower()
    return clean in ["b", "back", "0"]


def pause(prompt_text: str = "\n[bold cyan]Press Enter to return...[/bold cyan]") -> None:
    Prompt.ask(prompt_text, default="", show_default=False, show_choices=False)


def prompt_select_target_ip(default_fallback: str = "192.168.11.1") -> tuple[Optional[str], str]:
    interfaces = list_all_interfaces()
    if not interfaces:
        ip = Prompt.ask("[bold]Target Gateway IP (or 'b' to go back)[/bold]", default=default_fallback).strip()
        if is_back(ip):
            return None, "Manual"
        return ip, "Manual"

    console.print("\n[bold cyan]Detected Network Interfaces & Gateways:[/bold cyan]")
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("#", justify="center", style="cyan", no_wrap=True)
    table.add_column("Interface Name")
    table.add_column("Local IP")
    table.add_column("Target Gateway IP")
    table.add_column("Status", justify="center")

    default_choice = "1"
    for idx, iface in enumerate(interfaces, start=1):
        is_def = iface.get("is_default", False)
        status_tag = "[bold green]Default Route[/bold green]" if is_def else "[white]Active[/white]"
        if is_def:
            default_choice = str(idx)
        table.add_row(
            str(idx),
            iface.get("name", "Unknown"),
            iface.get("local_ip", "N/A"),
            iface.get("gateway_ip", "N/A"),
            status_tag,
        )

    console.print(table)
    range_desc = f"1-{len(interfaces)}" if len(interfaces) > 1 else "1"
    console.print("\n[bold]Options:[/bold]")
    console.print(f"  [bold cyan]{range_desc:<4}[/bold cyan] : Select interface and target gateway from table")
    console.print(f"  [bold cyan]{'IP':<4}[/bold cyan] : Enter custom target gateway IP address directly")
    console.print(f"  [bold cyan]{'B':<4}[/bold cyan] : Return to previous menu")

    choice = Prompt.ask(
        "\n[bold green]Select an option[/bold green]",
        default=default_choice,
        show_default=False,
    ).strip()

    if is_back(choice):
        return None, "Cancelled"

    try:
        idx_val = int(choice)
        if 1 <= idx_val <= len(interfaces):
            chosen_iface = interfaces[idx_val - 1]
            return chosen_iface["gateway_ip"], chosen_iface["name"]
    except ValueError:
        pass

    return choice, "Custom Input"


def get_default_interface_gateway(default_fallback: str = "192.168.11.1") -> tuple[str, str]:
    interfaces = list_all_interfaces()
    if not interfaces:
        detected_gw = detect_default_gateway()
        return detected_gw or default_fallback, "Auto-Detected"

    primary = next((i for i in interfaces if i.get("is_default")), interfaces[0]) if interfaces else None
    if primary:
        return primary["gateway_ip"], primary["name"]
    return default_fallback, "Default Gateway"


def show_main_menu() -> None:
    table = Table(title="WiFiRisk Main Menu", show_header=True, header_style="bold cyan")
    table.add_column("Option", justify="center", style="cyan", no_wrap=True)
    table.add_column("Action")

    table.add_row("1", "Quick Vulnerability Check (Live Target / Minimal Prompts)")
    table.add_row("2", "Full In-Depth Assessment (Multi-Layer Automated Pipeline)")
    table.add_row("3", "Standalone Assessment Modules (Create Session, Ports, DNS, Web, Firmware)")
    table.add_row("4", "View & Manage Assessments (All / Quick / Full / Created / Export & Clear)")
    table.add_row("5", "Security Scorecard & Findings (Knowledge Grid & PSR Calculations)")
    table.add_row("6", "Device Catalog & Benchmarking (Catalog, Search, Compare & Recommendations)")
    table.add_row("7", "MITRE CWE Threat Intelligence (Live Online Knowledge & Taxonomy)")
    table.add_row("8", "Network Tools & Documentation (Interfaces, Gateway Detector & Guide)")
    table.add_row("0", "Exit")

    console.print(table)


def render_finding_detail(finding: dict[str, Any], index: int | None = None) -> None:
    """
    Render a comprehensive, structured panel for a single security finding including threat modeling.
    """
    sev = finding.get("severity", "Medium")
    sev_lower = sev.lower()
    b_color = "red" if sev_lower in ["critical", "high"] else "yellow" if "medium" in sev_lower else "green"

    idx_prefix = f"#{index} - " if index is not None else ""
    title_text = f"[{b_color}][bold]{idx_prefix}{finding.get('id', '')}: {finding.get('title', '')}[/bold][/{b_color}]"

    cwe_text = finding.get("cwe", "").strip() or "CWE-General / Insecure Device Configuration"
    threat_text = finding.get("threat_scenario", "").strip() or "An attacker on the local or upstream network can exploit this weakness to intercept traffic or attempt unauthorized access."
    evidence_text = finding.get("evidence", "").strip() or "Observed during live device security assessment."
    impact_text = finding.get("impact", "").strip() or "May allow unauthorized network access or sensitive data leakage."
    rec_text = finding.get("recommendation", "").strip() or "Apply security hardening and update device configuration."
    hardening_text = finding.get("hardening_coverage", "").strip()

    content = f"""
[bold]Vulnerability Title:[/bold] {finding.get('title', '')}
[bold]Severity Tier:[/bold]       [{b_color}]{sev}[/{b_color}]
[bold]Weakness Mapping:[/bold]    {cwe_text}
[bold]Category:[/bold]            {finding.get('category', 'General Security')}
[bold]Assessment Module:[/bold]   {finding.get('module', 'Assessment Engine')}
[bold]Verification Status:[/bold] {finding.get('status', 'Confirmed')}

[bold magenta]Threat Modeling & Attack Scenarios:[/bold magenta]
{threat_text}

[bold cyan]Technical Evidence & Probed Data:[/bold cyan]
{evidence_text}

[bold red]Security Impact & Vulnerability Consequences:[/bold red]
{impact_text}

[bold green]Remediation & Mitigation Guidance:[/bold green]
{rec_text}
"""
    if hardening_text:
        content += f"""
[bold yellow]Manufacturer & Consumer Hardening Plan:[/bold yellow]
{hardening_text}
"""

    console.print(Panel(content.strip(), title=title_text, border_style=b_color))


def render_quick_alert_detail(alert: dict[str, Any], index: int | None = None) -> None:
    """
    Render a structured, informative panel for a quick scan vulnerability alert including threat modeling.
    """
    lvl = alert.get("level", "Medium")
    lvl_lower = lvl.lower()
    b_color = "red" if lvl_lower in ["critical", "high"] else "yellow" if "medium" in lvl_lower else "cyan"

    idx_prefix = f"#{index} - " if index is not None else ""
    title_text = f"[{b_color}][bold]{idx_prefix}{alert.get('title', '')}[/bold][/{b_color}]"

    cwe_text = alert.get("cwe", "CWE-General Network Weakness")
    threat_text = alert.get("threat_scenario", "An attacker on the shared network can probe this service to attempt eavesdropping or unauthenticated access.")
    hardening_text = alert.get("hardening_coverage", "")

    content = f"""
[bold]Vulnerability Title:[/bold] {alert.get('title', '')}
[bold]Severity Tier:[/bold]       [{b_color}]{lvl.upper()}[/{b_color}]
[bold]Weakness Mapping:[/bold]    {cwe_text}
[bold]Category:[/bold]            {alert.get('category', 'Network / Service Exposure')}
[bold]Verification Status:[/bold] {alert.get('status', 'Confirmed Exposure')}

[bold magenta]Threat Modeling & Attack Scenarios:[/bold magenta]
{threat_text}

[bold cyan]Technical Evidence & Probed Data:[/bold cyan]
{alert.get('evidence', 'Observed during live network triage scan.')}

[bold red]Security Impact & Vulnerability Consequences:[/bold red]
{alert.get('impact', 'Potential exposure to unauthorized interception or brute-force access.')}

[bold green]Remediation & Mitigation Guidance:[/bold green]
{alert.get('recommendation', 'Disable this exposed service or enforce cryptographic authentication.')}
"""
    if hardening_text:
        content += f"""
[bold yellow]Manufacturer & Consumer Hardening Plan:[/bold yellow]
{hardening_text}
"""

    console.print(Panel(content.strip(), title=title_text, border_style=b_color))


def explore_quick_scan_alerts(alerts: list[dict[str, Any]]) -> None:
    """
    Interactive loop allowing users to drill down into specific vulnerabilities.
    """
    if not alerts:
        return

    while True:
        console.print("\n[bold cyan]Discovered Vulnerabilities:[/bold cyan]")
        for idx, a in enumerate(alerts, 1):
            lvl = a.get("level", "Medium")
            lvl_color = "red" if lvl.lower() == "high" else "yellow" if lvl.lower() == "medium" else "cyan"
            console.print(f"  [bold cyan]{idx}.[/bold cyan] [{lvl_color}][{lvl}][/{lvl_color}] {a.get('title', '')}")

        range_desc = f"1-{len(alerts)}" if len(alerts) > 1 else "1"
        console.print("\n[bold]Options:[/bold]")
        console.print(f"  [bold cyan]{range_desc:<4}[/bold cyan] : View technical details for a specific vulnerability")
        console.print(f"  [bold cyan]{'A':<4}[/bold cyan] : View complete breakdown of all discovered vulnerabilities")
        console.print(f"  [bold cyan]{'Q':<4}[/bold cyan] : Query MITRE CWE threat intelligence for these alerts")
        console.print(f"  [bold cyan]{'0':<4}[/bold cyan] : Return to previous menu")

        choice = Prompt.ask(
            "\n[bold green]Select an option[/bold green]",
            default="0",
            show_default=False,
        ).strip()

        if choice in ["0", "b", "B", "", "quit", "exit"]:
            break
        elif choice.upper() == "Q":
            prompt_cwe_query_for_findings(alerts)
        elif choice.upper() == "A":
            clear_screen()
            show_banner()
            console.print(f"[bold cyan]--- Complete Vulnerability Detail Breakdown ({len(alerts)} items) ---[/bold cyan]\n")
            for idx, a in enumerate(alerts, 1):
                render_quick_alert_detail(a, index=idx)
            Prompt.ask("\n[bold cyan]Press Enter to return to options[/bold cyan]", default="")
        else:
            try:
                selected_idx = int(choice) - 1
                if 0 <= selected_idx < len(alerts):
                    clear_screen()
                    show_banner()
                    render_quick_alert_detail(alerts[selected_idx], index=selected_idx + 1)
                    Prompt.ask("\n[bold cyan]Press Enter to return to options[/bold cyan]", default="")
                else:
                    console.print(f"[red]Invalid choice. Enter 1 to {len(alerts)}, 'A', 'Q' or '0'.[/red]")
            except ValueError:
                console.print(f"[red]Invalid choice. Enter 1 to {len(alerts)}, 'A', 'Q' or '0'.[/red]")


def explore_full_assessment_findings(findings: list[dict[str, Any]]) -> None:
    """
    Interactive loop allowing users to explore full assessment findings in full detail.
    """
    if not findings:
        return

    while True:
        console.print("\n[bold cyan]Discovered Security Findings:[/bold cyan]")
        for idx, f in enumerate(findings, 1):
            sev = f.get("severity", "Medium")
            sev_color = "red" if sev.lower() in ["critical", "high"] else "yellow" if "medium" in sev.lower() else "green"
            console.print(f"  [bold cyan]{idx}.[/bold cyan] [{sev_color}][{sev}][/{sev_color}] [bold]{f.get('id', '')}:[/bold] {f.get('title', '')}")

        range_desc = f"1-{len(findings)}" if len(findings) > 1 else "1"
        console.print("\n[bold]Options:[/bold]")
        console.print(f"  [bold cyan]{range_desc:<4}[/bold cyan] : View technical details for a specific finding")
        console.print(f"  [bold cyan]{'A':<4}[/bold cyan] : View complete breakdown of all discovered findings")
        console.print(f"  [bold cyan]{'Q':<4}[/bold cyan] : Query MITRE CWE threat intelligence for these findings")
        console.print(f"  [bold cyan]{'0':<4}[/bold cyan] : Return to previous menu")

        choice = Prompt.ask(
            "\n[bold green]Select an option[/bold green]",
            default="0",
            show_default=False,
        ).strip()

        if choice in ["0", "b", "B", "", "quit", "exit"]:
            break
        elif choice.upper() == "Q":
            prompt_cwe_query_for_findings(findings)
        elif choice.upper() == "A":
            clear_screen()
            show_banner()
            console.print(f"[bold cyan]--- Complete Vulnerability Findings Breakdown ({len(findings)} items) ---[/bold cyan]\n")
            for idx, f in enumerate(findings, 1):
                render_finding_detail(f, index=idx)
            Prompt.ask("\n[bold cyan]Press Enter to return to options[/bold cyan]", default="")
        else:
            try:
                selected_idx = int(choice) - 1
                if 0 <= selected_idx < len(findings):
                    clear_screen()
                    show_banner()
                    render_finding_detail(findings[selected_idx], index=selected_idx + 1)
                    Prompt.ask("\n[bold cyan]Press Enter to return to options[/bold cyan]", default="")
                else:
                    console.print(f"[red]Invalid choice. Enter 1 to {len(findings)}, 'A', 'Q' or '0'.[/red]")
            except ValueError:
                console.print(f"[red]Invalid choice. Enter 1 to {len(findings)}, 'A', 'Q' or '0'.[/red]")


def run_quick_vulnerability_check_screen() -> None:
    """
    Fast, standalone live security check that inspects target ports, DNS and web services
    without creating assessment database sessions or calculating complex price metrics.
    """
    while True:
        clear_screen()
        show_banner()
        console.print("[bold cyan]--- Quick Live Vulnerability Check ---[/bold cyan]\n")
        console.print("Direct network scan for open ports, unencrypted services and live security exposures.\n")

        target_ip, iface_name = prompt_select_target_ip(default_fallback="192.168.11.1")
        if target_ip is None:
            console.print("[yellow]Returning to main menu...[/yellow]")
            return

        console.print(f"\n[bold cyan]Starting Live Quick Scan on target {target_ip} ({iface_name})...[/bold cyan]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=None),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[bold cyan]Initializing Quick Scan...", total=100)

            def on_quick_progress(percent: int, message: str) -> None:
                progress.update(task, completed=percent, description=f"[bold cyan]{message}")

            results = run_standalone_quick_scan(target_ip=target_ip, progress_callback=on_quick_progress)
            progress.update(task, completed=100, description="[bold green]Quick vulnerability check completed!")

        open_ports = results.get("open_ports", [])
        alerts = results.get("alerts", [])
        status_text = results.get("overall_status", "Clean")
        status_color = results.get("status_color", "green")

        console.print(f"\n[bold green]Scan Completed for {target_ip} (via {results['scan_method']})![/bold green]\n")

        # 1. Open Ports & Services Table
        if open_ports:
            port_table = Table(title=f"Discovered Ports & Services ({target_ip})", show_header=True, header_style="bold cyan")
            port_table.add_column("Port", justify="right", style="cyan")
            port_table.add_column("Protocol", justify="center")
            port_table.add_column("State", justify="center")
            port_table.add_column("Service")
            port_table.add_column("Version / Banner")

            for p in open_ports:
                port_table.add_row(
                    str(p.get("port")),
                    p.get("protocol", "tcp"),
                    "[green]open[/green]",
                    p.get("service", "unknown"),
                    p.get("banner", "-") or "-",
                )
            console.print(port_table)
        else:
            console.print("[yellow]No common management ports (FTP, SSH, Telnet, DNS, HTTP) were found open.[/yellow]")

        # 2. Service Details
        console.print("\n[bold cyan]Service Probing Summary:[/bold cyan]")
        console.print(f"  - [bold]DNS Service (Port 53):[/bold]  {results['dns_status']}")
        console.print(f"  - [bold]Web Service (Port 80):[/bold]  {results['web_status']}")
        if results.get("web_details", {}).get("title"):
            console.print(f"    [dim]Web Page Title: {results['web_details']['title']}[/dim]")

        # 3. Vulnerability Alerts Summary
        if alerts:
            console.print(f"\n[bold red]Security Vulnerabilities & Exposure Alerts ({len(alerts)}):[/bold red]")
            for idx, alert in enumerate(alerts, 1):
                lvl = alert["level"].lower()
                b_color = "red" if lvl == "high" else "yellow" if lvl == "medium" else "cyan"
                console.print(
                    Panel(
                        f"[bold]{alert['description']}[/bold]",
                        title=f"[{b_color}]#{idx} - {alert['level'].upper()}: {alert['title']}[/{b_color}]",
                        border_style=b_color,
                    )
                )
        else:
            console.print("\n[bold green]No critical or high security vulnerabilities detected on the target interface.[/bold green]")

        # 4. Standalone Posture Verdict
        summary_box = f"""
[bold]Target Gateway:[/bold]     {target_ip} ({iface_name})
[bold]Scan Timestamp:[/bold]     {results['scan_time']}
[bold]Open Ports Count:[/bold]   {len(open_ports)}
[bold]Security Alerts:[/bold]    {len(alerts)}

[bold]Overall Posture:[/bold]
[{status_color}][bold]{status_text}[/bold][/{status_color}]
"""
        console.print(Panel(summary_box.strip(), title="Quick Scan Verdict", border_style=status_color))

        repeat_quick = False
        while True:
            console.print("\n[bold cyan]Post-Scan Actions:[/bold cyan]")
            if alerts:
                console.print("1. Run Another Quick Scan")
                console.print("2. Explore Discovered Vulnerabilities in Detail")
                console.print("3. Query MITRE CWE Threat Intelligence for Discovered Alerts")
                console.print("0. Return to Main Menu")

                next_choice = Prompt.ask(
                    "\n[bold green]Select an option[/bold green]",
                    choices=["0", "1", "2", "3", "b", "B", ""],
                    default="0",
                    show_default=False,
                    show_choices=False,
                ).strip()

                if next_choice == "1":
                    repeat_quick = True
                    break
                elif next_choice == "2":
                    explore_quick_scan_alerts(alerts)
                elif next_choice == "3":
                    prompt_cwe_query_for_findings(alerts)
                else:
                    break
            else:
                console.print("1. Run Another Quick Scan")
                console.print("0. Return to Main Menu")

                next_choice = Prompt.ask(
                    "\n[bold green]Select an option[/bold green]",
                    choices=["0", "1", "b", "B", ""],
                    default="0",
                    show_default=False,
                    show_choices=False,
                ).strip()

                if next_choice == "1":
                    repeat_quick = True
                    break
                else:
                    break

        if not repeat_quick:
            break


def run_full_assessment_screen() -> None:
    while True:
        clear_screen()
        show_banner()
        console.print("[bold cyan]--- In-Depth Comprehensive Security Assessment ---[/bold cyan]\n")

        target_ip, iface_name = prompt_select_target_ip(default_fallback="192.168.11.1")
        if target_ip is None:
            return

        default_device_name = f"Target-{target_ip}"
        device_id = Prompt.ask("[bold]Device ID (or 'b' to go back)[/bold]", default=default_device_name, show_default=False).strip()
        if is_back(device_id):
            return

        price_input = Prompt.ask("[bold]Purchase Price in LKR (Optional, or 'b' to go back)[/bold]", default="").strip()
        if is_back(price_input):
            return
        try:
            price_lkr = int(price_input) if price_input else 0
        except ValueError:
            price_lkr = 0

        setup_domain = Prompt.ask("[bold]Setup Domain (Optional, or 'b' to go back)[/bold]", default="").strip()
        if is_back(setup_domain):
            return

        brand = Prompt.ask("[bold]Brand (Optional, or 'b' to go back)[/bold]", default="").strip()
        if is_back(brand):
            return

        model = Prompt.ask("[bold]Model (Optional, or 'b' to go back)[/bold]", default="").strip()
        if is_back(model):
            return

        firmware_version = Prompt.ask("[bold]Firmware Version (Optional, or 'b' to go back)[/bold]", default="").strip()
        if is_back(firmware_version):
            return

        fw_file_prompt = Prompt.ask(
            "[bold]Path to Firmware Binary file for static analysis (Optional, or 'b' to go back)[/bold]",
            default="",
        ).strip()
        if is_back(fw_file_prompt):
            return
        firmware_file_path = fw_file_prompt if fw_file_prompt else None

        notes = Prompt.ask("[bold]Assessment Notes (or 'b' to go back)[/bold]", default=f"Session via {iface_name}", show_default=False).strip()
        if is_back(notes):
            return

        console.print(f"\n[bold cyan]Initiating full assessment pipeline on {target_ip}...[/bold cyan]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=None),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[bold cyan]Executing Comprehensive Assessment Pipeline...", total=100)

            def on_full_prog(percent: int, msg: str) -> None:
                progress.update(task, completed=percent, description=f"[bold cyan]{msg}")

            results = run_full_safe_assessment(
                target_ip=target_ip,
                device_id=device_id,
                price_lkr=price_lkr,
                setup_domain=setup_domain,
                brand=brand,
                model=model,
                firmware_version=firmware_version,
                firmware_file_path=firmware_file_path,
                notes=notes,
                progress_callback=on_full_prog,
            )
            progress.update(task, completed=100, description="[bold green]Assessment Pipeline Completed!")

        eval_data = results.get("evaluation", {})
        score = eval_data.get("final_score", 100)
        risk = eval_data.get("risk_level", "Low")
        psr = eval_data.get("psr", 0.0)
        rec = eval_data.get("recommendation", {})
        findings = results.get("findings") or results.get("all_findings") or []
        severity_counts = eval_data.get("severity_counts", {})

        status_color = "red" if risk in ["Critical", "High"] else "yellow" if risk == "Medium" else "green"

        summary_box = f"""
[bold]Assessment Session ID:[/bold]  {results.get('assessment_id', '')}
[bold]Device Identifier:[/bold]      {device_id}
[bold]Target Gateway:[/bold]          {target_ip} ({iface_name})
[bold]Purchase Price:[/bold]          LKR {eval_data.get('price_lkr', price_lkr)}
[bold]Total Findings:[/bold]          {len(findings)} ({severity_counts.get('High', 0)} High, {severity_counts.get('Medium', 0)} Medium, {severity_counts.get('Low-Medium', 0)} Low-Med)

[bold]Base Security Score:[/bold]     {eval_data.get('base_score', 100)}/100
[bold]Deductions Applied:[/bold]      -{eval_data.get('total_deductions', 0)} points
[bold]Final Security Score:[/bold]    [{status_color}]{score}/100[/{status_color}]
[bold]Overall Risk Level:[/bold]      [{status_color}]{risk}[/{status_color}]
[bold]Price-to-Security (PSR):[/bold] {psr} (Baseline: LKR 15,000)

[bold]Recommendation Category:[/bold]
[bold {status_color}]{rec['category']}[/bold {status_color}]

[bold]Summary Guidance:[/bold]
{rec['guidance']}
"""
        console.print(Panel(summary_box.strip(), title=f"Full Assessment Verdict: {results['assessment_id']}", border_style=status_color))

        if findings:
            table = Table(title=f"Discovered Findings ({len(findings)} total)", show_header=True, header_style="bold cyan")
            table.add_column("Finding ID", style="cyan", no_wrap=True)
            table.add_column("Severity Tier", justify="center")
            table.add_column("Module")
            table.add_column("Title")

            for f in findings:
                table.add_row(
                    f.get("id", ""),
                    f.get("severity", ""),
                    f.get("module", ""),
                    f.get("title", ""),
                )
            console.print(table)

            repeat_full = False
            while True:
                console.print("\n[bold cyan]Post-Assessment Actions:[/bold cyan]")
                console.print("1. Explore Discovered Vulnerabilities in Detail")
                console.print("2. Query MITRE CWE Threat Intelligence for Discovered Findings")
                console.print("3. Export Assessment Reports (Markdown, TXT, DOCX)")
                console.print("4. Run Another Full Assessment")
                console.print("0. Return to Main Menu")

                post_choice = Prompt.ask(
                    "\n[bold green]Select an option[/bold green]",
                    choices=["0", "1", "2", "3", "4", "b", "B", ""],
                    default="1",
                    show_default=False,
                    show_choices=False,
                ).strip()

                if post_choice in ["0", "b", "B", ""]:
                    break
                elif post_choice == "1":
                    explore_full_assessment_findings(findings)
                elif post_choice == "2":
                    prompt_cwe_query_for_findings(findings)
                elif post_choice == "3":
                    rep_files = export_assessment_report(results["assessment_id"], format_type="all")
                    console.print("\n[bold green]Reports successfully generated:[/bold green]")
                    for fmt, p in rep_files.items():
                        console.print(f"  - [bold cyan]{fmt.upper()}:[/bold cyan] {p}")
                elif post_choice == "4":
                    repeat_full = True
                    break

            if not repeat_full:
                break
        else:
            console.print("[bold green]No security vulnerabilities detected on the target device.[/bold green]")
            export_now = Confirm.ask("\nWould you like to export assessment reports (Markdown, TXT, DOCX) now?", default=False)
            if export_now:
                rep_files = export_assessment_report(results["assessment_id"], format_type="all")
                console.print("\n[bold green]Reports successfully generated:[/bold green]")
                for fmt, p in rep_files.items():
                    console.print(f"  - [bold cyan]{fmt.upper()}:[/bold cyan] {p}")

            console.print("\n[bold cyan]Post-Assessment Actions:[/bold cyan]")
            console.print("1. Run Another Full Assessment")
            console.print("0. Return to Main Menu")

            post_choice = Prompt.ask(
                "\n[bold green]Select an option[/bold green]",
                choices=["0", "1", "b", "B", ""],
                default="0",
                show_default=False,
                show_choices=False,
            ).strip()

            if post_choice != "1":
                break


def create_assessment_screen() -> None:
    while True:
        clear_screen()
        show_banner()
        console.print("[bold cyan]--- Create New Assessment Session ---[/bold cyan]\n")

        target_ip, iface_name = prompt_select_target_ip(default_fallback="192.168.11.1")
        if target_ip is None:
            console.print("[yellow]Returning to main menu...[/yellow]")
            return

        console.print(f"[green]Selected gateway:[/green] [bold cyan]{target_ip}[/bold cyan] ({iface_name})")

        device_id = Prompt.ask("[bold]Device ID (or 'b' to go back)[/bold]", default=f"Target-{target_ip}", show_default=False).strip()
        if is_back(device_id):
            return

        price_input = Prompt.ask("[bold]Purchase Price in LKR (Optional, or 'b' to go back)[/bold]", default="").strip()
        if is_back(price_input):
            return
        try:
            price_lkr = int(price_input) if price_input else 0
        except ValueError:
            price_lkr = 0

        setup_domain = Prompt.ask("[bold]Setup Domain (Optional, or 'b' to go back)[/bold]", default="").strip()
        if is_back(setup_domain):
            return

        notes = Prompt.ask("[bold]Assessment Notes (or 'b' to go back)[/bold]", default=f"Session via {iface_name}", show_default=False).strip()
        if is_back(notes):
            return

        metadata = {
            "setup_domain": setup_domain,
            "interface": iface_name,
        }

        new_assessment = create_assessment(
            device_id=device_id,
            target_ip=target_ip,
            price_lkr=price_lkr,
            notes=notes,
            metadata=metadata,
        )

        confirmation_details = f"""
[bold green]Assessment Created Successfully![/bold green]

[bold]Assessment ID:[/bold] {new_assessment["id"]}
[bold]Device ID:[/bold]     {new_assessment["device_id"]}
[bold]Target IP:[/bold]     {new_assessment["target_ip"]} (Interface: {iface_name})
[bold]Price:[/bold]         LKR {new_assessment["price_lkr"]}
[bold]Status:[/bold]        {new_assessment["status"]}
[bold]Created At:[/bold]    {new_assessment["created_at"]}
[bold]Notes:[/bold]         {new_assessment["notes"]}
"""
        console.print(Panel(confirmation_details.strip(), title=f"New Assessment: {new_assessment['id']}", border_style="green"))

        repeat_create = False
        while True:
            console.print("\n[bold cyan]Post-Creation Actions:[/bold cyan]")
            console.print("1. Create Another Assessment Session")
            console.print("2. View All Assessment Sessions (List & Manage)")
            console.print("0. Return to Main Menu")

            post_choice = Prompt.ask(
                "\n[bold green]Select an option[/bold green]",
                choices=["0", "1", "2", "b", "B", ""],
                default="0",
                show_default=False,
                show_choices=False,
            ).strip()

            if post_choice == "1":
                repeat_create = True
                break
            elif post_choice == "2":
                list_assessments_screen()
                console.print(Panel(confirmation_details.strip(), title=f"New Assessment: {new_assessment['id']}", border_style="green"))
            else:
                break

        if not repeat_create:
            break


def list_assessments_screen() -> None:
    while True:
        clear_screen()
        show_banner()
        console.print("[bold cyan]--- View & Manage Assessments ---[/bold cyan]\n")

        all_asms = get_all_assessments()
        quick_asms = get_assessments_by_category("quick_scan")
        full_asms = get_assessments_by_category("full_assessment")
        created_asms = get_assessments_by_category("created")

        console.print("[bold]Select Assessment Category to View:[/bold]\n")
        console.print(f"1. All Assessments (Created & Tested Sessions - {len(all_asms)} total)")
        console.print(f"2. Quick Scans Only ({len(quick_asms)} total)")
        console.print(f"3. Full In-Depth Assessments ({len(full_asms)} total)")
        console.print(f"4. Created / Pending Assessments ({len(created_asms)} total)")
        console.print("5. Export Complete Research Test Dataset & Audit Log (.txt / .log / .json)")
        console.print("6. Clear / Delete All Assessments & Findings (Global Reset)")
        console.print("0. Back to Main Menu")

        cat_choice = Prompt.ask(
            "\n[bold green]Select an option[/bold green]",
            choices=["0", "1", "2", "3", "4", "5", "6", "b", "B", ""],
            default="1",
            show_default=False,
            show_choices=False,
        ).strip()

        if cat_choice in ["0", "b", "B", ""]:
            return

        if cat_choice == "5":
            clear_screen()
            show_banner()
            console.print("[bold cyan]--- Export Complete Research Test Dataset & Audit Log ---[/bold cyan]\n")
            console.print("This feature compiles all tested repeaters, assessment sessions, confirmed vulnerabilities,")
            console.print("scores and raw technical evidence logs into a master research dataset for supervisors.\n")
            console.print("Select Export Format:")
            console.print("1. All Formats (Master Plain Text Dataset .txt, Audit Log .log, Machine JSON .json)")
            console.print("2. Plain Text Dataset (.txt) only")
            console.print("3. Audit Log (.log) only")
            console.print("4. JSON Dataset (.json) only")
            console.print("0. Back")

            ds_fmt_choice = Prompt.ask(
                "\n[bold green]Select an option[/bold green]",
                choices=["0", "1", "2", "3", "4", "b", "B"],
                default="1",
                show_default=False,
                show_choices=False,
            )
            if is_back(ds_fmt_choice) or ds_fmt_choice == "0":
                continue

            ds_map = {"1": "all", "2": "txt", "3": "log", "4": "json"}
            chosen_ds_fmt = ds_map[ds_fmt_choice]

            console.print(f"\n[bold cyan]Generating research test dataset in format: {chosen_ds_fmt}...[/bold cyan]")
            generated = export_research_test_dataset(format_type=chosen_ds_fmt)

            console.print("\n[bold green]Research dataset export complete![/bold green]\n")
            for fmt_name, fpath in generated.items():
                console.print(f"  - [bold cyan]{fmt_name.upper()}:[/bold cyan] {fpath}")

            pause()
            continue

        if cat_choice == "6":
            if not all_asms:
                console.print("\n[yellow]No assessment records to clear.[/yellow]")
                pause()
                continue

            confirmed = Confirm.ask(
                f"\n[bold red]Are you sure you want to permanently delete ALL {len(all_asms)} recorded assessment sessions and associated findings?[/bold red]",
                default=False,
            )
            if confirmed:
                deleted_cnt = clear_all_assessments()
                console.print(f"\n[bold green]Successfully cleared {deleted_cnt} assessment session(s) and reset findings globally.[/bold green]")
            else:
                console.print("\n[yellow]Global clear operation cancelled.[/yellow]")
            pause()
            continue

        cat_map = {
            "1": ("all", "All Security Assessments (Created & Tested)"),
            "2": ("quick_scan", "Quick Scan Assessments"),
            "3": ("full_assessment", "Full In-Depth Assessments"),
            "4": ("created", "Created / Pending Assessments"),
        }
        category_key, category_title = cat_map[cat_choice]
        render_assessment_category_view(category_key, category_title)


def render_assessment_category_view(category_key: str, category_title: str) -> None:
    while True:
        clear_screen()
        show_banner()
        asms = get_assessments_by_category(category_key)

        table = Table(title=f"{category_title} ({len(asms)} recorded)", show_header=True, header_style="bold cyan")
        table.add_column("#", justify="center", style="cyan", no_wrap=True)
        table.add_column("Assessment ID", style="bold cyan", no_wrap=True)
        table.add_column("Device ID")
        table.add_column("Target IP")
        table.add_column("Price (LKR)", justify="right")
        table.add_column("Status", justify="center")
        table.add_column("Category", justify="center")
        table.add_column("Findings", justify="center")
        table.add_column("Created At")

        for idx, asm in enumerate(asms, start=1):
            asm_id = asm.get("id", "")
            asm_dev = asm.get("device_id", "")
            asm_findings = get_findings_by_assessment_id(asm_id)
            if not asm_findings and asm_dev:
                asm_findings = get_findings_by_device_id(asm_dev)
            findings_cnt = len(asm_findings)

            asm_type = classify_assessment_type(asm)
            type_label = "Quick Scan" if asm_type == "quick_scan" else "Full Audit" if asm_type == "full_assessment" else "Pending"
            status_style = "green" if asm.get("status") == "Completed" else "yellow" if asm.get("status") == "In Progress" else "white"

            table.add_row(
                str(idx),
                asm_id,
                asm_dev,
                asm.get("target_ip", ""),
                str(asm.get("price_lkr", 0)),
                f"[{status_style}]{asm.get('status', 'Created')}[/{status_style}]",
                type_label,
                str(findings_cnt),
                asm.get("created_at", ""),
            )

        console.print(table)

        if not asms:
            console.print(f"\n[yellow]No assessment sessions found in '{category_title}'.[/yellow]")
            Prompt.ask("\n[bold cyan]Press Enter to return to Assessment Categories[/bold cyan]", default="")
            return

        console.print("\n[bold cyan]Category Actions:[/bold cyan]")
        console.print("1. Select an Assessment (View Details, Export Report, Clear / Delete)")
        console.print("2. Export Reports for All Listed Assessments in this Category")
        console.print("3. Clear / Delete All Listed Assessments in this Category")
        console.print("0. Back to Assessment Categories")

        sub_choice = Prompt.ask(
            "\n[bold green]Select an option[/bold green]",
            choices=["0", "1", "2", "3", "b", "B", ""],
            default="1",
            show_default=False,
            show_choices=False,
        ).strip()

        if sub_choice in ["0", "b", "B", ""]:
            return

        if sub_choice == "1":
            chosen_id = Prompt.ask(
                f"\n[bold cyan]Enter Assessment ID (e.g. {asms[0].get('id')}) or '#' (1..{len(asms)}) to manage ('b' to cancel)[/bold cyan]"
            ).strip()
            if is_back(chosen_id) or not chosen_id:
                continue

            target_asm = None
            if chosen_id.isdigit():
                idx_num = int(chosen_id)
                if 1 <= idx_num <= len(asms):
                    target_asm = asms[idx_num - 1]
            if not target_asm:
                for a in asms:
                    if a.get("id", "").lower() == chosen_id.lower():
                        target_asm = a
                        break

            if not target_asm:
                console.print(f"\n[red]Assessment not found in this list:[/red] {chosen_id}")
                pause()
                continue

            manage_single_assessment_session(target_asm["id"])

        elif sub_choice == "2":
            clear_screen()
            show_banner()
            console.print(f"[bold cyan]--- Bulk Export Reports for {len(asms)} Listed Assessments ---[/bold cyan]\n")
            console.print("Select Output Format:")
            console.print("1. All Formats (Markdown, Plain Text, Word DOCX)")
            console.print("2. Markdown (.md) only")
            console.print("3. Plain Text (.txt) only")
            console.print("4. Microsoft Word (.docx) only")
            console.print("0. Cancel")

            bulk_fmt_choice = Prompt.ask(
                "\n[bold green]Select an option[/bold green]",
                choices=["0", "1", "2", "3", "4", "b", "B"],
                default="1",
                show_default=False,
                show_choices=False,
            )
            if is_back(bulk_fmt_choice) or bulk_fmt_choice == "0":
                continue

            fmt_map = {"1": "all", "2": "md", "3": "txt", "4": "docx"}
            chosen_fmt = fmt_map[bulk_fmt_choice]

            console.print(f"\n[bold cyan]Exporting reports for {len(asms)} assessment(s)...[/bold cyan]\n")
            for a in asms:
                aid = a.get("id")
                try:
                    exp_files = export_assessment_report(assessment_id=aid, format_type=chosen_fmt)
                    console.print(f"[bold green]✓ {aid}:[/bold green] {list(exp_files.values())}")
                except Exception as err:
                    console.print(f"[red]✗ {aid}: {err}[/red]")

            console.print(f"\n[bold green]Bulk export completed! Reports saved in 'reports/' directory.[/bold green]")
            pause()

        elif sub_choice == "3":
            confirmed = Confirm.ask(
                f"\n[bold red]Are you sure you want to permanently delete ALL {len(asms)} assessment(s) in '{category_title}' and their findings?[/bold red]",
                default=False,
            )
            if confirmed:
                deleted_ids = [a.get("id") for a in asms if a.get("id")]
                cnt = delete_assessments_by_ids(deleted_ids)
                console.print(f"\n[bold green]Successfully deleted {cnt} assessment(s) and cleared findings globally.[/bold green]")
                pause()
                return
            else:
                console.print("\n[yellow]Clear operation cancelled.[/yellow]")
                pause()


def manage_single_assessment_session(assessment_id: str) -> None:
    while True:
        clear_screen()
        show_banner()
        asm = get_assessment_by_id(assessment_id)
        if not asm:
            console.print(f"[yellow]Assessment {assessment_id} is no longer available (it may have been deleted).[/yellow]")
            pause()
            return

        device_id = asm.get("device_id", "Target-Device")
        target_ip = asm.get("target_ip", "192.168.11.1")
        price_lkr = asm.get("price_lkr", 0)
        status = asm.get("status", "Created")
        created_at = asm.get("created_at", "")
        checks = asm.get("checks", [])

        eval_res = evaluate_device_security(
            device_id=device_id if not assessment_id else None,
            assessment_id=assessment_id,
            custom_price=price_lkr,
        )
        findings = get_findings_by_assessment_id(assessment_id)
        if not findings and device_id:
            findings = get_findings_by_device_id(device_id)

        risk = eval_res.get("risk_level", "Low")
        score = eval_res.get("final_score", 100)
        psr = eval_res.get("psr", 0.0)
        rec = eval_res.get("recommendation", {})
        status_color = "red" if risk in ["Critical", "High"] else "yellow" if risk == "Medium" else "green"

        summary_box = f"""
[bold]Assessment ID:[/bold]       {asm.get('id')}
[bold]Device Identifier:[/bold]   {device_id}
[bold]Target Gateway IP:[/bold]   {target_ip}
[bold]Purchase Price:[/bold]       LKR {price_lkr}
[bold]Status:[/bold]               {status}
[bold]Created At:[/bold]           {created_at}
[bold]Executed Checks:[/bold]      {len(checks)} module(s) executed
[bold]Confirmed Findings:[/bold]   {len(findings)} discovered

[bold]Base Security Score:[/bold]  {eval_res.get('base_score', 100)}/100
[bold]Total Deductions:[/bold]     -{eval_res.get('total_deductions', 0)} points
[bold]Final Security Score:[/bold] [{status_color}]{score}/100[/{status_color}]
[bold]Risk Classification:[/bold]  [{status_color}]{risk}[/{status_color}]
[bold]Price-to-Security (PSR):[/bold] {psr} (Baseline: LKR 15,000)

[bold]Recommendation Category:[/bold]
[bold {status_color}]{rec.get('category', 'N/A')}[/bold {status_color}]

[bold]Guidance:[/bold]
{rec.get('guidance', '')}
"""
        console.print(Panel(summary_box.strip(), title=f"Assessment Details: {assessment_id}", border_style=status_color))

        if findings:
            f_table = Table(title=f"Discovered Findings for {assessment_id} ({len(findings)} total)", show_header=True, header_style="bold cyan")
            f_table.add_column("Finding ID", style="cyan", no_wrap=True)
            f_table.add_column("Severity", justify="center")
            f_table.add_column("Module")
            f_table.add_column("Title")
            f_table.add_column("CWE")

            for f in findings:
                f_sev = f.get("severity", "")
                sev_style = "bold red" if f_sev.lower() in ["high", "critical"] else "bold yellow" if "medium" in f_sev.lower() else "bold green"
                f_table.add_row(
                    f.get("id", ""),
                    f"[{sev_style}]{f_sev}[/{sev_style}]",
                    f.get("module", "General"),
                    f.get("title", ""),
                    f.get("cwe", "CWE-General"),
                )
            console.print(f_table)

        console.print("\n[bold cyan]Assessment Actions:[/bold cyan]")
        console.print("1. Export Security Report for this Assessment (Markdown, Plain Text, Word DOCX)")
        console.print("2. Explore Discovered Findings in Technical Detail")
        console.print("3. Update Assessment Metadata (Device ID, IP, Price, Status, Notes)")
        console.print("4. Clear / Delete this Assessment & its Findings (Permanent)")
        console.print("0. Back to Assessment List")

        act = Prompt.ask(
            "\n[bold green]Select an option[/bold green]",
            choices=["0", "1", "2", "3", "4", "b", "B", ""],
            default="1",
            show_default=False,
            show_choices=False,
        ).strip()

        if act in ["0", "b", "B", ""]:
            return

        if act == "1":
            console.print("\n[bold]Select Export Format:[/bold]")
            console.print("1. All Formats (Markdown, Plain Text, DOCX Word Document)")
            console.print("2. Markdown (.md) only")
            console.print("3. Plain Text (.txt) only")
            console.print("4. Microsoft Word (.docx) only")
            console.print("0. Cancel")

            exp_fmt_choice = Prompt.ask(
                "[bold green]Select an option[/bold green]",
                choices=["0", "1", "2", "3", "4", "b", "B"],
                default="1",
                show_default=False,
                show_choices=False,
            )
            if is_back(exp_fmt_choice) or exp_fmt_choice == "0":
                continue

            fmt_map = {"1": "all", "2": "md", "3": "txt", "4": "docx"}
            chosen_fmt = fmt_map[exp_fmt_choice]

            console.print(f"\n[bold cyan]Generating security report for {assessment_id}...[/bold cyan]")
            generated_files = export_assessment_report(assessment_id=assessment_id, format_type=chosen_fmt)

            console.print(f"\n[bold green]Report generation complete![/bold green]\n")
            for fmt, fpath in generated_files.items():
                console.print(f"  - [bold cyan]{fmt.upper()}:[/bold cyan] {fpath}")
            pause()

        elif act == "2":
            if not findings:
                console.print("\n[yellow]No findings recorded for this assessment.[/yellow]")
                pause()
                continue
            explore_quick_scan_alerts(findings)

        elif act == "3":
            update_single_assessment_flow(assessment_id)

        elif act == "4":
            confirmed = Confirm.ask(
                f"\n[bold red]Are you sure you want to permanently delete assessment {assessment_id} ({device_id}) and all its findings?[/bold red]",
                default=False,
            )
            if confirmed:
                deleted = delete_assessment_by_id(assessment_id)
                if deleted:
                    console.print(f"\n[bold green]Assessment {assessment_id} and its findings deleted successfully![/bold green]")
                else:
                    console.print(f"\n[red]Failed to delete assessment {assessment_id}.[/red]")
                pause()
                return
            else:
                console.print("\n[yellow]Delete operation cancelled.[/yellow]")
                pause()


def update_single_assessment_flow(assessment_id: str) -> None:
    target_asm = get_assessment_by_id(assessment_id)
    if not target_asm:
        console.print(f"\n[red]Assessment not found:[/red] {assessment_id}")
        pause()
        return

    clear_screen()
    show_banner()
    console.print(f"[bold cyan]--- Update Assessment Session: {target_asm['id']} ---[/bold cyan]\n")
    console.print("[dim]Press Enter to keep current values, or enter updated information ('b' to cancel).[/dim]\n")

    curr_dev = target_asm.get("device_id", "Target-Device")
    new_dev = Prompt.ask(f"[bold]Device ID / Name[/bold]", default=curr_dev).strip()
    if is_back(new_dev):
        return

    curr_ip = target_asm.get("target_ip", "192.168.11.1")
    new_ip = Prompt.ask(f"[bold]Target Gateway IP[/bold]", default=curr_ip).strip()
    if is_back(new_ip):
        return

    curr_price = str(target_asm.get("price_lkr", 0))
    new_price_str = Prompt.ask(f"[bold]Purchase Price in LKR[/bold]", default=curr_price).strip()
    if is_back(new_price_str):
        return
    try:
        new_price = int(new_price_str)
    except ValueError:
        new_price = target_asm.get("price_lkr", 0)

    curr_status = target_asm.get("status", "Created")
    new_status = Prompt.ask(
        f"[bold]Assessment Status[/bold]",
        choices=["Created", "In Progress", "Completed", "b", "B"],
        default=curr_status,
        show_default=False,
        show_choices=False,
    ).strip()
    if is_back(new_status):
        return

    meta = target_asm.get("metadata", {})
    curr_domain = meta.get("setup_domain", "")
    new_domain = Prompt.ask(f"[bold]Setup Domain Clue (Optional)[/bold]", default=curr_domain).strip()
    if is_back(new_domain):
        return
    meta["setup_domain"] = new_domain

    curr_notes = target_asm.get("notes", "")
    new_notes = Prompt.ask(f"[bold]Assessment Notes (Optional)[/bold]", default=curr_notes).strip()
    if is_back(new_notes):
        return

    updated_record = update_assessment(
        assessment_id=assessment_id,
        device_id=new_dev,
        target_ip=new_ip,
        price_lkr=new_price,
        status=new_status,
        metadata=meta,
        notes=new_notes,
    )

    if updated_record:
        summary = f"""
[bold green]Assessment {assessment_id} Updated Successfully![/bold green]

[bold]Device ID:[/bold]     {updated_record.get('device_id')}
[bold]Target Gateway:[/bold] {updated_record.get('target_ip')}
[bold]Price:[/bold]          LKR {updated_record.get('price_lkr')}
[bold]Status:[/bold]         {updated_record.get('status')}
[bold]Setup Domain:[/bold]   {updated_record.get('metadata', {}).get('setup_domain', 'None')}
[bold]Notes:[/bold]          {updated_record.get('notes', 'None')}
[bold]Updated At:[/bold]     {updated_record.get('updated_at')}
"""
        console.print(Panel(summary.strip(), title=f"Updated: {assessment_id}", border_style="green"))
    else:
        console.print(f"[red]Failed to update assessment {assessment_id}.[/red]")
    pause()


def prompt_select_assessment_id(
    prompt_message: str = "Select Assessment",
    default_fallback: str | None = None,
    allow_manual_input: bool = True,
) -> tuple[Optional[str], Optional[dict[str, Any]]]:
    """
    Prompt the user to select an existing assessment session with an interactive list of available assessments,
    supporting numbered selection [1..N], direct ID entry (ASM-001), full details expansion ('l'), and cancellation ('b').
    Returns (assessment_id, assessment_dict) or (None, None) if cancelled.
    """
    assessments = get_all_assessments()

    if not assessments:
        if not allow_manual_input:
            console.print("[yellow]No assessment sessions found in database.[/yellow]")
            pause()
            return None, None
        default_id = default_fallback or "ASM-001"
        entered_id = Prompt.ask(
            f"[bold]{prompt_message} (No saved sessions found, enter ID or 'b' to go back)[/bold]",
            default=default_id,
            show_default=False,
        ).strip()
        if is_back(entered_id):
            return None, None
        return entered_id, None

    table = Table(title=f"Available Assessment Sessions ({len(assessments)} recorded)", show_header=True, header_style="bold cyan")
    table.add_column("#", justify="center", style="cyan", no_wrap=True)
    table.add_column("Assessment ID", style="bold cyan")
    table.add_column("Device ID")
    table.add_column("Target Gateway")
    table.add_column("Price (LKR)", justify="right")
    table.add_column("Status", justify="center")
    table.add_column("Created Date")

    for idx, asm in enumerate(assessments, start=1):
        stat = asm.get("status", "Created")
        stat_color = "green" if stat == "Completed" else "yellow"
        table.add_row(
            str(idx),
            asm.get("id", ""),
            asm.get("device_id", "Target-Device"),
            asm.get("target_ip", "N/A"),
            str(asm.get("price_lkr", 0)),
            f"[{stat_color}]{stat}[/{stat_color}]",
            asm.get("created_at", ""),
        )
    console.print(table)

    default_asm = assessments[-1]
    default_id = default_asm.get("id", "ASM-001")
    range_str = f"1-{len(assessments)}" if len(assessments) > 1 else "1"

    console.print("\n[bold]Options:[/bold]")
    console.print(f"  [bold cyan]{range_str:<4}[/bold cyan] : Select assessment by number from table")
    console.print(f"  [bold cyan]{'ID':<4}[/bold cyan] : Enter Assessment ID directly (e.g. ASM-001)")
    console.print(f"  [bold cyan]{'L':<4}[/bold cyan] : View full detailed breakdown of all sessions")
    console.print(f"  [bold cyan]{'B':<4}[/bold cyan] : Return to previous menu")

    while True:
        choice = Prompt.ask(
            "\n[bold green]Select an option[/bold green]",
            default=default_id,
            show_default=False,
        ).strip()

        if is_back(choice):
            return None, None

        if choice.lower() in ["l", "list", "details"]:
            clear_screen()
            show_banner()
            console.print("[bold cyan]--- All Assessment Sessions Detailed Breakdown ---[/bold cyan]\n")
            for idx, asm in enumerate(assessments, start=1):
                checks_count = len(asm.get("checks", []))
                card = f"""
[bold]Session Number:[/bold]    #{idx}
[bold]Assessment ID:[/bold]     {asm.get('id')}
[bold]Device Identifier:[/bold] {asm.get('device_id')}
[bold]Target Gateway:[/bold]    {asm.get('target_ip')}
[bold]Device Price:[/bold]      LKR {asm.get('price_lkr', 0)}
[bold]Status:[/bold]            {asm.get('status', 'Created')}
[bold]Created At:[/bold]        {asm.get('created_at')}
[bold]Executed Checks:[/bold]   {checks_count} check(s) recorded
[bold]Setup Domain:[/bold]      {asm.get('metadata', {}).get('setup_domain', 'None')}
[bold]Notes:[/bold]             {asm.get('notes', 'None')}
"""
                console.print(Panel(card.strip(), title=f"Assessment: {asm.get('id')}", border_style="cyan"))
            console.print(table)
            continue

        try:
            selected_idx = int(choice) - 1
            if 0 <= selected_idx < len(assessments):
                chosen_asm = assessments[selected_idx]
                return chosen_asm["id"], chosen_asm
        except ValueError:
            pass

        match_asm = next((a for a in assessments if a.get("id", "").upper() == choice.upper()), None)
        if match_asm:
            return match_asm["id"], match_asm

        if allow_manual_input and choice:
            return choice, None

        console.print(f"[red]Invalid selection: '{choice}'. Enter 1 to {len(assessments)}, a valid Assessment ID, or 'b' to go back.[/red]")


def run_network_discovery_screen() -> None:
    while True:
        clear_screen()
        show_banner()
        console.print("[bold cyan]--- Run Network Discovery ---[/bold cyan]\n")

        assessment_id, asm = prompt_select_assessment_id("Select Assessment for Network Discovery")
        if not assessment_id:
            return

        if asm:
            target_ip = asm.get("target_ip", "192.168.11.1")
            device_id = asm.get("device_id", "Target-Device")
            console.print(f"[green]Loaded from assessment:[/green] Target = [bold]{target_ip}[/bold], Device = [bold]{device_id}[/bold]")
        else:
            target_ip, iface_name = prompt_select_target_ip()
            if target_ip is None:
                return
            device_id = Prompt.ask("[bold]Device ID / Name (or 'b' to go back)[/bold]", default=f"Target-{target_ip}").strip()
            if is_back(device_id):
                return

        console.print("\n[bold]Select Discovery Method:[/bold]")
        console.print("1. Live Safe Network Scan (Python Sockets / Nmap)")
        console.print("2. Import / Paste Nmap Scan Text")
        console.print("3. Import Nmap Text from File")
        console.print("0. Back to Main Menu")

        method_choice = Prompt.ask("[bold green]Select an option[/bold green]", choices=["0", "1", "2", "3", "b", "B"], default="1", show_default=False, show_choices=False)
        if is_back(method_choice):
            return

        raw_nmap_text = None

        if method_choice == "2":
            console.print("\n[cyan]Paste raw Nmap output below. When finished, press Enter then type 'EOF' and press Enter:[/cyan]")
            lines = []
            while True:
                try:
                    line = input()
                    if line.strip() == "EOF":
                        break
                    lines.append(line)
                except EOFError:
                    break
            raw_nmap_text = "\n".join(lines)
        elif method_choice == "3":
            file_path_input = Prompt.ask("[bold]Enter path to Nmap output text file (or 'b' to go back)[/bold]").strip()
            if is_back(file_path_input):
                return
            try:
                with open(file_path_input, "r", encoding="utf-8") as f:
                    raw_nmap_text = f.read()
            except Exception as err:
                console.print(f"[red]Error reading file:[/red] {err}")
                pause()
                return

        console.print("\n[bold cyan]Executing network discovery...[/bold cyan]")
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=None),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[bold cyan]Scanning target network ports...", total=100)

            def on_net_prog(percent: int, msg: str) -> None:
                progress.update(task, completed=percent, description=f"[bold cyan]{msg}")

            results = perform_network_discovery(
                target_ip=target_ip,
                device_id=device_id,
                assessment_id=assessment_id,
                raw_nmap_text=raw_nmap_text,
                progress_callback=on_net_prog,
            )
            progress.update(task, completed=100, description="[bold green]Network discovery completed!")

        open_ports = results.get("open_ports", [])
        findings = results.get("findings", [])

        console.print(f"\n[bold green]Scan Completed via method: {results['scan_method']}[/bold green]")
        console.print(f"[bold]Evidence saved to:[/bold] {results['evidence_file']}\n")

        if open_ports:
            port_table = Table(title=f"Discovered Ports on {target_ip}", show_header=True, header_style="bold cyan")
            port_table.add_column("Port", style="cyan", justify="right")
            port_table.add_column("Protocol", justify="center")
            port_table.add_column("State", justify="center")
            port_table.add_column("Service")
            port_table.add_column("Banner / Details")

            for port_info in open_ports:
                port_table.add_row(
                    str(port_info.get("port")),
                    port_info.get("protocol", "tcp"),
                    port_info.get("state", "open"),
                    port_info.get("service", "unknown"),
                    port_info.get("banner", ""),
                )
            console.print(port_table)
        else:
            console.print("[yellow]No open common ports discovered on target.[/yellow]")

        if findings:
            console.print(f"\n[bold red]Network Findings Detected ({len(findings)}):[/bold red]")
            for f in findings:
                sev = f["severity"].lower()
                b_style = "red" if sev == "high" else "yellow" if "medium" in sev else "green"
                console.print(
                    Panel(
                        f"""
[bold]Title:[/bold] {f["title"]}
[bold]Severity:[/bold] {f["severity"]} | [bold]Category:[/bold] {f["category"]}
[bold]Impact:[/bold] {f["impact"]}
[bold]Recommendation:[/bold] {f["recommendation"]}
""".strip(),
                        title=f["id"],
                        border_style=b_style,
                    )
                )

        repeat_net = False
        while True:
            console.print("\n[bold cyan]Post-Scan Actions:[/bold cyan]")
            if findings:
                console.print("1. Run Another Network Discovery Scan")
                console.print("2. Explore Discovered Findings in Detail")
                console.print("3. Query MITRE CWE Threat Intelligence for Discovered Findings")
                console.print("0. Return to Main Menu")
                next_act = Prompt.ask("\n[bold green]Select an option[/bold green]", choices=["0", "1", "2", "3", "b", "B", ""], default="0", show_default=False, show_choices=False).strip()
                if next_act == "1":
                    repeat_net = True
                    break
                elif next_act == "2":
                    explore_full_assessment_findings(findings)
                elif next_act == "3":
                    prompt_cwe_query_for_findings(findings)
                else:
                    break
            else:
                console.print("1. Run Another Network Discovery Scan")
                console.print("0. Return to Main Menu")
                next_act = Prompt.ask("\n[bold green]Select an option[/bold green]", choices=["0", "1", "b", "B", ""], default="0", show_default=False, show_choices=False).strip()
                if next_act == "1":
                    repeat_net = True
                    break
                else:
                    break

        if not repeat_net:
            break


def run_dns_checks_screen() -> None:
    while True:
        clear_screen()
        show_banner()
        console.print("[bold cyan]--- Run DNS Behavior Checks ---[/bold cyan]\n")

        assessment_id, asm = prompt_select_assessment_id("Select Assessment for DNS Checks")
        if not assessment_id:
            return

        if asm:
            target_ip = asm.get("target_ip", "192.168.11.1")
            device_id = asm.get("device_id", "Target-Device")
            setup_domain_default = asm.get("metadata", {}).get("setup_domain", "")
            console.print(f"[green]Loaded from assessment:[/green] Target = [bold]{target_ip}[/bold], Device = [bold]{device_id}[/bold]")
        else:
            target_ip, iface_name = prompt_select_target_ip()
            if target_ip is None:
                return
            device_id = Prompt.ask("[bold]Device ID (or 'b' to go back)[/bold]", default=f"Target-{target_ip}").strip()
            if is_back(device_id):
                return
            setup_domain_default = ""

        setup_domain = Prompt.ask("[bold]Setup Domain to test (Optional, press Enter if none, or 'b' to go back)[/bold]", default=setup_domain_default).strip()
        if is_back(setup_domain):
            return

        control_domain = Prompt.ask("[bold]Control Domain for Comparison (or 'b' to go back)[/bold]", default="google.com").strip()
        if is_back(control_domain):
            return

        upstream_ip = Prompt.ask("[bold]Upstream-side Repeater IP (Optional, press Enter to skip or 'b' to go back)[/bold]", default="").strip()
        if is_back(upstream_ip):
            return
        upstream_ip = upstream_ip if upstream_ip else None

        console.print("\n[bold]Select Query Method:[/bold]")
        console.print("1. Live DNS Queries (dnspython / nslookup)")
        console.print("2. Enter / Import Manual Resolution Results")
        console.print("0. Back to Main Menu")

        method_choice = Prompt.ask("[bold green]Select an option[/bold green]", choices=["0", "1", "2", "b", "B"], default="1", show_default=False, show_choices=False)
        if is_back(method_choice):
            return

        manual_setup_ips = None
        manual_control_ips = None
        manual_up_setup_ips = None
        manual_up_control_ips = None

        if method_choice == "2":
            if setup_domain:
                setup_ips_str = Prompt.ask(f"[bold]Resolved IPs for {setup_domain} on {target_ip} (comma-separated)[/bold]", default=target_ip).strip()
                if is_back(setup_ips_str):
                    return
                manual_setup_ips = [ip.strip() for ip in setup_ips_str.split(",") if ip.strip()]

            control_ips_str = Prompt.ask(f"[bold]Resolved IPs for {control_domain} on {target_ip} (comma-separated)[/bold]", default="142.250.190.46").strip()
            if is_back(control_ips_str):
                return
            manual_control_ips = [ip.strip() for ip in control_ips_str.split(",") if ip.strip()]

        console.print("\n[bold cyan]Executing DNS behavior checks...[/bold cyan]")
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=None),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[bold cyan]Running DNS Behavior Checks...", total=100)
            progress.update(task, completed=30, description=f"[bold cyan]Resolving setup domain '{setup_domain or 'General'}' on {target_ip}...")
            results = perform_dns_checks(
                target_ip=target_ip,
                device_id=device_id,
                assessment_id=assessment_id,
                setup_domain=setup_domain,
                control_domain=control_domain,
                upstream_ip=upstream_ip,
                manual_setup_ips=manual_setup_ips,
                manual_control_ips=manual_control_ips,
                manual_upstream_setup_ips=manual_up_setup_ips,
                manual_upstream_control_ips=manual_up_control_ips,
            )
            progress.update(task, completed=100, description="[bold green]DNS checks completed!")

        console.print(f"\n[bold green]DNS Checks Completed![/bold green]")
        console.print(f"[bold]Evidence saved to:[/bold] {results['evidence_file']}\n")

        dns_table = Table(title="DNS Resolution Results", show_header=True, header_style="bold cyan")
        dns_table.add_column("DNS Server / Interface", style="cyan")
        dns_table.add_column("Domain")
        dns_table.add_column("Resolved IP(s)")
        dns_table.add_column("Behavior Status")

        if setup_domain:
            setup_ips_display = ", ".join(results["setup_ips"]) if results["setup_ips"] else "No response"
            target_status = "[red]Internal IP Leaked[/red]" if target_ip in results["setup_ips"] else "[green]Normal[/green]"
            dns_table.add_row(f"Target ({target_ip})", setup_domain, setup_ips_display, target_status)

        ctrl_ips_display = ", ".join(results["control_ips"]) if results["control_ips"] else "No response"
        dns_table.add_row(f"Target ({target_ip})", control_domain, ctrl_ips_display, "[green]Forwarded[/green]" if results["control_ips"] else "[yellow]No response / Closed[/yellow]")

        console.print(dns_table)

        findings = results.get("findings", [])
        if findings:
            console.print(f"\n[bold red]DNS Findings Detected ({len(findings)}):[/bold red]")
            for f in findings:
                sev = f["severity"].lower()
                b_style = "red" if sev == "high" else "yellow" if "medium" in sev else "green"
                console.print(
                    Panel(
                        f"""
[bold]Title:[/bold] {f["title"]}
[bold]Severity:[/bold] {f["severity"]} | [bold]Category:[/bold] {f["category"]}
[bold]Impact:[/bold] {f["impact"]}
[bold]Recommendation:[/bold] {f["recommendation"]}
""".strip(),
                        title=f["id"],
                        border_style=b_style,
                    )
                )

        repeat_dns = False
        while True:
            console.print("\n[bold cyan]Post-Check Actions:[/bold cyan]")
            if findings:
                console.print("1. Run Another DNS Check")
                console.print("2. Explore Discovered Findings in Detail")
                console.print("3. Query MITRE CWE Threat Intelligence for Discovered Findings")
                console.print("0. Return to Main Menu")
                next_act = Prompt.ask("\n[bold green]Select an option[/bold green]", choices=["0", "1", "2", "3", "b", "B", ""], default="0", show_default=False, show_choices=False).strip()
                if next_act == "1":
                    repeat_dns = True
                    break
                elif next_act == "2":
                    explore_full_assessment_findings(findings)
                elif next_act == "3":
                    prompt_cwe_query_for_findings(findings)
                else:
                    break
            else:
                console.print("1. Run Another DNS Check")
                console.print("0. Return to Main Menu")
                next_act = Prompt.ask("\n[bold green]Select an option[/bold green]", choices=["0", "1", "b", "B", ""], default="0", show_default=False, show_choices=False).strip()
                if next_act == "1":
                    repeat_dns = True
                    break
                else:
                    break

        if not repeat_dns:
            break


def run_web_checks_screen() -> None:
    while True:
        clear_screen()
        show_banner()
        console.print("[bold cyan]--- Run Web Interface Checks ---[/bold cyan]\n")

        assessment_id, asm = prompt_select_assessment_id("Select Assessment for Web Interface Checks")
        if not assessment_id:
            return

        if asm:
            target_ip = asm.get("target_ip", "192.168.11.1")
            device_id = asm.get("device_id", "Target-Device")
            console.print(f"[green]Loaded from assessment:[/green] Target = [bold]{target_ip}[/bold], Device = [bold]{device_id}[/bold]")
        else:
            target_ip, iface_name = prompt_select_target_ip()
            if target_ip is None:
                return
            device_id = Prompt.ask("[bold]Device ID (or 'b' to go back)[/bold]", default=f"Target-{target_ip}").strip()
            if is_back(device_id):
                return

        target_url = Prompt.ask("[bold]Target URL (or 'b' to go back)[/bold]", default=f"http://{target_ip}/").strip()
        if is_back(target_url):
            return

        console.print("\n[bold]Select Web Check Mode:[/bold]")
        console.print("1. Live Web Interface Inspection (HTTP fetch & DOM parsing)")
        console.print("2. Import / Paste Login Page HTML")
        console.print("3. Manual Lab Evidence Confirmation (Guided)")
        console.print("0. Back to Main Menu")

        check_mode = Prompt.ask("[bold green]Select an option[/bold green]", choices=["0", "1", "2", "3", "b", "B"], default="1", show_default=False, show_choices=False)
        if is_back(check_mode):
            return

        raw_html = None
        observed_login_url = None
        manual_observations = {}

        if check_mode == "2":
            console.print("\n[cyan]Paste raw login HTML below. Type 'EOF' on a new line when done:[/cyan]")
            lines = []
            while True:
                try:
                    line = input()
                    if line.strip() == "EOF":
                        break
                    lines.append(line)
                except EOFError:
                    break
            raw_html = "\n".join(lines)

            observed_login_url_input = Prompt.ask(
                "[bold]Observed login request URL (Optional, press Enter if none)[/bold]",
                default="",
            ).strip()
            if is_back(observed_login_url_input):
                return
            observed_login_url = observed_login_url_input if observed_login_url_input else None

        elif check_mode == "3":
            console.print("\n[bold cyan]Answer the following safe observation questions based on your lab testing:[/bold cyan]\n")
            manual_observations["hidden_credentials_in_html"] = Confirm.ask("Does index.html contain hidden username or password values?", default=False)
            manual_observations["login_without_credentials"] = Confirm.ask("Does clicking LOGIN grant access without entering credentials?", default=False)
            manual_observations["insecure_auth_cookie"] = Confirm.ask("Is there an Authorization cookie with Base64 credentials lacking HttpOnly/Secure flags?", default=False)
            manual_observations["credentials_in_url"] = Confirm.ask("Are credentials exposed in the login URL query string?", default=False)
            manual_observations["no_logout_option"] = Confirm.ask("Is there NO visible logout button to terminate the session?", default=False)

        console.print("\n[bold cyan]Executing web interface security checks...[/bold cyan]")
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=None),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(f"[bold cyan]Auditing Web Interface on {target_url}...", total=100)

            def on_web_prog(percent: int, msg: str) -> None:
                progress.update(task, completed=percent, description=f"[bold cyan]{msg}")

            results = perform_web_checks(
                target_url=target_url,
                device_id=device_id,
                assessment_id=assessment_id,
                raw_html=raw_html,
                observed_login_url=observed_login_url,
                manual_observations=manual_observations if check_mode == "3" else None,
                progress_callback=on_web_prog,
            )
            progress.update(task, completed=100, description="[bold green]Web interface checks completed!")

        findings = results.get("findings", [])

        console.print(f"\n[bold green]Web Checks Completed via method: {results['check_method']}![/bold green]")
        console.print(f"[bold]Evidence saved to:[/bold] {results['evidence_file']}\n")

        if not results.get("is_reachable") and check_mode == "1":
            console.print(f"[yellow]Web interface is not reachable on {target_url}. No HTTP vulnerabilities detected.[/yellow]")
        else:
            analysis = results.get("html_analysis", {})
            if analysis:
                web_table = Table(title=f"Web Analysis Summary for {target_url}", show_header=True, header_style="bold cyan")
                web_table.add_column("Property", style="cyan")
                web_table.add_column("Observed Value")

                web_table.add_row("Page Title", analysis.get("title") or "N/A")
                web_table.add_row("Hidden Form Inputs", str(len(analysis.get("hidden_fields", []))))
                web_table.add_row("Visible Input Fields", str(len(analysis.get("visible_inputs", []))))
                web_table.add_row("Hidden 'admin' Credential Detected", "[red]Yes[/red]" if analysis.get("has_hidden_admin") else "[green]No[/green]")
                web_table.add_row("Basic Auth / Cookie Script Logic", "[red]Detected[/red]" if analysis.get("has_basic_cookie_logic") else "[green]None[/green]")
                web_table.add_row("Logout Links Found", str(analysis.get("logout_links_count", 0)))
                if analysis.get("firmware_clue"):
                    web_table.add_row("Firmware Clue in HTML", analysis.get("firmware_clue"))

                console.print(web_table)

        findings = results.get("findings", [])
        if findings:
            console.print(f"\n[bold red]Web Interface Findings Detected ({len(findings)}):[/bold red]")
            for f in findings:
                sev = f["severity"].lower()
                b_style = "red" if sev == "high" else "yellow" if "medium" in sev else "green"
                console.print(
                    Panel(
                        f"""
[bold]Title:[/bold] {f["title"]}
[bold]Severity:[/bold] {f["severity"]} | [bold]Category:[/bold] {f["category"]}
[bold]Impact:[/bold] {f["impact"]}
[bold]Recommendation:[/bold] {f["recommendation"]}
""".strip(),
                        title=f["id"],
                        border_style=b_style,
                    )
                )

        repeat_web = False
        while True:
            console.print("\n[bold cyan]Post-Check Actions:[/bold cyan]")
            if findings:
                console.print("1. Run Another Web Interface Check")
                console.print("2. Explore Discovered Findings in Detail")
                console.print("3. Query MITRE CWE Threat Intelligence for Discovered Findings")
                console.print("0. Return to Main Menu")
                next_act = Prompt.ask("\n[bold green]Select an option[/bold green]", choices=["0", "1", "2", "3", "b", "B", ""], default="0", show_default=False, show_choices=False).strip()
                if next_act == "1":
                    repeat_web = True
                    break
                elif next_act == "2":
                    explore_full_assessment_findings(findings)
                elif next_act == "3":
                    prompt_cwe_query_for_findings(findings)
                else:
                    break
            else:
                console.print("1. Run Another Web Interface Check")
                console.print("0. Return to Main Menu")
                next_act = Prompt.ask("\n[bold green]Select an option[/bold green]", choices=["0", "1", "b", "B", ""], default="0", show_default=False, show_choices=False).strip()
                if next_act == "1":
                    repeat_web = True
                    break
                else:
                    break

        if not repeat_web:
            break


def run_firmware_discovery_screen() -> None:
    while True:
        clear_screen()
        show_banner()
        console.print("[bold cyan]--- Online Firmware Discovery (Path A) ---[/bold cyan]\n")

        assessment_id, asm = prompt_select_assessment_id("Select Assessment for Online Firmware Discovery")
        if not assessment_id:
            return

        device_id_default = asm.get("device_id", "Target-Device") if asm else "Target-Device"
        device_id = Prompt.ask("[bold]Device ID (or 'b' to go back)[/bold]", default=device_id_default, show_default=False).strip()
        if is_back(device_id):
            return

        dev = get_device_by_id(device_id)
        brand_default = dev.get("brand", "") if dev else ""
        model_default = dev.get("model", "") if dev else ""
        fw_default = dev.get("firmware_version", "") if dev else ""
        domain_default = asm.get("metadata", {}).get("setup_domain", "") if asm else ""

        brand = Prompt.ask("[bold]Brand (Optional, or 'b' to go back)[/bold]", default=brand_default, show_default=False).strip()
        if is_back(brand):
            return

        model = Prompt.ask("[bold]Model (Optional, or 'b' to go back)[/bold]", default=model_default, show_default=False).strip()
        if is_back(model):
            return

        firmware_version = Prompt.ask("[bold]Firmware Version (Optional, or 'b' to go back)[/bold]", default=fw_default, show_default=False).strip()
        if is_back(firmware_version):
            return

        setup_domain = Prompt.ask("[bold]Setup Domain (Optional, or 'b' to go back)[/bold]", default=domain_default, show_default=False).strip()
        if is_back(setup_domain):
            return

        vendor_clue = Prompt.ask("[bold]Vendor Clue (Optional, or 'b' to go back)[/bold]", default="").strip()
        if is_back(vendor_clue):
            return

        console.print("\n[bold]Select Discovery Source Mode:[/bold]")
        console.print("1. Automatic Online Repository & Search Index Discovery")
        console.print("2. Manual Discovery Source Entry")
        console.print("0. Back to Main Menu")

        source_choice = Prompt.ask("[bold green]Select an option[/bold green]", choices=["0", "1", "2", "b", "B"], default="1", show_default=False, show_choices=False)
        if is_back(source_choice):
            return

        manual_results = []
        if source_choice == "2":
            console.print("\nEnter discovered firmware source URLs (one per line, press Enter on empty line to finish):")
            while True:
                src_url = Prompt.ask("[bold cyan]Source URL[/bold cyan]", default="").strip()
                if not src_url:
                    break
                manual_results.append(src_url)

        console.print("\n[bold cyan]Executing online firmware discovery...[/bold cyan]")
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=None),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[bold cyan]Searching online firmware repositories...", total=100)
            progress.update(task, completed=40, description="[bold cyan]Querying search indexes and open-source firmware mirrors...")
            results = perform_online_firmware_discovery(
                device_id=device_id,
                assessment_id=assessment_id,
                brand=brand,
                model=model,
                firmware_version=firmware_version,
                vendor_clue=vendor_clue,
                setup_domain=setup_domain,
                manual_results=manual_results,
            )
            progress.update(task, completed=100, description="[bold green]Firmware discovery completed!")

        discovery = results["discovery"]
        found = discovery["found"]

        table = Table(title="Online Firmware Discovery Status", show_header=True, header_style="bold cyan")
        table.add_column("Parameter", style="cyan")
        table.add_column("Detail")

        table.add_row("Device ID", device_id)
        table.add_row("Firmware Version Tested", firmware_version or "N/A")
        table.add_row("Search Queries Evaluated", str(len(discovery.get("queries_used", []))))
        table.add_row("Discovery Status", "[green]Firmware Found[/green]" if found else "[yellow]No Public Firmware Available[/yellow]")
        table.add_row("Evidence Path", results["evidence_file"])

        console.print(table)

        if not found and discovery.get("queries_used"):
            console.print(
                Panel(
                    f"[yellow]No official firmware update package or public support portal could be identified for model clue '{brand}' version '{firmware_version}'.[/yellow]\n\n"
                    "[bold]Next Step:[/bold] If you possess a firmware dump or manufacturer binary package, you can analyze it via [cyan]Option 9: Firmware Static Analysis[/cyan].",
                    title="Firmware Availability Notice",
                    border_style="yellow",
                )
            )

        findings = results.get("findings", [])
        if findings:
            console.print(f"\n[bold red]Firmware Findings Generated ({len(findings)}):[/bold red]")
            for f in findings:
                console.print(
                    Panel(
                        f"""
[bold]Title:[/bold] {f["title"]}
[bold]Severity:[/bold] {f["severity"]} | [bold]Category:[/bold] {f["category"]}
[bold]Impact:[/bold] {f["impact"]}
[bold]Recommendation:[/bold] {f["recommendation"]}
""".strip(),
                        title=f["id"],
                        border_style="yellow",
                    )
                )

        repeat_fw_disc = False
        while True:
            console.print("\n[bold cyan]Post-Discovery Actions:[/bold cyan]")
            if findings:
                console.print("1. Search Another Firmware Source / Model")
                console.print("2. Explore Discovered Findings in Detail")
                console.print("3. Query MITRE CWE Threat Intelligence for Discovered Findings")
                console.print("0. Return to Main Menu")
                next_act = Prompt.ask("\n[bold green]Select an option[/bold green]", choices=["0", "1", "2", "3", "b", "B", ""], default="0", show_default=False, show_choices=False).strip()
                if next_act == "1":
                    repeat_fw_disc = True
                    break
                elif next_act == "2":
                    explore_full_assessment_findings(findings)
                elif next_act == "3":
                    prompt_cwe_query_for_findings(findings)
                else:
                    break
            else:
                console.print("1. Search Another Firmware Source / Model")
                console.print("0. Return to Main Menu")
                next_act = Prompt.ask("\n[bold green]Select an option[/bold green]", choices=["0", "1", "b", "B", ""], default="0", show_default=False, show_choices=False).strip()
                if next_act == "1":
                    repeat_fw_disc = True
                    break
                else:
                    break

        if not repeat_fw_disc:
            break


def run_firmware_static_analysis_screen() -> None:
    while True:
        clear_screen()
        show_banner()
        console.print("[bold cyan]--- Firmware Safe Static Analysis (Path B) ---[/bold cyan]\n")

        assessment_id, asm = prompt_select_assessment_id("Select Assessment for Firmware Static Analysis")
        if not assessment_id:
            return

        device_id_default = asm.get("device_id", "Target-Device") if asm else "Target-Device"
        device_id = Prompt.ask("[bold]Device ID (or 'b' to go back)[/bold]", default=device_id_default, show_default=False).strip()
        if is_back(device_id):
            return

        file_path_input = Prompt.ask("[bold]Enter Path to Firmware File (or 'b' to go back)[/bold]").strip()
        if is_back(file_path_input):
            return

        target_path = file_path_input

        try:
            console.print("\n[bold cyan]Running safe static analysis on firmware binary...[/bold cyan]")
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]{task.description}"),
                BarColumn(bar_width=None),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task(f"[bold cyan]Analyzing firmware binary '{target_path}'...", total=100)
                progress.update(task, completed=40, description="[bold cyan]Computing SHA-256/MD5 hashes and scanning embedded strings...")
                results = perform_firmware_static_analysis(
                    file_path=target_path,
                    device_id=device_id,
                    assessment_id=assessment_id,
                )
                progress.update(task, completed=100, description="[bold green]Firmware static analysis completed!")
        except Exception as exc:
            console.print(f"[red]Error analyzing firmware file:[/red] {exc}")
            pause()
            return

        console.print(f"\n[bold green]Static Analysis Completed Successfully![/bold green]")
        console.print(f"[bold]Evidence saved to:[/bold] {results['evidence_file']}\n")

        hashes = results["hashes"]
        file_type_info = results["file_type_info"]
        indicators = results["indicators"]

        table = Table(title=f"Firmware Static Analysis: {results['file_name']}", show_header=True, header_style="bold cyan")
        table.add_column("Property", style="cyan")
        table.add_column("Value")

        table.add_row("File Name", results["file_name"])
        table.add_row("File Size", f"{hashes['size_kb']} KB ({hashes['size_bytes']} bytes)")
        table.add_row("SHA-256 Hash", hashes["sha256"])
        table.add_row("MD5 Hash", hashes["md5"])
        table.add_row("Detected Image Type", file_type_info["detected_type"])
        if file_type_info.get("system_file_info"):
            table.add_row("System File Type", file_type_info["system_file_info"])
        table.add_row("Embedded Services", ", ".join(indicators["embedded_services"]) if indicators["embedded_services"] else "None detected")
        table.add_row("Hardcoded Credentials Detected", str(len(indicators["hardcoded_creds"])))
        table.add_row("Private Keys Detected", str(len(indicators["private_keys"])))
        table.add_row("Cryptographic Signature", "[yellow]Unsigned / No Signature Detected[/yellow]" if indicators["is_unsigned"] else "[green]Signed[/green]")

        console.print(table)

        findings = results.get("findings", [])
        if findings:
            console.print(f"\n[bold red]Static Firmware Findings Detected ({len(findings)}):[/bold red]")
            for f in findings:
                sev = f["severity"].lower()
                b_style = "red" if sev == "high" else "yellow" if "medium" in sev else "green"
                console.print(
                    Panel(
                        f"""
[bold]Title:[/bold] {f["title"]}
[bold]Severity:[/bold] {f["severity"]} | [bold]Category:[/bold] {f["category"]}
[bold]Impact:[/bold] {f["impact"]}
[bold]Recommendation:[/bold] {f["recommendation"]}
""".strip(),
                        title=f["id"],
                        border_style=b_style,
                    )
                )

        repeat_fw_static = False
        while True:
            console.print("\n[bold cyan]Post-Analysis Actions:[/bold cyan]")
            if findings:
                console.print("1. Analyze Another Firmware Binary")
                console.print("2. Explore Discovered Findings in Detail")
                console.print("3. Query MITRE CWE Threat Intelligence for Discovered Findings")
                console.print("0. Return to Main Menu")
                next_act = Prompt.ask("\n[bold green]Select an option[/bold green]", choices=["0", "1", "2", "3", "b", "B", ""], default="0", show_default=False, show_choices=False).strip()
                if next_act == "1":
                    repeat_fw_static = True
                    break
                elif next_act == "2":
                    explore_full_assessment_findings(findings)
                elif next_act == "3":
                    prompt_cwe_query_for_findings(findings)
                else:
                    break
            else:
                console.print("1. Analyze Another Firmware Binary")
                console.print("0. Return to Main Menu")
                next_act = Prompt.ask("\n[bold green]Select an option[/bold green]", choices=["0", "1", "b", "B", ""], default="0", show_default=False, show_choices=False).strip()
                if next_act == "1":
                    repeat_fw_static = True
                    break
                else:
                    break

        if not repeat_fw_static:
            break


def export_report_screen() -> None:
    """
    Redirects to the unified assessment management and report export interface.
    """
    list_assessments_screen()


def detect_network_screen() -> None:
    clear_screen()
    show_banner()
    console.print("[bold cyan]--- Select & View Network Interfaces ---[/bold cyan]\n")

    interfaces = list_all_interfaces()

    table = Table(title="Discovered Network Adapters & Routes", show_header=True, header_style="bold cyan")
    table.add_column("#", justify="center", style="cyan", no_wrap=True)
    table.add_column("Interface / Adapter Name")
    table.add_column("Local IP Address")
    table.add_column("Target Gateway IP")
    table.add_column("Subnet Mask")
    table.add_column("Route Status", justify="center")

    for idx, iface in enumerate(interfaces, start=1):
        is_def = iface.get("is_default", False)
        status_tag = "[bold green]Default Route[/bold green]" if is_def else "[white]Active[/white]"
        table.add_row(
            str(idx),
            iface.get("name", "Unknown"),
            iface.get("local_ip", "N/A"),
            iface.get("gateway_ip", "N/A"),
            str(iface.get("subnet_mask", "N/A")),
            status_tag,
        )

    console.print(table)
    pause()


def show_findings_screen() -> None:
    while True:
        clear_screen()
        show_banner()
        console.print("[bold cyan]--- Show Security Findings (Device Matrix & Threat Intelligence) ---[/bold cyan]\n")

        console.print("1. View Findings by Assessment ID")
        console.print("2. View Findings by Device ID")
        console.print("3. View All Stored Findings (Device Grid View)")
        console.print("0. Back to Main Menu")

        query_mode = Prompt.ask("[bold green]Select an option[/bold green]", choices=["0", "1", "2", "3", "b", "B"], default="1", show_default=False, show_choices=False)
        if is_back(query_mode):
            return

        findings = []
        header_title = ""

        if query_mode == "1":
            assessment_id, asm = prompt_select_assessment_id("Select Assessment to View Findings", allow_manual_input=False)
            if not assessment_id:
                return
            findings = get_findings_by_assessment_id(assessment_id)
            header_title = f"Security Findings Grid for Assessment: {assessment_id}"
            counts = count_findings_by_severity(assessment_id=assessment_id)
        elif query_mode == "2":
            device_id = Prompt.ask("[bold cyan]Enter Device ID (or 'b' to go back)[/bold cyan]", default="WR-001").strip()
            if is_back(device_id):
                return
            findings = get_findings_by_device_id(device_id)
            header_title = f"Security Findings Grid for Device: {device_id}"
            counts = count_findings_by_severity(device_id=device_id)
        else:
            findings = get_all_findings()
            header_title = "All Confirmed Security Findings by Device (Knowledge Grid View)"
            counts = count_findings_by_severity()

        if not findings:
            console.print("[yellow]No findings found matching the criteria.[/yellow]")
            pause()
            continue

        # Group findings by device
        devices_map: dict[str, list[dict[str, Any]]] = {}
        for f in findings:
            dev_id = f.get("device_id", "Unknown-Device")
            devices_map.setdefault(dev_id, []).append(f)

        clear_screen()
        show_banner()

        summary_badges = (
            f"[bold red]High: {counts.get('High', 0)}[/bold red] | "
            f"[bold yellow]Medium: {counts.get('Medium', 0)}[/bold yellow] | "
            f"[bold cyan]Low-Medium: {counts.get('Low-Medium', 0)}[/bold cyan] | "
            f"[bold green]Low: {counts.get('Low', 0)}[/bold green] | "
            f"[bold white]Info: {counts.get('Informational', 0)}[/bold white]"
        )
        console.print(Panel(summary_badges, title=f"Severity Summary ({len(findings)} total findings across {len(devices_map)} device(s))", border_style="cyan"))

        table = Table(
            title=header_title,
            show_header=True,
            header_style="bold cyan",
            show_lines=True,
        )
        table.add_column("Device Name & Scope", style="bold cyan", width=28, vertical="middle")
        table.add_column("Discovered Security Findings & Technical Details", style="white")

        flat_finding_index: list[dict[str, Any]] = []

        for dev_id, dev_findings in devices_map.items():
            dev = get_device_by_id(dev_id)
            display_name = dev.get("display_name", dev_id) if dev else dev_id
            high_c = sum(1 for f in dev_findings if f.get("severity", "").lower() in ["critical", "high"])
            med_c = sum(1 for f in dev_findings if "medium" in f.get("severity", "").lower())
            low_c = len(dev_findings) - high_c - med_c

            dev_info = (
                f"[bold cyan]{dev_id}[/bold cyan]\n"
                f"[white]{display_name}[/white]\n\n"
                f"[dim]Total:[/dim] {len(dev_findings)} finding(s)\n"
                f"[{ 'red' if high_c else 'dim' }]{high_c} High[/{ 'red' if high_c else 'dim' }] | "
                f"[{ 'yellow' if med_c else 'dim' }]{med_c} Med[/{ 'yellow' if med_c else 'dim' }] | "
                f"[{ 'green' if low_c else 'dim' }]{low_c} Low[/{ 'green' if low_c else 'dim' }]"
            )

            findings_lines = []
            for f in dev_findings:
                flat_finding_index.append(f)
                idx = len(flat_finding_index)
                sev = f.get("severity", "Medium")
                sev_color = "red" if sev.lower() in ["critical", "high"] else "yellow" if "medium" in sev.lower() else "green"
                cwe_str = f.get("cwe", "")
                cwe_part = f" | [cyan]{cwe_str}[/cyan]" if cwe_str else ""
                module_part = f.get("module", "General")
                impact_str = f.get("impact", "")

                line = (
                    f"[bold cyan]{idx}.[/bold cyan] [{sev_color}][{sev.upper()}][/{sev_color}] [bold]{f.get('id', '')}:[/bold] {f.get('title', '')}\n"
                    f"   [dim]Layer: {module_part}{cwe_part}[/dim]\n"
                    f"   [yellow]Threat Impact:[/yellow] {impact_str}"
                )
                findings_lines.append(line)

            table.add_row(dev_info, "\n\n".join(findings_lines))

        console.print(table)

        # Interactive drill-down / options
        range_desc = f"1-{len(flat_finding_index)}" if len(flat_finding_index) > 1 else "1"
        console.print("\n[bold]Options:[/bold]")
        console.print(f"  [bold cyan]{range_desc:<4}[/bold cyan] : View full threat modeling & mitigation details for a finding")
        console.print(f"  [bold cyan]{'Q':<4}[/bold cyan] : Query MITRE CWE threat intelligence for these findings")
        console.print(f"  [bold cyan]{'0':<4}[/bold cyan] : Return to previous menu")

        while True:
            choice = Prompt.ask("\n[bold green]Select an option[/bold green]", default="0", show_default=False).strip()

            if is_back(choice) or choice == "0":
                return
            elif choice.upper() == "Q":
                prompt_cwe_query_for_findings(flat_finding_index)
                break
            else:
                try:
                    selected_idx = int(choice) - 1
                    if 0 <= selected_idx < len(flat_finding_index):
                        f_item = flat_finding_index[selected_idx]
                        clear_screen()
                        show_banner()
                        render_finding_detail(f_item, index=selected_idx + 1)
                        Prompt.ask("\n[bold cyan]Press Enter to return to findings grid[/bold cyan]", default="")
                        break
                    else:
                        console.print(f"[red]Invalid choice. Enter {range_desc}, 'Q', or '0'.[/red]")
                except ValueError:
                    console.print(f"[red]Invalid choice. Enter {range_desc}, 'Q', or '0'.[/red]")


def calculate_score_screen() -> None:
    while True:
        clear_screen()
        show_banner()
        console.print("[bold cyan]--- Security Score & Price-to-Security Evaluation ---[/bold cyan]\n")

        console.print("1. Calculate Score for Assessment ID")
        console.print("2. Calculate Score for Device ID")
        console.print("0. Back to Main Menu")

        calc_choice = Prompt.ask("[bold green]Select an option[/bold green]", choices=["0", "1", "2", "b", "B"], default="1", show_default=False, show_choices=False)
        if is_back(calc_choice):
            return

        device_id = None
        assessment_id = None
        price_override = None

        if calc_choice == "1":
            assessment_id, asm = prompt_select_assessment_id("Select Assessment to Calculate Score & PSR", allow_manual_input=False)
            if not assessment_id:
                return
            stored_price = asm.get("price_lkr") if asm else None
            if stored_price and stored_price > 0:
                console.print(f"\n[green]Using recorded assessment price:[/green] [bold]LKR {stored_price:,}[/bold]")
                price_override = stored_price
            else:
                console.print(f"\n[yellow]Notice: No purchase price recorded for assessment {assessment_id}. A purchase price is required to calculate the score and Price-to-Security Ratio (PSR).[/yellow]")
                while True:
                    price_input_str = Prompt.ask("[bold]Enter Purchase Price in LKR (or 'b' to cancel)[/bold]").strip()
                    if is_back(price_input_str) or not price_input_str:
                        console.print("[yellow]Calculation cancelled: Purchase price is required.[/yellow]")
                        pause()
                        return
                    try:
                        val = int(price_input_str)
                        if val > 0:
                            price_override = val
                            update_assessment(assessment_id, price_lkr=val)
                            break
                        else:
                            console.print("[red]Price must be a valid number greater than 0.[/red]")
                    except ValueError:
                        console.print("[red]Price must be a valid number greater than 0.[/red]")
        else:
            device_id = Prompt.ask("[bold cyan]Enter Device ID (or 'b' to go back)[/bold cyan]").strip()
            if is_back(device_id) or not device_id:
                return
            dev = get_device_by_id(device_id)
            stored_price = dev.get("price_lkr") if dev else None
            if stored_price and stored_price > 0:
                console.print(f"\n[green]Using recorded catalog price:[/green] [bold]LKR {stored_price:,}[/bold]")
                price_override = stored_price
            else:
                console.print(f"\n[yellow]Notice: No purchase price recorded for {device_id}. A purchase price is required to calculate the score and Price-to-Security Ratio (PSR).[/yellow]")
                while True:
                    price_input_str = Prompt.ask("[bold]Enter Purchase Price in LKR (or 'b' to cancel)[/bold]").strip()
                    if is_back(price_input_str) or not price_input_str:
                        console.print("[yellow]Calculation cancelled: Purchase price is required.[/yellow]")
                        pause()
                        return
                    try:
                        val = int(price_input_str)
                        if val > 0:
                            price_override = val
                            break
                        else:
                            console.print("[red]Price must be a valid number greater than 0.[/red]")
                    except ValueError:
                        console.print("[red]Price must be a valid number greater than 0.[/red]")

        console.print("\n[bold cyan]Calculating security metrics and recommendation...[/bold cyan]\n")
        eval_res = evaluate_device_security(
            device_id=device_id,
            assessment_id=assessment_id,
            custom_price=price_override,
        )

        score = eval_res["final_score"]
        risk = eval_res["risk_level"]
        psr = eval_res["psr"]
        rec = eval_res["recommendation"]
        price = eval_res["price_lkr"]

        risk_color = "red" if risk in ["Critical", "High"] else "yellow" if risk == "Medium" else "green"

        summary_text = f"""
[bold]Target / Device:[/bold]        {eval_res['device_or_assessment']}
[bold]Purchase Price:[/bold]         LKR {price}
[bold]Findings Evaluated:[/bold]     {eval_res['findings_count']} ({eval_res['severity_counts'].get('High', 0)} High, {eval_res['severity_counts'].get('Medium', 0)} Med, {eval_res['severity_counts'].get('Low-Medium', 0)} Low-Med)

[bold]Base Score:[/bold]             {eval_res['base_score']}/100
[bold]Total Deductions:[/bold]       -{eval_res['total_deductions']} points
[bold]Final Security Score:[/bold]   [{risk_color}]{score}/100[/{risk_color}]
[bold]Risk Level:[/bold]             [{risk_color}]{risk}[/{risk_color}]
[bold]Price-to-Security (PSR):[/bold] {psr} (Baseline: LKR 15,000)

[bold]Recommendation Category:[/bold]
[bold {risk_color}]{rec['category']}[/bold {risk_color}]

[bold]Evaluation & Guidance:[/bold]
{rec['guidance']}
"""
        console.print(Panel(summary_text.strip(), title=f"Security Evaluation Scorecard: {eval_res['device_or_assessment']}", border_style=risk_color))

        deductions = eval_res.get("deductions_detail", [])
        if deductions:
            ded_table = Table(title="Score Deductions Breakdown", show_header=True, header_style="bold cyan")
            ded_table.add_column("Finding ID", style="cyan")
            ded_table.add_column("Severity", justify="center")
            ded_table.add_column("Points Deducted", justify="right", style="red")
            ded_table.add_column("Vulnerability Title")

            for d in deductions:
                ded_table.add_row(
                    d.get("finding_id", ""),
                    d.get("severity", ""),
                    f"-{d.get('deduction', 0)}",
                    d.get("title", ""),
                )
            console.print(ded_table)

        mitigations = rec.get("mitigations", [])
        if mitigations:
            console.print("\n[bold cyan]Recommended Mitigation & Hardening Steps:[/bold cyan]")
            for idx, m in enumerate(mitigations, 1):
                console.print(f"  [bold]{idx}.[/bold] {m}")

        console.print("\n[bold cyan]Post-Evaluation Actions:[/bold cyan]")
        console.print("1. Calculate Score for Another Device / Assessment")
        console.print("0. Return to Main Menu")

        next_act = Prompt.ask("\n[bold green]Select an option[/bold green]", choices=["0", "1", "b", "B", ""], default="0", show_default=False, show_choices=False).strip()
        if next_act != "1":
            break


def list_devices_screen() -> None:
    clear_screen()
    show_banner()

    devices = get_all_devices()

    table = Table(title="Assessed Wi-Fi Repeaters & Comparison Benchmarks", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Device")
    table.add_column("Brand")
    table.add_column("Firmware")
    table.add_column("Score", justify="right")
    table.add_column("Risk", justify="center")
    table.add_column("Recommendation")

    for device in devices:
        table.add_row(
            device["id"],
            device["display_name"],
            device["brand"],
            device["firmware_version"],
            str(device["security_score"]),
            device["risk_level"],
            device["recommendation"],
        )

    console.print(table)
    pause()


def search_device_screen() -> None:
    clear_screen()
    show_banner()

    keyword = Prompt.ask("[bold cyan]Enter brand, model, firmware or keyword to search (or 'b' to go back)[/bold cyan]").strip()
    if is_back(keyword):
        return

    keyword_lower = keyword.lower()
    devices = get_all_devices()
    matched_devices = []

    for device in devices:
        searchable_text = " ".join(
            [
                device.get("id", ""),
                device.get("display_name", ""),
                device.get("brand", ""),
                device.get("model", ""),
                device.get("firmware_version", ""),
                device.get("mac_vendor", ""),
                device.get("summary", ""),
            ]
        ).lower()

        if keyword_lower in searchable_text:
            matched_devices.append(device)

    if not matched_devices:
        console.print(f"\n[red]No devices found for keyword:[/red] {keyword}")
        pause()
        return

    table = Table(title=f"Search Results for '{keyword}'", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Device")
    table.add_column("Brand")
    table.add_column("Firmware")
    table.add_column("Risk")
    table.add_column("Recommendation")

    for device in matched_devices:
        table.add_row(
            device["id"],
            device["display_name"],
            device["brand"],
            device["firmware_version"],
            device["risk_level"],
            device["recommendation"],
        )

    console.print(table)
    pause()


def show_device_details_screen() -> None:
    clear_screen()
    show_banner()

    device_id = Prompt.ask("[bold cyan]Enter Device ID (or 'b' to go back)[/bold cyan]").strip()
    if is_back(device_id) or not device_id:
        return

    device = get_device_by_id(device_id)
    if device is None:
        console.print(f"[red]Device not found:[/red] {device_id}")
        pause()
        return

    details = f"""
[bold]Device ID:[/bold] {device["id"]}
[bold]Display Name:[/bold] {device["display_name"]}
[bold]Brand:[/bold] {device["brand"]}
[bold]Model:[/bold] {device["model"]}
[bold]Firmware Version:[/bold] {device["firmware_version"]}
[bold]MAC Vendor:[/bold] {device["mac_vendor"]}
[bold]Price:[/bold] LKR {device["price_lkr"]}
[bold]Purchase Source:[/bold] {device["purchase_source"]}

[bold]Security Score:[/bold] {device["security_score"]}/100
[bold]Risk Level:[/bold] {device["risk_level"]}
[bold]Recommendation:[/bold] {device["recommendation"]}

[bold]Summary:[/bold]
{device["summary"]}
"""

    console.print(Panel(details.strip(), title=f"Device Report: {device['id']}", border_style="cyan"))

    findings = get_findings_by_device_id(device["id"])
    if findings:
        console.print(f"\n[bold red]Confirmed Security Vulnerabilities for {device['id']} ({len(findings)} found):[/bold red]")
        f_table = Table(title=f"Vulnerabilities Identified for {device['id']}", show_header=True, header_style="bold cyan")
        f_table.add_column("Finding ID", style="cyan", no_wrap=True)
        f_table.add_column("Severity", justify="center")
        f_table.add_column("Module")
        f_table.add_column("Title")
        f_table.add_column("Status", justify="center")
        for f in findings:
            f_table.add_row(
                f.get("id", ""),
                f.get("severity", ""),
                f.get("module", "General"),
                f.get("title", ""),
                f.get("status", "Confirmed"),
            )
        console.print(f_table)
    else:
        console.print(f"\n[yellow]No security findings recorded for device {device['id']} yet. Run a live assessment to probe its open ports and web interface.[/yellow]")

    pause()


def compare_devices_screen() -> None:
    clear_screen()
    show_banner()

    first_id = Prompt.ask("[bold cyan]Enter first Device ID (or 'b' to go back)[/bold cyan]").strip()
    if is_back(first_id) or not first_id:
        return

    second_id = Prompt.ask("[bold cyan]Enter second Device ID (or 'b' to go back)[/bold cyan]").strip()
    if is_back(second_id) or not second_id:
        return

    first_device = get_device_by_id(first_id)
    second_device = get_device_by_id(second_id)

    if first_device is None:
        console.print(f"[red]First device not found:[/red] {first_id}")
        pause()
        return

    if second_device is None:
        console.print(f"[red]Second device not found:[/red] {second_id}")
        pause()
        return

    table = Table(title=f"Device Security Comparison: {first_device['id']} vs {second_device['id']}", show_header=True, header_style="bold cyan")
    table.add_column("Field", style="cyan")
    table.add_column(f"{first_device['id']} ({first_device['display_name']})")
    table.add_column(f"{second_device['id']} ({second_device['display_name']})")

    table.add_row("Brand", first_device["brand"], second_device["brand"])
    table.add_row("Model", first_device.get("model", ""), second_device.get("model", ""))
    table.add_row("Firmware Version", first_device["firmware_version"], second_device["firmware_version"])
    table.add_row("Price", f"LKR {first_device['price_lkr']}", f"LKR {second_device['price_lkr']}")
    table.add_row("Security Score", f"{first_device['security_score']}/100", f"{second_device['security_score']}/100")
    table.add_row("Risk Level", first_device["risk_level"], second_device["risk_level"])
    table.add_row("Recommendation", first_device["recommendation"], second_device["recommendation"])

    console.print(table)
    pause()


def recommend_device_screen() -> None:
    clear_screen()
    show_banner()

    budget_input = Prompt.ask("[bold cyan]Enter your budget in LKR (or 'b' to go back)[/bold cyan]", default="5000").strip()
    if is_back(budget_input):
        return

    try:
        budget = int(budget_input)
    except ValueError:
        budget = 5000

    devices = get_all_devices()
    affordable_devices = []

    for device in devices:
        if int(device["price_lkr"]) <= budget:
            affordable_devices.append(device)

    if not affordable_devices:
        console.print(f"[red]No devices found under LKR {budget}[/red]")
        pause()
        return

    affordable_devices.sort(key=lambda item: item["security_score"], reverse=True)

    table = Table(title=f"Recommended Devices Under LKR {budget}", show_header=True, header_style="bold cyan")
    table.add_column("Rank", justify="center", style="cyan")
    table.add_column("ID")
    table.add_column("Device")
    table.add_column("Price")
    table.add_column("Score")
    table.add_column("Risk")
    table.add_column("Recommendation")

    for index, device in enumerate(affordable_devices, start=1):
        table.add_row(
            str(index),
            device["id"],
            device["display_name"],
            f"LKR {device['price_lkr']}",
            f"{device['security_score']}/100",
            device["risk_level"],
            device["recommendation"],
        )

    console.print(table)
    pause()


def help_screen() -> None:
    """
    Interactive In-System User Guide and Technical Reference.
    """
    while True:
        clear_screen()
        show_banner()
        console.print("[bold cyan]--- WiFiRisk In-System User Guide & Reference Manual ---[/bold cyan]\n")
        console.print("Select a topic to explore comprehensive instructions, workflows and formulas:\n")

        console.print("  [bold cyan]1.[/bold cyan] Quick Start Guide (Assess your repeater in 2 minutes)")
        console.print("  [bold cyan]2.[/bold cyan] Scanning Workflows (Quick Live Scan vs Full Assessment)")
        console.print("  [bold cyan]3.[/bold cyan] Individual Testing Modules Guide (Network, DNS, Web, Firmware)")
        console.print("  [bold cyan]4.[/bold cyan] 100-Point Scoring Engine & Price-to-Security Ratio (PSR)")
        console.print("  [bold cyan]5.[/bold cyan] Threat Modeling & Vulnerability Matrix (HTTP, DNS, Telnet)")
        console.print("  [bold cyan]6.[/bold cyan] Academic Report Generation (Markdown, TXT, DOCX)")
        console.print("  [bold cyan]7.[/bold cyan] Safe Lab Setup, Ethics & Target Interface Selection")
        console.print("  [bold cyan]8.[/bold cyan] Headless CLI Commands & Automation Reference")
        console.print("  [bold cyan]A.[/bold cyan] Read Complete User Manual")
        console.print("  [bold cyan]0.[/bold cyan] Return to Main Menu")

        choice = Prompt.ask("\n[bold green]Select an option[/bold green]", default="0", show_default=False).strip()

        if choice in ["0", "b", "B", "", "quit", "exit"]:
            break

        clear_screen()
        show_banner()

        if choice == "1":
            guide_content = """
[bold cyan]1. Quick Start Guide (2-Minute Assessment)[/bold cyan]

[bold]Step 1: Connect to the Repeater[/bold]
Connect your testing laptop to the Wi-Fi repeater via Wi-Fi or an Ethernet cable.

[bold]Step 2: Launch WiFiRisk[/bold]
In PowerShell or Terminal, run:
[green]python -m wifi_risk[/green]

[bold]Step 3: Run Option 1 (Quick Vulnerability Check)[/bold]
- The tool automatically detects your active network adapter and gateway IP.
- Press [bold]Enter[/bold] to confirm the gateway IP.
- Watch the live progress bar probe management ports, DNS and web interfaces.

[bold]Step 4: Explore Discovered Exposures[/bold]
- Review the summary scorecard and open ports table.
- Type [bold]1..N[/bold] or [bold]A[/bold] on the final screen to explore vulnerability details, threat vectors and remediation steps.
"""
            console.print(Panel(guide_content.strip(), title="Topic 1: Quick Start Guide", border_style="cyan"))

        elif choice == "2":
            guide_content = """
[bold cyan]2. Scanning Workflows: Quick Scan vs Full Assessment[/bold cyan]

[bold]Option 1: Quick Live Vulnerability Check[/bold]
- [bold]Purpose:[/bold] Rapid, non-destructive live network check.
- [bold]Database Interaction:[/bold] Standalone (does not create database records or deduct scores).
- [bold]Best For:[/bold] Initial triage, verifying open ports (FTP, SSH, Telnet, HTTP, DNS) and checking if web management is exposed.

[bold]Option 2: Full In-Depth Security Assessment[/bold]
- [bold]Purpose:[/bold] Analyze the price-to-value ratio and Price-to-Security Ratio (PSR), conduct comprehensive multi-layer vulnerability auditing and generate academic research documentation.
- [bold]Pipeline Stages:[/bold]
  1. Target IP and Interface Resolution
  2. Network Discovery (TCP port audit and banner capture)
  3. DNS Behavior Checks (setup domain resolution and upstream leakage)
  4. Web Interface Checks (HTML inspection, hardcoded credentials and cookie audit)
  5. Online Firmware Scraping (public vendor update search)
  6. Firmware Static Binary Analysis (optional SHA-256 hashes, string analysis)
  7. 100-Point Scoring Deduction and Price-to-Security (PSR) Value Computation
  8. Multi-format Report Export (Markdown, TXT, DOCX)
"""
            console.print(Panel(guide_content.strip(), title="Topic 2: Scanning Workflows", border_style="cyan"))

        elif choice == "3":
            guide_content = """
[bold cyan]3. Individual Testing Modules Guide (Options 5 - 9)[/bold cyan]

[bold]Option 5: Network Discovery[/bold]
- Probes management ports using Python sockets or Nmap.
- Supports pasting raw Nmap text or importing scan files from other tools.

[bold]Option 6: DNS Behavior Checks[/bold]
- Tests setup domain resolution and captive redirection.
- Compares responses against control domains (google.com) to detect captive redirection and upstream DNS leakage.

[bold]Option 7: Web Interface Checks[/bold]
- Fetches router login HTML and parses form elements.
- Checks for hardcoded credentials, unencrypted cookies (missing HttpOnly/Secure) and missing logout mechanisms.
- Supports guided manual observation confirmation.

[bold]Option 8: Online Firmware Discovery (Path A)[/bold]
- Queries vendor support repositories to verify if firmware update packages are publicly accessible.

[bold]Option 9: Firmware Safe Static Analysis (Path B)[/bold]
- Inspects uploaded firmware binaries (.bin, .trx, .img).
- Computes SHA-256/MD5 hashes, detects embedded services and extracts hardcoded credentials without executing untrusted code.
"""
            console.print(Panel(guide_content.strip(), title="Topic 3: Individual Testing Modules", border_style="cyan"))

        elif choice == "4":
            guide_content = """
[bold cyan]4. 100-Point Scoring Engine & Price-to-Security Ratio (PSR)[/bold cyan]

[bold]100-Point Security Deduction Formula:[/bold]
Every device starts with a clean baseline of 100 points. Points are deducted based on verified vulnerabilities:

  [bold]Final Score = max(0, 100 - Total Deductions)[/bold]

  - [bold red]Critical Finding:[/bold red]   -15 points (Remote root execution)
  - [bold red]High Finding:[/bold red]       -12 points (Exposed Telnet, hardcoded admin in HTML)
  - [bold yellow]Medium Finding:[/bold yellow]     -8 points (Unencrypted HTTP management, exposed FTP)
  - [bold yellow]Low-Medium Finding:[/bold yellow] -5 points (Exposed DNS resolver, missing logout)
  - [bold cyan]Low Finding:[/bold cyan]        -3 points (Verbose server headers)
  - [bold white]Informational:[/bold white]      -1 point (Generic banner notice)

[bold]Risk Level Tiers:[/bold]
  - [bold green]85 - 100:[/bold green] Low Risk (Secure configuration)
  - [bold yellow]65 - 84:[/bold yellow]  Medium Risk (Moderate exposures)
  - [bold red]40 - 64:[/bold red]  High Risk (Severe plaintext exposures)
  - [bold red]0 - 39:[/bold red]   Critical Risk (Do not deploy)

[bold]Price-to-Security Ratio (PSR):[/bold]
Evaluates economic security quality against a premium baseline device (LKR 15,000):

  [bold]PSR = (Security Score / 100) / (Device Price / 15000)[/bold]

  - [bold green]PSR > 3.0:[/bold green] High security value per rupee spent.
  - [bold yellow]PSR 1.0 - 3.0:[/bold yellow] Fair security value.
  - [bold red]PSR < 1.0:[/bold red] Poor security value relative to cost.
"""
            console.print(Panel(guide_content.strip(), title="Topic 4: Scoring & PSR Mathematics", border_style="cyan"))

        elif choice == "5":
            guide_content = """
[bold cyan]5. Threat Modeling & Vulnerability Matrix[/bold cyan]

[bold]1. Unencrypted HTTP Management (80/TCP):[/bold]
- [bold]Weaknesses:[/bold] CWE-319, CWE-352, CWE-306
- [bold]Threat Scenario:[/bold] Man-in-the-Middle credential sniffing over shared Wi-Fi and Cross-Site Request Forgery (CSRF) router reconfiguration.
- [bold]Fix:[/bold] Enforce HTTPS with TLS 1.2/1.3, HSTS headers and anti-CSRF form tokens.

[bold]2. Exposed DNS Resolver (53/TCP):[/bold]
- [bold]Weaknesses:[/bold] CWE-345, CWE-400, CVE-2020-25681 (DNSpooq)
- [bold]Threat Scenario:[/bold] DNS cache poisoning and forged DNS response flooding redirecting client traffic to phishing portals.
- [bold]Fix:[/bold] Upgrade dnsmasq to >= 2.83, bind resolver strictly to LAN and enable DNSSEC.

[bold]3. Exposed Telnet Service (23/TCP):[/bold]
- [bold]Weaknesses:[/bold] CWE-319, CWE-798, CWE-307
- [bold]Threat Scenario:[/bold] Automated Mirai-style botnet brute-forcing and cleartext shell credential capture.
- [bold]Fix:[/bold] Disable Telnet daemon in firmware and replace with SSH key-based authentication.

[bold]4. Hardcoded Admin Credentials in HTML:[/bold]
- [bold]Weaknesses:[/bold] CWE-798, CWE-200
- [bold]Threat Scenario:[/bold] Unauthenticated administrative takeover via webpage source code inspection.
- [bold]Fix:[/bold] Remove hardcoded credentials from templates and enforce unique factory passwords.
"""
            console.print(Panel(guide_content.strip(), title="Topic 5: Threat Modeling & Vulnerabilities", border_style="cyan"))

        elif choice == "6":
            guide_content = """
[bold cyan]6. Academic Report Generation (.md, .txt, .docx)[/bold cyan]

WiFiRisk automatically formats audit reports for direct inclusion in research papers and academic dissertations:

[bold]Exporting Reports (Option 12 or Post-Assessment):[/bold]
- [bold]Markdown (.md):[/bold] GitHub Flavored Markdown with scorecard tables and vulnerability checklists.
- [bold]Plain Text (.txt):[/bold] Clean, aligned ASCII tables suitable for text editors and terminal viewing.
- [bold]Microsoft Word (.docx):[/bold] Professionally styled document with headings, metadata tables, color-coded scorecards and academic attribution (COM4901, KIU).

Reports are saved to the [bold cyan]reports/[/bold cyan] directory.
"""
            console.print(Panel(guide_content.strip(), title="Topic 6: Report Generation", border_style="cyan"))

        elif choice == "7":
            guide_content = """
[bold cyan]7. Safe Lab Setup & Testing Ethics[/bold cyan]

[bold]Ethical Testing Notice:[/bold]
- Perform assessments [bold]ONLY[/bold] on Wi-Fi repeaters and network devices that you own or have explicit authorization to audit.
- Do not run scans against public networks or unauthorized third-party gateways.

[bold]Recommended Lab Setup:[/bold]
1. Isolate the target Wi-Fi repeater on a dedicated test network.
2. Connect your testing laptop directly to the repeater's wireless SSID or LAN Ethernet port.
3. Use Option 13 (Select & View Network Interfaces) to verify that your active interface points to the repeater's gateway IP before initiating scans.
"""
            console.print(Panel(guide_content.strip(), title="Topic 7: Safe Lab Setup & Ethics", border_style="cyan"))

        elif choice == "8":
            guide_content = """
[bold cyan]8. Headless CLI Subcommands & Automation[/bold cyan]

Run WiFiRisk directly from command-line scripts or CI pipelines without the interactive UI:

[bold]1. Execute Full Assessment:[/bold]
[green]python -m wifi_risk run --target-ip 192.168.11.1 --device-id WR-001 --price 2500[/green]

[bold]2. Export Reports:[/bold]
[green]python -m wifi_risk export --assessment-id ASM-001 --format all[/green]

[bold]3. Score a Device:[/bold]
[green]python -m wifi_risk score --device-id WR-001 --price 2500[/green]

[bold]4. List Detected Interfaces:[/bold]
[green]python -m wifi_risk interfaces[/green]

[bold]5. List Cataloged Devices:[/bold]
[green]python -m wifi_risk devices[/green]

[bold]6. Query Live MITRE CWE Intelligence:[/bold]
[green]python -m wifi_risk cwe 345[/green]
[green]python -m wifi_risk cwe 319 --online[/green]
"""
            console.print(Panel(guide_content.strip(), title="Topic 8: Headless CLI Commands", border_style="cyan"))

        elif choice.upper() == "A":
            full_manual = """
[bold cyan]WiFiRisk Complete User Manual[/bold cyan]

[bold]Academic Context:[/bold]
COM4901 Final Year Individual Research Project at KIU
Student: W.M.D.C.D.S Weerakoon (ID: 11161)

[bold]Navigation Tip:[/bold]
Type 'b', 'back' or '0' at any prompt to cancel an operation and return to the Main Menu.

[bold]Workflow Summary:[/bold]
1. Use [bold]Option 1[/bold] for quick live vulnerability auditing.
2. Use [bold]Option 2[/bold] for full in-depth assessments and report generation.
3. Use [bold]Options 5-9[/bold] for granular testing of specific service layers.
4. Use [bold]Option 12[/bold] to export Word, Markdown and Text documentation.
5. Use [bold]Option 17[/bold] to compare repeater security postures.
6. Use [bold]Option 20[/bold] to query live MITRE CWE taxonomy and threat intelligence.
"""
            console.print(Panel(full_manual.strip(), title="Complete User Manual", border_style="cyan"))

        Prompt.ask("\n[bold cyan]Press Enter to return to Guide Topics[/bold cyan]", default="")


def render_cwe_detail_panel(cwe_data: dict[str, Any]) -> None:
    """
    Render a comprehensive panel for a MITRE CWE entry with live intelligence and threat modeling.
    """
    cwe_id = cwe_data.get("id", "CWE-Unknown")
    name = cwe_data.get("name", "Unknown Weakness")
    abstraction = cwe_data.get("abstraction", "Weakness")
    status = cwe_data.get("status", "Active")
    source = cwe_data.get("source", "local_catalog")
    desc = cwe_data.get("description", "No description available.")
    scenarios = cwe_data.get("threat_scenarios", [])
    components = cwe_data.get("affected_components", [])
    mitigation = cwe_data.get("mitigation", "Follow standard defensive programming and device hardening guidelines.")
    related_cves = cwe_data.get("related_cves", [])
    mitre_url = cwe_data.get("mitre_url", "")

    scenarios_text = "\n".join([f"• {s}" for s in scenarios]) if scenarios else "Standard threat modeling scenarios apply."
    comp_text = ", ".join(components) if components else "Network Services & Embedded Firmware"
    cve_text = ", ".join(related_cves) if related_cves else "General vulnerability advisory mappings"

    src_badge = "[bold green]Live MITRE Feed[/bold green]" if "live" in source else "[bold cyan]Local Knowledge Catalog[/bold cyan]"

    content = f"""
[bold]Weakness Identifier:[/bold] [bold cyan]{cwe_id}[/bold cyan]
[bold]Official MITRE Title:[/bold] {name}
[bold]Weakness Abstraction:[/bold] {abstraction} ({status})
[bold]Data Source:[/bold]          {src_badge}
[bold]MITRE Reference:[/bold]      {mitre_url}

[bold magenta]Official Weakness Description:[/bold magenta]
{desc}

[bold red]Threat Modeling & Attack Scenarios:[/bold red]
{scenarios_text}

[bold yellow]Affected Repeater / IoT Components:[/bold yellow]
{comp_text}

[bold green]Recommended Security Mitigation:[/bold green]
{mitigation}

[bold blue]Related Vulnerability Advisories (CVEs):[/bold blue]
{cve_text}
"""
    console.print(Panel(content.strip(), title=f"MITRE Threat Intelligence: {cwe_id}", border_style="cyan"))


def _execute_cwe_lookup_with_feedback(raw_cwe: str) -> None:
    """
    Execute CWE lookup with clear user feedback before performing internet queries.
    """
    cwe_id = normalize_cwe_id(raw_cwe)
    catalog = load_cwe_catalog()

    if cwe_id in catalog:
        console.print(f"\n[bold green]✓ Found '{cwe_id}' in Local Knowledge Catalog.[/bold green]")
        check_online = Confirm.ask(
            "Would you like to connect to the internet to check for the latest MITRE / NIST live updates?",
            default=False,
        )
        if check_online:
            console.print("\n[bold yellow]Notice: Fetching live intelligence from MITRE Corporation (cwe.mitre.org) and NIST NVD requires an active internet connection.[/bold yellow]")
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]{task.description}"),
                BarColumn(bar_width=None),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task(f"[bold cyan]Connecting to cwe.mitre.org for {cwe_id}...", total=100)
                progress.update(task, completed=40, description="[bold cyan]Fetching official MITRE definition and CVE mappings...")
                res = query_cwe_intelligence(cwe_id, force_online=True)
                progress.update(task, completed=100, description="[bold green]MITRE intelligence fetch completed!")

            render_cwe_detail_panel(res)
        else:
            res = query_cwe_intelligence(cwe_id, force_online=False)
            render_cwe_detail_panel(res)
    else:
        console.print(f"\n[bold yellow]Notice: '{cwe_id}' is not present in the local catalog.[/bold yellow]")
        console.print("[bold yellow]The system will query online repositories (cwe.mitre.org / NIST NVD). Please ensure you have an active internet connection.[/bold yellow]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=None),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(f"[bold cyan]Connecting to cwe.mitre.org for {cwe_id}...", total=100)
            progress.update(task, completed=40, description="[bold cyan]Querying live MITRE taxonomy feed...")
            res = query_cwe_intelligence(cwe_id, force_online=True)
            progress.update(task, completed=100, description="[bold green]Online intelligence query completed!")

        if res.get("success", False):
            console.print(f"[bold green]✓ Successfully fetched live definition for {cwe_id} from MITRE and saved to local catalog![/bold green]\n")
            render_cwe_detail_panel(res)
        else:
            console.print(f"[red]Unable to fetch definition for '{cwe_id}'. Please verify the CWE ID or check your internet connectivity.[/red]")

    Prompt.ask("\n[bold cyan]Press Enter to return[/bold cyan]", default="")


def prompt_cwe_query_for_findings(findings_or_alerts: list[dict[str, Any]]) -> None:
    """
    Interactive post-scan workflow allowing researchers to query official MITRE CWE intelligence
    for vulnerabilities discovered in the current scan, with online querying and clear feedback.
    """
    if not findings_or_alerts:
        console.print("[yellow]No security findings or alerts to query.[/yellow]")
        return

    extracted = extract_cwes_from_items(findings_or_alerts)

    while True:
        clear_screen()
        show_banner()
        console.print("[bold cyan]--- MITRE CWE & Threat Intelligence Query for Discovered Vulnerabilities ---[/bold cyan]\n")
        console.print("Select a discovered CWE weakness from this scan or enter any custom CWE ID.\n")

        if extracted:
            console.print("[bold]Discovered Weaknesses in Current Scan:[/bold]")
            for idx, item in enumerate(extracted, 1):
                cat_badge = "[green][Local Catalog][/green]" if item["in_local_catalog"] else "[yellow][Live Online Query][/yellow]"
                titles_str = f" ({', '.join(item['titles'][:2])})" if item["titles"] else ""
                console.print(f"  [bold cyan]{idx}.[/bold cyan] [bold]{item['cwe_id']}[/bold] {cat_badge} - {item['name']}{titles_str}")

            range_desc = f"1-{len(extracted)}" if len(extracted) > 1 else "1"
            console.print("\n[bold]Options:[/bold]")
            console.print(f"  [bold cyan]{range_desc:<4}[/bold cyan] : Query MITRE intelligence for a discovered CWE above")
        else:
            console.print("[dim]No specific CWE identifiers found in scan records.[/dim]")
            console.print("\n[bold]Options:[/bold]")

        console.print(f"  [bold cyan]{'C':<4}[/bold cyan] : Enter custom CWE ID directly")
        console.print(f"  [bold cyan]{'S':<4}[/bold cyan] : Search online and local CWEs by keyword")
        console.print(f"  [bold cyan]{'0':<4}[/bold cyan] : Return to previous menu")

        choice = Prompt.ask(
            "\n[bold green]Select an option[/bold green]",
            default="0",
            show_default=False,
        ).strip()

        if choice in ["0", "b", "B", "", "quit", "exit"]:
            break
        elif choice.upper() == "C":
            custom_id = Prompt.ask("\n[bold cyan]Enter CWE ID to query (or 'b' to cancel)[/bold cyan]").strip()
            if custom_id and not is_back(custom_id):
                _execute_cwe_lookup_with_feedback(custom_id)
        elif choice.upper() == "S":
            kw = Prompt.ask("\n[bold cyan]Enter keyword to search (or 'b' to cancel)[/bold cyan]").strip()
            if kw and not is_back(kw):
                results = search_cwe_catalog(kw)
                if results:
                    table = Table(title=f"CWE Matches for '{kw}'", show_header=True, header_style="bold cyan")
                    table.add_column("CWE ID", style="cyan", no_wrap=True)
                    table.add_column("Official Title")
                    table.add_column("Key Affected Component")
                    for r in results:
                        comp = r.get("affected_components", ["General"])
                        table.add_row(r.get("id", ""), r.get("name", ""), comp[0] if comp else "General")
                    console.print(table)

                    detail_pick = Prompt.ask("\nEnter CWE ID from list to view details (or press Enter to return)", default="").strip()
                    if detail_pick and not is_back(detail_pick):
                        _execute_cwe_lookup_with_feedback(detail_pick)
                else:
                    console.print(f"[yellow]No local results found for '{kw}'. You can query online using option 'C'.[/yellow]")
                Prompt.ask("\n[bold cyan]Press Enter to continue[/bold cyan]", default="")
        else:
            try:
                sel_idx = int(choice) - 1
                if 0 <= sel_idx < len(extracted):
                    target_cwe = extracted[sel_idx]["cwe_id"]
                    _execute_cwe_lookup_with_feedback(target_cwe)
                else:
                    console.print(f"[red]Invalid selection. Please choose 1 to {len(extracted)}, 'C', 'S' or '0'.[/red]")
                    Prompt.ask("\n[bold cyan]Press Enter to continue[/bold cyan]", default="")
            except ValueError:
                console.print(f"[red]Invalid selection. Please choose 1 to {len(extracted)}, 'C', 'S' or '0'.[/red]")
                Prompt.ask("\n[bold cyan]Press Enter to continue[/bold cyan]", default="")


def run_cwe_intelligence_screen() -> None:
    """
    Interactive online & offline MITRE CWE and threat intelligence lookup console.
    """
    while True:
        clear_screen()
        show_banner()
        console.print("[bold cyan]--- Online MITRE CWE & Threat Intelligence Lookup ---[/bold cyan]\n")
        console.print("Query official MITRE taxonomy definitions, attack scenarios and vulnerability mitigations.\n")

        console.print("1. Query CWE by ID")
        console.print("2. Search Online & Local CWEs by Keyword")
        console.print("3. Fetch & Synchronize Latest MITRE CWE Taxonomy Definitions (Live Internet Sync)")
        console.print("4. View Complete Local CWE Knowledge Catalog")
        console.print("0. Return to Main Menu")

        choice = Prompt.ask("\n[bold green]Select an option[/bold green]", choices=["1", "2", "3", "4", "0", "b", "B"], default="0", show_default=False, show_choices=False)

        if choice in ["0", "b", "B"]:
            break

        elif choice == "1":
            while True:
                cwe_query = Prompt.ask("\n[bold cyan]Enter CWE ID to query (or 'b' to go back)[/bold cyan]").strip()
                if is_back(cwe_query) or not cwe_query:
                    break

                console.print(f"\n[bold cyan]Querying MITRE intelligence for '{cwe_query}'...[/bold cyan]")
                res = query_cwe_intelligence(cwe_query, force_online=False)
                if not res.get("success", False):
                    console.print("[yellow]Attempting live query from MITRE online repositories...[/yellow]")
                    res = query_cwe_intelligence(cwe_query, force_online=True)

                if res.get("success", False):
                    render_cwe_detail_panel(res)
                else:
                    console.print(f"[red]Could not retrieve definition for '{cwe_query}'. Please verify the CWE ID number.[/red]")

                Prompt.ask("\n[bold cyan]Press Enter to continue[/bold cyan]", default="")

        elif choice == "2":
            while True:
                keyword = Prompt.ask("\n[bold cyan]Enter keyword to search (or 'b' to go back)[/bold cyan]").strip()
                if is_back(keyword) or not keyword:
                    break

                results = search_cwe_catalog(keyword)
                if not results:
                    console.print(f"[yellow]No local catalog entries matched '{keyword}'. Querying online repositories...[/yellow]")
                    prompt_id = normalize_cwe_id(keyword)
                    if "CWE-" in prompt_id:
                        live_res = query_cwe_intelligence(prompt_id, force_online=True)
                        if live_res.get("success"):
                            results = [live_res]

                if results:
                    table = Table(title=f"CWE Intelligence Matches for '{keyword}' ({len(results)} found)", show_header=True, header_style="bold cyan")
                    table.add_column("CWE ID", style="cyan", no_wrap=True)
                    table.add_column("Official Title")
                    table.add_column("Abstraction", justify="center")
                    table.add_column("Key Affected Component")

                    for r in results:
                        comp = r.get("affected_components", ["General"])
                        comp_str = comp[0] if comp else "General"
                        table.add_row(r.get("id", ""), r.get("name", ""), r.get("abstraction", "Weakness"), comp_str)
                    console.print(table)

                    detail_choice = Prompt.ask("\n[bold cyan]Enter CWE ID from list to view full details (or press Enter to search again)[/bold cyan]", default="").strip()
                    if detail_choice and not is_back(detail_choice):
                        detail_res = query_cwe_intelligence(detail_choice)
                        if detail_res.get("success"):
                            render_cwe_detail_panel(detail_res)
                else:
                    console.print(f"[red]No CWE weakness definitions found matching keyword '{keyword}'.[/red]")

                Prompt.ask("\n[bold cyan]Press Enter to continue[/bold cyan]", default="")

        elif choice == "3":
            console.print("\n[bold cyan]Connecting to official MITRE repository (cwe.mitre.org)...[/bold cyan]")
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]{task.description}"),
                BarColumn(bar_width=None),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("[bold cyan]Synchronizing MITRE CWE taxonomy...", total=100)
                progress.update(task, completed=30, description="[bold cyan]Querying MITRE definitions feed...")
                sync_res = sync_all_catalog_cwes()
                progress.update(task, completed=100, description="[bold green]MITRE CWE synchronization completed!")

            console.print(f"\n[bold green]Synchronization Completed Successfully![/bold green]")
            console.print(f"• Total Catalog Entries: [bold]{sync_res['total']}[/bold]")
            console.print(f"• Successfully Synchronized: [bold green]{sync_res['synced']}[/bold green]")
            console.print(f"• Offline / Unchanged: [bold]{sync_res['failed']}[/bold]")
            console.print(f"• Sync Timestamp: {sync_res['timestamp']}")
            Prompt.ask("\n[bold cyan]Press Enter to return to menu[/bold cyan]", default="")

        elif choice == "4":
            catalog = load_cwe_catalog()
            table = Table(title=f"Complete WiFiRisk MITRE CWE Catalog ({len(catalog)} Weaknesses)", show_header=True, header_style="bold cyan")
            table.add_column("CWE ID", style="cyan", no_wrap=True)
            table.add_column("Official Title")
            table.add_column("Abstraction", justify="center")
            table.add_column("Status", justify="center")

            for cwe_id, cwe_data in catalog.items():
                table.add_row(cwe_id, cwe_data.get("name", ""), cwe_data.get("abstraction", "Weakness"), cwe_data.get("status", "Active"))
            console.print(table)

            detail_choice = Prompt.ask("\n[bold cyan]Enter CWE ID to view full details (or press Enter to return)[/bold cyan]", default="").strip()
            if detail_choice and not is_back(detail_choice):
                detail_res = query_cwe_intelligence(detail_choice)
                if detail_res.get("success"):
                    render_cwe_detail_panel(detail_res)
            Prompt.ask("\n[bold cyan]Press Enter to return[/bold cyan]", default="")


# ==========================================
# DIRECT COMMAND-LINE SUBCOMMANDS
# ==========================================


@app.command(name="run")
def cli_run_assessment(
    target_ip: str = typer.Option("auto", "--target-ip", "-t", help="Target gateway IP or 'auto' for interface auto-detection"),
    device_id: str = typer.Option("Target-Device", "--device-id", "-d", help="Unique Device Identifier"),
    price: int = typer.Option(0, "--price", "-p", help="Purchase price in LKR"),
    setup_domain: str = typer.Option("", "--setup-domain", help="Expected setup domain name"),
    brand: str = typer.Option("", "--brand", "-b", help="Brand clue"),
    model: str = typer.Option("", "--model", "-m", help="Device model name"),
    firmware_version: str = typer.Option("", "--firmware-version", "-f", help="Firmware version clue"),
    firmware_file: Optional[str] = typer.Option(None, "--firmware-file", help="Path to firmware image binary"),
    notes: str = typer.Option("Direct CLI safe assessment execution", "--notes", help="Assessment notes"),
) -> None:
    """
    Directly execute full safe security assessment from the command line.
    """
    show_banner()
    console.print(f"[bold cyan]Running Direct Assessment on {target_ip} ({device_id})...[/bold cyan]\n")

    results = run_full_safe_assessment(
        target_ip=target_ip,
        device_id=device_id,
        price_lkr=price,
        setup_domain=setup_domain,
        brand=brand,
        model=model,
        firmware_version=firmware_version,
        firmware_file_path=firmware_file,
        notes=notes,
    )

    eval_data = results.get("evaluation", {})
    score = eval_data.get("final_score", 100)
    risk = eval_data.get("risk_level", "Low")
    psr = eval_data.get("psr", 0.0)
    rec = eval_data.get("recommendation", {})
    findings = results.get("findings") or results.get("all_findings") or []
    deductions_detail = eval_data.get("deductions_detail", [])

    risk_color = "red" if risk in ["Critical", "High"] else "yellow" if risk == "Medium" else "green"

    summary_text = f"""
[bold]Assessment ID:[/bold]       {results.get('assessment_id', '')}
[bold]Target IP / Device:[/bold]  {results.get('target_ip', target_ip)} ({device_id})
[bold]Device Price:[/bold]        LKR {price}
[bold]Total Findings:[/bold]      {len(findings)} discovered

[bold]Base Security Score:[/bold] 100/100
[bold]Deductions Applied:[/bold]  -{eval_data.get('total_deductions', 0)} points
[bold]Final Score:[/bold]         [{risk_color}]{score}/100[/{risk_color}]
[bold]Risk Level:[/bold]          [{risk_color}]{risk}[/{risk_color}]
[bold]Price-to-Security (PSR):[/bold] {psr} (Baseline: LKR 15,000)

[bold]Recommendation Category:[/bold]
[bold {risk_color}]{rec.get('category', 'N/A')}[/bold {risk_color}]

[bold]Summary Guidance:[/bold]
{rec.get('guidance', '')}

[bold]Unified Evidence File:[/bold]
{results.get('full_evidence_file', '')}
"""
    console.print(Panel(summary_text.strip(), title=f"Full Assessment Completed: {device_id}", border_style=risk_color))

    if findings:
        table = Table(title=f"Discovered Vulnerabilities for {device_id} ({len(findings)} finding(s))", show_header=True, header_style="bold cyan")
        table.add_column("Finding ID", style="cyan", no_wrap=True)
        table.add_column("Severity Tier", justify="center")
        table.add_column("Layer / Module")
        table.add_column("Vulnerability Title")
        table.add_column("Deduction", justify="center", style="bold red")

        ded_map = {d.get("finding_id"): d.get("deduction", 0) for d in deductions_detail}

        for f in findings:
            f_id = f.get("id", "")
            f_sev = f.get("severity", "")
            sev_style = "bold red" if f_sev.lower() in ["high", "critical"] else "bold yellow" if "medium" in f_sev.lower() else "bold green"
            ded_val = ded_map.get(f_id, "")
            ded_display = f"-{ded_val} pts" if ded_val else ""

            table.add_row(
                f_id,
                f"[{sev_style}]{f_sev}[/{sev_style}]",
                f.get("module", "General"),
                f.get("title", ""),
                ded_display,
            )
        console.print(table)
    else:
        console.print(f"\n[bold green]✓ No security vulnerabilities discovered on {target_ip}. Device is clean.[/bold green]")


@app.command(name="interfaces")
def cli_detect_interfaces() -> None:
    """
    Directly list all available network adapters, IP addresses and default gateways.
    """
    show_banner()
    interfaces = list_all_interfaces()
    table = Table(title="Discovered Network Adapters & Routes", show_header=True, header_style="bold cyan")
    table.add_column("#", justify="center", style="cyan", no_wrap=True)
    table.add_column("Interface / Adapter Name")
    table.add_column("Local IP Address")
    table.add_column("Target Gateway IP")
    table.add_column("Subnet Mask")
    table.add_column("Route Status", justify="center")

    for idx, iface in enumerate(interfaces, start=1):
        is_def = iface.get("is_default", False)
        status_tag = "[bold green]Default Route[/bold green]" if is_def else "[white]Active[/white]"
        table.add_row(
            str(idx),
            iface.get("name", "Unknown"),
            iface.get("local_ip", "N/A"),
            iface.get("gateway_ip", "N/A"),
            str(iface.get("subnet_mask", "N/A")),
            status_tag,
        )

    console.print(table)


@app.command(name="export")
def cli_export_report(
    assessment_id: str = typer.Option("ASM-001", "--assessment-id", "-a", help="Assessment ID to export report for"),
    format_type: str = typer.Option("all", "--format", "-f", help="Output format: all, md, txt, docx"),
    output_dir: str = typer.Option("reports", "--output-dir", "-o", help="Output directory path"),
) -> None:
    """
    Directly export security assessment reports from the command line.
    """
    show_banner()
    console.print(f"[bold cyan]Exporting assessment report for {assessment_id} in format: {format_type}...[/bold cyan]\n")

    try:
        files = export_assessment_report(assessment_id=assessment_id, format_type=format_type, output_dir=output_dir)
        console.print("[bold green]Generated Report Files:[/bold green]")
        for fmt, p in files.items():
            console.print(f"  - [bold cyan]{fmt.upper()}:[/bold cyan] {p}")
    except Exception as err:
        console.print(f"[bold red]Export Error:[/bold red] {err}")


@app.command(name="export-dataset")
def cli_export_dataset(
    format_type: str = typer.Option("all", "--format", "-f", help="Output format: all, txt, log, json"),
    output_dir: str = typer.Option("reports", "--output-dir", "-o", help="Output directory path"),
) -> None:
    """
    Export complete research test dataset and audit logs from tested devices and results.
    """
    show_banner()
    console.print(f"[bold cyan]Exporting complete research test dataset in format: {format_type}...[/bold cyan]\n")

    try:
        files = export_research_test_dataset(output_dir=output_dir, format_type=format_type)
        console.print("[bold green]Generated Research Dataset Files:[/bold green]")
        for fmt, p in files.items():
            console.print(f"  - [bold cyan]{fmt.upper()}:[/bold cyan] {p}")
    except Exception as err:
        console.print(f"[bold red]Dataset Export Error:[/bold red] {err}")


@app.command(name="score")
def cli_score_device(
    device_id: Optional[str] = typer.Option(None, "--device-id", "-d", help="Device ID to evaluate"),
    assessment_id: Optional[str] = typer.Option(None, "--assessment-id", "-a", help="Assessment session ID to evaluate"),
    price: Optional[int] = typer.Option(None, "--price", "-p", help="Custom purchase price in LKR (defaults to stored price)"),
) -> None:
    """
    Directly calculate security score and recommendation for a device or assessment session.
    """
    show_banner()
    if not device_id and not assessment_id:
        device_id = "WR-001"

    res = evaluate_device_security(device_id=device_id, assessment_id=assessment_id, custom_price=price)
    rec = res["recommendation"]
    risk_color = "red" if res["risk_level"] in ["Critical", "High"] else "yellow" if res["risk_level"] == "Medium" else "green"

    summary_text = f"""
[bold]Target / Device:[/bold]        {res['device_or_assessment']}
[bold]Price:[/bold]                  LKR {res['price_lkr']:,}
[bold]Findings Evaluated:[/bold]     {res['findings_count']} ({res['severity_counts'].get('High', 0)} High, {res['severity_counts'].get('Medium', 0)} Med, {res['severity_counts'].get('Low-Medium', 0)} Low-Med)
[bold]Base Score:[/bold]             {res['base_score']}/100
[bold]Total Deductions:[/bold]       -{res['total_deductions']} points
[bold]Security Score:[/bold]         [{risk_color}]{res['final_score']}/100[/{risk_color}]
[bold]Risk Level:[/bold]             [{risk_color}]{res['risk_level']}[/{risk_color}]
[bold]Price-to-Security (PSR):[/bold] {res['psr']}
[bold]Recommendation:[/bold]         [bold {risk_color}]{rec['category']}[/bold {risk_color}]
[bold]Guidance:[/bold]               {rec['guidance']}
"""
    console.print(Panel(summary_text.strip(), title=f"Scorecard: {res['device_or_assessment']}", border_style=risk_color))


@app.command(name="devices")
def cli_list_devices() -> None:
    """
    Directly list tested devices from the command line.
    """
    show_banner()
    devices = get_all_devices()
    table = Table(title="Assessed Wi-Fi Repeaters & Comparison Benchmarks", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Device")
    table.add_column("Brand")
    table.add_column("Firmware")
    table.add_column("Price (LKR)", justify="right")
    table.add_column("Score", justify="right")
    table.add_column("Risk", justify="center")
    table.add_column("Recommendation")

    for device in devices:
        table.add_row(
            device["id"],
            device["display_name"],
            device["brand"],
            device["firmware_version"],
            str(device["price_lkr"]),
            str(device["security_score"]),
            device["risk_level"],
            device["recommendation"],
        )
    console.print(table)


@app.command(name="cwe")
def cli_query_cwe(
    cwe_id: str = typer.Argument(..., help="CWE ID to query (ID number or CWE-XXX)"),
    online: bool = typer.Option(False, "--online", "-o", help="Force live query to online MITRE repository"),
) -> None:
    """
    Directly query official MITRE CWE intelligence from the command line.
    """
    show_banner()
    res = query_cwe_intelligence(cwe_id, force_online=online)
    if res.get("success", False):
        render_cwe_detail_panel(res)
    else:
        console.print(f"[red]No MITRE definition found for '{cwe_id}'.[/red]")


def run_standalone_modules_screen() -> None:
    """
    Submenu for individual modular security checks and manual session initialization.
    """
    while True:
        clear_screen()
        show_banner()
        console.print("[bold cyan]--- Standalone Assessment Modules ---[/bold cyan]\n")
        console.print("1. Create New Assessment Session")
        console.print("2. Run Network Discovery (TCP Port & Service Probing)")
        console.print("3. Run DNS Behavior Checks (Setup Domain & Query Analysis)")
        console.print("4. Run Web Interface Checks (HTML Inspection & Hidden Credentials)")
        console.print("5. Online Firmware Discovery (Path A - Search Indexes & Mirrors)")
        console.print("6. Firmware Static Analysis (Path B - User-Uploaded Binary Inspection)")
        console.print("0. Back to Main Menu")

        choice = Prompt.ask(
            "\n[bold green]Select a module[/bold green]",
            choices=["0", "1", "2", "3", "4", "5", "6", "b", "B", ""],
            default="0",
            show_default=False,
            show_choices=False,
        ).strip()

        if choice in ["0", "b", "B", ""]:
            return
        elif choice == "1":
            create_assessment_screen()
        elif choice == "2":
            run_network_discovery_screen()
        elif choice == "3":
            run_dns_checks_screen()
        elif choice == "4":
            run_web_checks_screen()
        elif choice == "5":
            run_firmware_discovery_screen()
        elif choice == "6":
            run_firmware_static_analysis_screen()


def run_scorecard_and_findings_screen() -> None:
    """
    Submenu for vulnerability matrix exploration and PSR scoring.
    """
    while True:
        clear_screen()
        show_banner()
        console.print("[bold cyan]--- Security Scorecard & Findings ---[/bold cyan]\n")
        console.print("1. Show Discovered Findings (Knowledge Grid Matrix Grouped by Device)")
        console.print("2. Calculate Security Score & Price-to-Security Ratio (PSR)")
        console.print("0. Back to Main Menu")

        choice = Prompt.ask(
            "\n[bold green]Select an option[/bold green]",
            choices=["0", "1", "2", "b", "B", ""],
            default="0",
            show_default=False,
            show_choices=False,
        ).strip()

        if choice in ["0", "b", "B", ""]:
            return
        elif choice == "1":
            show_findings_screen()
        elif choice == "2":
            calculate_score_screen()


def run_device_catalog_screen() -> None:
    """
    Submenu for repeater device catalog, benchmarking and budget recommendations.
    """
    while True:
        clear_screen()
        show_banner()
        console.print("[bold cyan]--- Device Catalog & Benchmarking ---[/bold cyan]\n")
        console.print("1. List All Devices in Catalog")
        console.print("2. Search Device Catalog (by Brand, Model, Vendor)")
        console.print("3. Show Device Details & Recorded Vulnerabilities")
        console.print("4. Compare Two Repeaters (Side-by-Side Comparison Matrix)")
        console.print("5. Recommend Repeater by Budget (LKR)")
        console.print("0. Back to Main Menu")

        choice = Prompt.ask(
            "\n[bold green]Select an option[/bold green]",
            choices=["0", "1", "2", "3", "4", "5", "b", "B", ""],
            default="0",
            show_default=False,
            show_choices=False,
        ).strip()

        if choice in ["0", "b", "B", ""]:
            return
        elif choice == "1":
            list_devices_screen()
        elif choice == "2":
            search_device_screen()
        elif choice == "3":
            show_device_details_screen()
        elif choice == "4":
            compare_devices_screen()
        elif choice == "5":
            recommend_device_screen()


def run_network_utilities_screen() -> None:
    """
    Submenu for network interface detection and system reference guide.
    """
    while True:
        clear_screen()
        show_banner()
        console.print("[bold cyan]--- Network Tools & Documentation ---[/bold cyan]\n")
        console.print("1. Select & View Network Interfaces (Auto-detect Gateway IP & Subnet)")
        console.print("2. Help, Research Methodology & Technical Reference")
        console.print("0. Back to Main Menu")

        choice = Prompt.ask(
            "\n[bold green]Select an option[/bold green]",
            choices=["0", "1", "2", "b", "B", ""],
            default="0",
            show_default=False,
            show_choices=False,
        ).strip()

        if choice in ["0", "b", "B", ""]:
            return
        elif choice == "1":
            detect_network_screen()
        elif choice == "2":
            help_screen()


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """
    Open the interactive WiFiRisk console.
    """
    if ctx.invoked_subcommand is not None:
        return

    try:
        while True:
            clear_screen()
            show_banner()
            show_main_menu()

            choice = Prompt.ask(
                "\n[bold green]wifi-risk >[/bold green]",
                choices=["1", "2", "3", "4", "5", "6", "7", "8", "0"],
                show_choices=False,
            )

            if choice == "1":
                run_quick_vulnerability_check_screen()
            elif choice == "2":
                run_full_assessment_screen()
            elif choice == "3":
                run_standalone_modules_screen()
            elif choice == "4":
                list_assessments_screen()
            elif choice == "5":
                run_scorecard_and_findings_screen()
            elif choice == "6":
                run_device_catalog_screen()
            elif choice == "7":
                run_cwe_intelligence_screen()
            elif choice == "8":
                run_network_utilities_screen()
            elif choice == "0":
                console.print("[bold green]Exiting WiFiRisk. Goodbye![/bold green]")
                raise typer.Exit()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Exiting WiFiRisk... Goodbye![/bold yellow]")
        raise typer.Exit()


if __name__ == "__main__":
    app()
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt

from wifi_risk.services.device_service import get_all_devices, get_device_by_id
from wifi_risk.services.finding_service import get_findings_by_device_id


app = typer.Typer(help="Wi-Fi repeater security risk assessment CLI")
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
    console.print(f"[bold cyan]{ASCII_ART}[/bold cyan]")
    console.print("[bold]WiFiRisk - Low-Cost Wi-Fi Repeater Security Assessment CLI[/bold]")
    console.print("[green]Developed by Dulara[/green]")
    console.print(
        "A research-focused CLI tool to evaluate Wi-Fi repeaters by security risk, "
        "price-to-security value, vulnerabilities, compromises, and recommendations.\n"
    )


def pause() -> None:
    Prompt.ask("\n[bold cyan]Press Enter to continue[/bold cyan]", default="")


def show_main_menu() -> None:
    table = Table(title="Available Options", show_header=True, header_style="bold cyan")
    table.add_column("Option", justify="center", style="cyan", no_wrap=True)
    table.add_column("Action")

    table.add_row("1", "List Devices")
    table.add_row("2", "Search Device")
    table.add_row("3", "Show Device Details")
    table.add_row("4", "Show Device Findings")
    table.add_row("5", "Compare Devices")
    table.add_row("6", "Recommend Device")
    table.add_row("7", "Help")
    table.add_row("0", "Exit")

    console.print(table)


def list_devices_screen() -> None:
    clear_screen()
    show_banner()

    devices = get_all_devices()

    table = Table(title="Assessed Wi-Fi Repeaters")
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

    keyword = Prompt.ask("[bold cyan]Enter brand, model, firmware, or keyword to search[/bold cyan]")
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

    table = Table(title=f"Search Results for '{keyword}'")
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

    device_id = Prompt.ask("[bold cyan]Enter Device ID[/bold cyan]", default="WR-001")
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
    pause()


def show_device_findings_screen() -> None:
    clear_screen()
    show_banner()

    device_id = Prompt.ask("[bold cyan]Enter Device ID[/bold cyan]", default="WR-001")
    device = get_device_by_id(device_id)

    if device is None:
        console.print(f"[red]Device not found:[/red] {device_id}")
        pause()
        return

    findings = get_findings_by_device_id(device_id)

    if not findings:
        console.print(f"[yellow]No findings found for device:[/yellow] {device_id}")
        pause()
        return

    table = Table(title=f"Security Findings for {device_id}")
    table.add_column("Finding ID", style="cyan", no_wrap=True)
    table.add_column("Severity", justify="center")
    table.add_column("Category")
    table.add_column("Title")
    table.add_column("Status", justify="center")

    for finding in findings:
        table.add_row(
            finding["id"],
            finding["severity"],
            finding["category"],
            finding["title"],
            finding["status"],
        )

    console.print(table)

    for finding in findings:
        severity = finding["severity"].lower()

        if severity == "high":
            border_style = "red"
        elif severity == "medium":
            border_style = "yellow"
        else:
            border_style = "green"

        console.print(
            Panel(
                f"""
[bold]Title:[/bold] {finding["title"]}
[bold]Category:[/bold] {finding["category"]}
[bold]Severity:[/bold] {finding["severity"]}
[bold]Status:[/bold] {finding["status"]}

[bold]Impact:[/bold]
{finding["impact"]}

[bold]Recommendation:[/bold]
{finding["recommendation"]}
""".strip(),
                title=finding["id"],
                border_style=border_style,
            )
        )

    pause()


def compare_devices_screen() -> None:
    clear_screen()
    show_banner()

    first_id = Prompt.ask("[bold cyan]Enter first Device ID[/bold cyan]", default="WR-001")
    second_id = Prompt.ask("[bold cyan]Enter second Device ID[/bold cyan]")

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

    table = Table(title="Device Comparison")
    table.add_column("Field", style="cyan")
    table.add_column(first_device["id"])
    table.add_column(second_device["id"])

    table.add_row("Device", first_device["display_name"], second_device["display_name"])
    table.add_row("Brand", first_device["brand"], second_device["brand"])
    table.add_row("Firmware", first_device["firmware_version"], second_device["firmware_version"])
    table.add_row("Price", f"LKR {first_device['price_lkr']}", f"LKR {second_device['price_lkr']}")
    table.add_row("Security Score", f"{first_device['security_score']}/100", f"{second_device['security_score']}/100")
    table.add_row("Risk Level", first_device["risk_level"], second_device["risk_level"])
    table.add_row("Recommendation", first_device["recommendation"], second_device["recommendation"])

    console.print(table)
    pause()


def recommend_device_screen() -> None:
    clear_screen()
    show_banner()

    budget = typer.prompt("Enter your budget in LKR", type=int)

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

    table = Table(title=f"Recommended Devices Under LKR {budget}")
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
    clear_screen()
    show_banner()

    help_text = """
[bold cyan]WiFiRisk Help[/bold cyan]

This CLI helps users check the security posture of tested Wi-Fi repeaters.

[bold]Main Sections[/bold]

1. [bold]List Devices[/bold]
   Shows all tested devices in the local database.

2. [bold]Search Device[/bold]
   Search by device ID, brand, model, firmware version, MAC vendor, or keyword.

3. [bold]Show Device Details[/bold]
   Shows full information about a selected repeater.

4. [bold]Show Device Findings[/bold]
   Shows confirmed vulnerabilities, impact, and recommendations.

5. [bold]Compare Devices[/bold]
   Compares two repeaters by price, firmware, security score, risk level, and recommendation.

6. [bold]Recommend Device[/bold]
   Shows devices within a selected budget, sorted by security score.

[bold]Example Device ID[/bold]
WR-001
"""

    console.print(Panel(help_text.strip(), title="Help", border_style="cyan"))
    pause()


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """
    Open the interactive WiFiRisk console.
    """
    if ctx.invoked_subcommand is not None:
        return

    while True:
        clear_screen()
        show_banner()
        show_main_menu()

        choice = Prompt.ask(
            "\n[bold green]wifi-risk >[/bold green]",
            choices=["1", "2", "3", "4", "5", "6", "7", "0"],
            show_choices=False,
        )

        if choice == "1":
            list_devices_screen()
        elif choice == "2":
            search_device_screen()
        elif choice == "3":
            show_device_details_screen()
        elif choice == "4":
            show_device_findings_screen()
        elif choice == "5":
            compare_devices_screen()
        elif choice == "6":
            recommend_device_screen()
        elif choice == "7":
            help_screen()
        elif choice == "0":
            console.print("[bold green]Exiting WiFiRisk. Goodbye![/bold green]")
            raise typer.Exit()
        
if __name__ == "__main__":
    app()
import typer
from rich.console import Console
from .ssl_checker import check_ssl
from .file_checker import check_exposed_files
from .dns_checker import check_spf, check_dkim

app = typer.Typer(help="site-guardian: Passive security auditor for small business websites.")
console = Console()


@app.callback()
def main():
    """site-guardian: Passive security auditor for small business websites."""


@app.command()
def audit(domain: str):
    """Run a full passive security audit on a domain."""
    console.print(f"\n[bold cyan]Auditing {domain}...[/bold cyan]\n")

    console.print("[bold]1. SSL Certificate[/bold]")
    ssl_result = check_ssl(domain)
    if ssl_result["error"]:
        console.print(f"  [red]Error:[/red] {ssl_result['error']}")
    elif ssl_result["valid"]:
        console.print(f"  [green]Valid[/green] - expires in {ssl_result['days_left']} days ({ssl_result['expiry_date']})")
    else:
        console.print(f"  [red]Expired or invalid![/red] Days left: {ssl_result['days_left']}")

    console.print("\n[bold]2. Exposed Sensitive Files[/bold]")
    file_results = check_exposed_files(domain)
    for res in file_results:
        if res.get("exposed"):
            console.print(f"  [red]EXPOSED:[/red] {res['url']} (status {res['status']})")
        elif res.get("error"):
            console.print(f"  [yellow]?[/yellow] {res['path']} - {res['error']}")
        else:
            console.print(f"  [green]OK[/green] {res['path']} (status {res['status']})")

    console.print("\n[bold]3. Email Security (SPF)[/bold]")
    spf = check_spf(domain)
    if spf["exists"]:
        console.print(f"  [green]SPF found:[/green] {spf['record']}")
    else:
        console.print(f"  [red]No SPF record:[/red] {spf['error']}")

    console.print("\n[bold]4. Email Security (DKIM)[/bold]")
    dkim = check_dkim(domain)
    if dkim["exists"]:
        console.print(f"  [green]DKIM found (selector: {dkim['selector']}):[/green] {dkim['record']}")
    else:
        console.print(f"  [red]No DKIM record:[/red] {dkim['error']}")

    console.print("\n[bold yellow]Fix-it Guide:[/bold yellow]")
    console.print("  - Renew SSL certificate if expired or expiring soon.")
    console.print("  - Remove or protect exposed files immediately.")
    console.print("  - Add SPF record: v=spf1 include:_spf.google.com ~all (adjust as needed).")
    console.print("  - Configure DKIM signing with your email provider.")

if __name__ == "__main__":
    app()

"""Console output utilities with Rich integration."""

import sys
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.theme import Theme

# Custom theme for the application
SCANNER_THEME = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "red bold",
    "success": "green",
    "highlight": "magenta",
    "dim": "dim",
    "bold": "bold",
})

# Global console instance
console = Console(theme=SCANNER_THEME)


def print_banner() -> None:
    """Print the application banner."""
    banner = """
[bold cyan]╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   [bold white]ACTIONS SCANNER[/bold white]                                          ║
║   [dim]GitHub Actions Vulnerability Scanner[/dim]                       ║
║   [dim]Detect exploitable pull_request_target workflows[/dim]           ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝[/bold cyan]
"""
    console.print(banner)


def print_phase(phase_num: str, title: str) -> None:
    """Print a phase header."""
    console.print()
    console.rule(f"[bold cyan]{phase_num}[/bold cyan]: {title}", style="blue")


def print_config(config: dict[str, Any]) -> None:
    """Print configuration as a formatted table."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="dim")
    table.add_column("Value", style="cyan")

    for key, value in config.items():
        table.add_row(key, str(value))

    console.print()
    console.print(Panel(table, title="[bold]Configuration[/bold]", border_style="dim"))


def print_summary(
    title: str,
    stats: dict[str, int | str],
    style: str = "cyan",
) -> None:
    """Print a summary panel with statistics."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Metric", style="dim")
    table.add_column("Value", style=style)

    for key, value in stats.items():
        table.add_row(key, str(value))

    console.print()
    console.print(Panel(table, title=f"[bold]{title}[/bold]", border_style=style))


def print_success(message: str) -> None:
    """Print a success message."""
    console.print(f"[success]✓[/success] {message}")


def print_error(message: str) -> None:
    """Print an error message."""
    console.print(f"[error]✗[/error] {message}", style="error")


def print_warning(message: str) -> None:
    """Print a warning message."""
    console.print(f"[warning]![/warning] {message}", style="warning")


def print_info(message: str) -> None:
    """Print an info message."""
    console.print(f"[info]i[/info] {message}")


def create_progress() -> Progress:
    """Create a Rich progress bar for long-running operations."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=False,
    )


def create_simple_progress() -> Progress:
    """Create a simple progress bar without spinner."""
    return Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True,
    )


def is_terminal() -> bool:
    """Check if running in an interactive terminal."""
    return sys.stdout.isatty()


class ScanProgress:
    """Context manager for scan progress tracking."""

    def __init__(self, total: int, description: str = "Scanning"):
        self.total = total
        self.description = description
        self.progress: Progress | None = None
        self.task_id: Any = None

    def __enter__(self) -> "ScanProgress":
        if is_terminal():
            self.progress = create_progress()
            self.progress.start()
            self.task_id = self.progress.add_task(self.description, total=self.total)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self.progress:
            self.progress.stop()

    def advance(self, amount: int = 1) -> None:
        """Advance the progress bar."""
        if self.progress and self.task_id is not None:
            self.progress.advance(self.task_id, amount)

    def update(self, completed: int, description: str | None = None) -> None:
        """Update progress with absolute values."""
        if self.progress and self.task_id is not None:
            update_kwargs: dict[str, Any] = {"completed": completed}
            if description:
                update_kwargs["description"] = description
            self.progress.update(self.task_id, **update_kwargs)

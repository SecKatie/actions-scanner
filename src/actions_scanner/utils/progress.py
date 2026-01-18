"""Progress tracking utilities for async operations."""

import asyncio
import sys
import time
from dataclasses import dataclass, field


@dataclass
class ProgressStats:
    """Statistics for progress tracking."""

    total: int = 0
    completed: int = 0
    succeeded: int = 0
    failed: int = 0
    start_time: float = field(default_factory=time.time)

    @property
    def elapsed(self) -> float:
        """Get elapsed time in seconds."""
        return time.time() - self.start_time

    @property
    def percentage(self) -> float:
        """Get completion percentage."""
        if self.total == 0:
            return 0.0
        return (self.completed / self.total) * 100

    @property
    def remaining(self) -> int:
        """Get remaining count."""
        return self.total - self.completed


class AsyncProgressTracker:
    """Async-safe progress tracking."""

    def __init__(self, total: int, description: str = "Processing"):
        self.total = total
        self.description = description
        self.completed = 0
        self.succeeded = 0
        self.failed = 0
        self.start_time = time.time()
        self._lock = asyncio.Lock()

    @property
    def stats(self) -> ProgressStats:
        """Get current progress statistics."""
        return ProgressStats(
            total=self.total,
            completed=self.completed,
            succeeded=self.succeeded,
            failed=self.failed,
            start_time=self.start_time,
        )

    async def increment(self, success: bool = True) -> int:
        """Increment and return current count."""
        async with self._lock:
            self.completed += 1
            if success:
                self.succeeded += 1
            else:
                self.failed += 1
            return self.completed

    async def update_inline(self, extra_info: str = "") -> None:
        """Print inline progress update (for terminals)."""
        if not sys.stdout.isatty():
            return

        async with self._lock:
            pct = (self.completed / self.total * 100) if self.total > 0 else 0
            elapsed = time.time() - self.start_time

            # Build progress bar
            bar_width = 30
            filled = int(bar_width * self.completed / self.total) if self.total > 0 else 0
            bar = "█" * filled + "░" * (bar_width - filled)

            # Format time
            mins, secs = divmod(int(elapsed), 60)
            time_str = f"{mins}m{secs:02d}s" if mins else f"{secs}s"

            line = (
                f"\r  [{bar}] {pct:5.1f}% │ "
                f"{self.completed}/{self.total} │ "
                f"{time_str} {extra_info}"
            )
            print(line, end="", flush=True)

    def clear_line(self) -> None:
        """Clear the current line (for terminals)."""
        if sys.stdout.isatty():
            print("\r\033[K", end="")


def format_duration(seconds: float) -> str:
    """Format duration in human-readable form."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        mins, secs = divmod(seconds, 60)
        return f"{int(mins)}m {int(secs)}s"
    else:
        hours, remainder = divmod(seconds, 3600)
        mins, secs = divmod(remainder, 60)
        return f"{int(hours)}h {int(mins)}m"


def progress_bar(current: int, total: int, width: int = 30) -> str:
    """Create a simple ASCII progress bar."""
    if total == 0:
        return "─" * width

    filled = int(width * current / total)
    remaining = width - filled

    return "█" * filled + "░" * remaining


class SimpleProgressBar:
    """Simple progress bar for non-async contexts."""

    def __init__(self, total: int, description: str = ""):
        self.total = total
        self.description = description
        self.completed = 0
        self.start_time = time.time()

    def update(self, amount: int = 1) -> None:
        """Update progress by amount."""
        self.completed += amount
        self._display()

    def set(self, value: int) -> None:
        """Set progress to specific value."""
        self.completed = value
        self._display()

    def _display(self) -> None:
        """Display the progress bar."""
        if not sys.stdout.isatty():
            return

        pct = (self.completed / self.total * 100) if self.total > 0 else 0
        bar = progress_bar(self.completed, self.total)
        elapsed = format_duration(time.time() - self.start_time)

        desc = f"{self.description}: " if self.description else ""
        print(
            f"\r  {desc}[{bar}] {pct:5.1f}% ({self.completed}/{self.total}) {elapsed}",
            end="",
            flush=True,
        )

    def finish(self) -> None:
        """Complete the progress bar."""
        self.completed = self.total
        self._display()
        print()  # New line

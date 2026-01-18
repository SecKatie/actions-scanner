"""Async utility functions and helpers."""

import asyncio
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

T = TypeVar("T")


async def run_git_command(
    args: list[str],
    cwd: Path,
    check: bool = True,
    timeout: float | None = 30.0,
) -> tuple[int, str, str]:
    """Run a git command asynchronously.

    Args:
        args: Command arguments (e.g., ["git", "status"])
        cwd: Working directory
        check: Raise exception on non-zero exit code
        timeout: Command timeout in seconds

    Returns:
        Tuple of (return_code, stdout, stderr)

    Raises:
        RuntimeError: If check=True and command fails
        asyncio.TimeoutError: If command exceeds timeout
    """
    proc = await asyncio.create_subprocess_exec(
        *args,
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        raise

    # returncode is guaranteed to be set after communicate() completes
    assert proc.returncode is not None
    if check and proc.returncode != 0:
        raise RuntimeError(f"Git command failed: {stderr.decode()}")

    return proc.returncode, stdout.decode(), stderr.decode()


async def run_command(
    args: list[str],
    cwd: Path | None = None,
    timeout: float | None = 60.0,
    env: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    """Run a shell command asynchronously.

    Args:
        args: Command arguments
        cwd: Working directory (optional)
        timeout: Command timeout in seconds
        env: Environment variables to set

    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    proc = await asyncio.create_subprocess_exec(
        *args,
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        raise

    # returncode is guaranteed to be set after communicate() completes
    assert proc.returncode is not None
    return proc.returncode, stdout.decode(), stderr.decode()


async def gather_with_concurrency(
    n: int,
    *coros,
) -> list:
    """Run coroutines with limited concurrency.

    Args:
        n: Maximum concurrent tasks
        *coros: Coroutines to run

    Returns:
        List of results
    """
    semaphore = asyncio.Semaphore(n)

    async def limited_coro(coro):
        async with semaphore:
            return await coro

    return await asyncio.gather(*[limited_coro(c) for c in coros])


async def gather_with_progress(
    coros: list,
    concurrency: int = 10,
    on_complete: Callable[[int, int, Any], None] | None = None,
) -> list:
    """Run coroutines with concurrency limit and progress callback.

    Args:
        coros: List of coroutines to run
        concurrency: Maximum concurrent tasks
        on_complete: Callback(completed, total, result) for each completion

    Returns:
        List of results in order of completion
    """
    semaphore = asyncio.Semaphore(concurrency)
    results = []
    total = len(coros)
    completed = 0
    lock = asyncio.Lock()

    async def run_with_tracking(coro, index: int):
        nonlocal completed
        async with semaphore:
            result = await coro
            async with lock:
                completed += 1
                results.append((index, result))
                if on_complete:
                    on_complete(completed, total, result)
            return result

    await asyncio.gather(
        *[run_with_tracking(coro, i) for i, coro in enumerate(coros)],
        return_exceptions=True,
    )

    # Sort by original index and return just results
    results.sort(key=lambda x: x[0])
    return [r[1] for r in results]


class AsyncBatcher:
    """Batch async operations for efficient processing."""

    def __init__(self, batch_size: int = 100, concurrency: int = 10):
        self.batch_size = batch_size
        self.concurrency = concurrency

    async def process(
        self,
        items: list[T],
        processor: Callable[[T], Any],
        on_batch_complete: Callable[..., Any] | None = None,
    ) -> list:
        """Process items in batches.

        Args:
            items: Items to process
            processor: Async function to process each item
            on_batch_complete: Callback(batch_num, total_batches, results)

        Returns:
            List of all results
        """
        all_results = []
        total_batches = (len(items) + self.batch_size - 1) // self.batch_size

        for batch_num in range(total_batches):
            start = batch_num * self.batch_size
            end = min(start + self.batch_size, len(items))
            batch = items[start:end]

            results = await gather_with_concurrency(
                self.concurrency,
                *[processor(item) for item in batch],
            )

            all_results.extend(results)

            if on_batch_complete:
                on_batch_complete(batch_num + 1, total_batches, results)

        return all_results


def create_semaphore(concurrency: int) -> asyncio.Semaphore:
    """Create a semaphore for concurrency control.

    Args:
        concurrency: Maximum concurrent operations

    Returns:
        asyncio.Semaphore instance
    """
    return asyncio.Semaphore(concurrency)

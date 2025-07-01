"""Queue to ensure commands are done in order."""

import asyncio
import logging

import aiohttp

_LOGGER = logging.getLogger(__name__)

queue: asyncio.Queue = asyncio.Queue(maxsize=1)


async def handle_queue():
    """Asyncio queue handler."""
    while True:
        func = None
        try:
            func = await queue.get()
            if callable(func):
                _LOGGER.warning("Handling queue item: %s", func)
                await func()
        except asyncio.CancelledError:
            raise
        except (TimeoutError, aiohttp.ClientError) as e:
            _LOGGER.error(
                "Network or client error handling queue item. %s: %s", type(e).__name__, e
            )
        finally:
            if func:
                queue.task_done()
        await asyncio.sleep(0)

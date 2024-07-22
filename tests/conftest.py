import asyncio

import pytest


@pytest.fixture(autouse=True)
def event_loop():
    """Force the pytest-asyncio loop to be the main one."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

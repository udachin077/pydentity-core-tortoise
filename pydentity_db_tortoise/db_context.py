from contextlib import asynccontextmanager
from typing import AsyncGenerator

from tortoise.backends.base.client import TransactionContext
from tortoise.transactions import in_transaction


class TortoiseDbContext:
    def __init__(self):
        pass

    async def ensure_created(self):
        pass

    async def ensure_deleted(self):
        pass

    @asynccontextmanager
    async def get_async_session(self) -> AsyncGenerator[TransactionContext, None]:
        async with in_transaction() as session:
            yield session

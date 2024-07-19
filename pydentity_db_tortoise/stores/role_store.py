from typing import Type, Generic, Optional
from uuid import uuid4

from pydentity.abc.stores import IRoleStore
from pydentity.exc import ArgumentNoneException
from pydentity.identity_result import IdentityResult
from pydentity.types import TRole
from tortoise.backends.base.client import BaseDBAsyncClient

from pydentity_db_tortoise.models import IdentityRole


class RoleStore(IRoleStore[TRole], Generic[TRole]):
    role_model: Type[TRole] = IdentityRole

    def __init__(self, session: BaseDBAsyncClient):
        self.session = session

    def create_model_from_dict(self, **kwargs):
        return self.role_model(**kwargs)

    async def save_changes(self):
        pass

    async def refresh(self, role: TRole):
        await role.refresh_from_db(using_db=self.session)

    async def all(self) -> list[TRole]:
        return await self.role_model.all(using_db=self.session)

    async def create(self, role: TRole) -> IdentityResult:
        if role is None:
            raise ArgumentNoneException("role")

        await role.save(using_db=self.session)
        await self.save_changes()
        await self.refresh(role)
        return IdentityResult.success()

    async def update(self, role: TRole) -> IdentityResult:
        if role is None:
            raise ArgumentNoneException("role")

        role.concurrency_stamp = uuid4()
        await role.save(using_db=self.session)
        await self.save_changes()
        await self.refresh(role)
        return IdentityResult.success()

    async def delete(self, role: TRole) -> IdentityResult:
        if role is None:
            raise ArgumentNoneException("role")

        await role.delete(using_db=self.session)
        await self.save_changes()
        return IdentityResult.success()

    async def find_by_id(self, role_id: str) -> Optional[TRole]:
        if role_id is None:
            raise ArgumentNoneException("role_id")

        return await self.role_model.get_or_none(pk=role_id, using_db=self.session)

    async def find_by_name(self, normalized_name: str) -> Optional[TRole]:
        if normalized_name is None:
            raise ArgumentNoneException("normalized_name")

        return await self.role_model.get_or_none(normalized_name=normalized_name, using_db=self.session)

    async def get_role_id(self, role: TRole) -> str:
        if role is None:
            raise ArgumentNoneException("role")

        return str(role.id)

    async def get_role_name(self, role: TRole) -> Optional[str]:
        if role is None:
            raise ArgumentNoneException("role")

        return role.name

    async def set_role_name(self, role: TRole, role_name: Optional[str]) -> None:
        if role is None:
            raise ArgumentNoneException("role")

        role.name = role_name

    async def get_normalized_role_name(self, role: TRole) -> Optional[str]:
        if role is None:
            raise ArgumentNoneException("role")

        return role.normalized_name

    async def set_normalized_role_name(self, role: TRole, normalized_name: Optional[str]) -> None:
        if role is None:
            raise ArgumentNoneException("role")

        role.normalized_name = normalized_name

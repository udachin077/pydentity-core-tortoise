from typing import Type, Generic, Optional
from uuid import uuid4

from pydenticore import IdentityResult
from pydenticore.exc import ArgumentNoneException
from pydenticore.interfaces.stores import IRoleClaimStore, IRoleStore
from pydenticore.security.claims import Claim
from pydenticore.types import TRole, TRoleClaim
from tortoise.backends.base.client import BaseDBAsyncClient

__all__ = ("RoleStore",)


class RoleStore(IRoleClaimStore[TRole], IRoleStore[TRole], Generic[TRole]):
    role_model: Type[TRole]
    role_claim_model: Type[TRoleClaim]

    def __init__(self, transaction: BaseDBAsyncClient = None):
        self.transaction = transaction

    def create_model_from_dict(self, **kwargs):
        return self.role_model(**kwargs)

    async def refresh(self, role: TRole):
        await role.refresh_from_db(using_db=self.transaction)

    async def all(self) -> list[TRole]:
        return await self.role_model.all(using_db=self.transaction)

    async def create(self, role: TRole) -> IdentityResult:
        if role is None:
            raise ArgumentNoneException('role')

        await role.save(using_db=self.transaction)
        await self.refresh(role)
        return IdentityResult.success()

    async def update(self, role: TRole) -> IdentityResult:
        if role is None:
            raise ArgumentNoneException('role')

        role.concurrency_stamp = uuid4()
        await role.save(using_db=self.transaction)
        await self.refresh(role)
        return IdentityResult.success()

    async def delete(self, role: TRole) -> IdentityResult:
        if role is None:
            raise ArgumentNoneException('role')

        await role.delete(using_db=self.transaction)
        return IdentityResult.success()

    async def find_by_id(self, role_id: str) -> Optional[TRole]:
        if role_id is None:
            raise ArgumentNoneException('role_id')

        return await self.role_model.get_or_none(id=role_id, using_db=self.transaction)

    async def find_by_name(self, normalized_name: str) -> Optional[TRole]:
        if normalized_name is None:
            raise ArgumentNoneException('normalized_name')

        return await self.role_model.get_or_none(normalized_name=normalized_name, using_db=self.transaction)

    async def get_role_id(self, role: TRole) -> str:
        if role is None:
            raise ArgumentNoneException('role')

        return str(role.id)

    async def get_role_name(self, role: TRole) -> Optional[str]:
        if role is None:
            raise ArgumentNoneException('role')

        return role.name

    async def set_role_name(self, role: TRole, role_name: Optional[str]) -> None:
        if role is None:
            raise ArgumentNoneException('role')

        role.name = role_name

    async def get_normalized_role_name(self, role: TRole) -> Optional[str]:
        if role is None:
            raise ArgumentNoneException('role')

        return role.normalized_name

    async def set_normalized_role_name(self, role: TRole, normalized_name: Optional[str]) -> None:
        if role is None:
            raise ArgumentNoneException('role')

        role.normalized_name = normalized_name

    async def add_claim(self, role: TRole, claim: Claim) -> None:
        if role is None:
            raise ArgumentNoneException('role')
        if claim is None:
            raise ArgumentNoneException('claim')

        await self.role_claim_model(
            role_id=role.id,
            claim_type=claim.type,
            claim_value=claim.value
        ).save(self.transaction)

    async def remove_claim(self, role: TRole, claim: Claim) -> None:
        if role is None:
            raise ArgumentNoneException('role')
        if claim is None:
            raise ArgumentNoneException('claim')

        await self.role_claim_model.filter(
            role_id=role.id,
            claim_type=claim.type,
            claim_value=claim.value
        ).using_db(self.transaction).delete()

    async def get_claims(self, role: TRole) -> list[Claim]:
        if role is None:
            raise ArgumentNoneException('role')

        result = await (
            self.role_claim_model.filter(role_id=role.id).using_db(self.transaction)
            .values_list('claim_type', 'claim_value')
        )

        return [Claim(*r) for r in result]

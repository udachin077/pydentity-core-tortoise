from typing import AsyncGenerator
from uuid import uuid4

import pytest
import pytest_asyncio
from pydentity.security.claims import Claim
from tortoise import Tortoise
from tortoise.exceptions import IntegrityError

from pydentity_db.models import IdentityRole, IdentityRoleClaim
from pydentity_db.stores.role_store import RoleStore


@pytest_asyncio.fixture(scope='session')
async def store() -> AsyncGenerator[RoleStore, None]:
    await Tortoise.init(
        db_url="sqlite://:memory:",
        modules={"models": ["pydentity_db.models"]},
    )
    await Tortoise.generate_schemas()
    RoleStore.role_model = IdentityRole
    RoleStore.role_claim_model = IdentityRoleClaim
    yield RoleStore()
    await Tortoise.close_connections()


@pytest.mark.asyncio
async def test_all(store):
    await IdentityRole.bulk_create([
        IdentityRole(name='admin', normalized_name='ADMIN'),
        IdentityRole(name='user', normalized_name='USER'),
        IdentityRole(name='guest', normalized_name='GUEST'),
    ])
    assert len(await store.all()) == 3


@pytest.mark.asyncio
async def test_create(store):
    role = IdentityRole(name='test_create', normalized_name='test_create'.upper())
    result = await store.create(role)
    assert result.succeeded is True
    found = await IdentityRole.filter(normalized_name='test_create'.upper())  # type: ignore
    assert len(found) == 1

    with pytest.raises(IntegrityError):
        role = IdentityRole(name='test_create', normalized_name='test_create'.upper())
        await store.create(role)


@pytest.mark.asyncio
async def test_update(store):
    await IdentityRole(name='test_update', normalized_name='test_update'.upper()).save()
    role: IdentityRole = await IdentityRole.get_or_none(normalized_name='test_update'.upper())

    role.name = 'UpdatedRole'
    role.normalized_name = 'UPDATEDROLE'
    assert role.concurrency_stamp is None
    result = await store.update(role)
    assert result.succeeded is True
    assert role.concurrency_stamp is not None


@pytest.mark.asyncio
async def test_delete(store):
    role = IdentityRole(name='test_delete', normalized_name='test_delete'.upper())
    await role.save()

    result = await store.delete(role)
    assert result.succeeded is True


@pytest.mark.asyncio
async def test_find_by_id(store):
    role = IdentityRole(name='test_find_by_id', normalized_name='test_find_by_id'.upper())
    await role.save()

    found = await store.find_by_id(role.id)
    assert found is not None and found.name == 'test_find_by_id'
    assert await store.find_by_id(str(uuid4())) is None


@pytest.mark.asyncio
async def test_find_by_name(store):
    role = IdentityRole(name='test_find_by_name', normalized_name='test_find_by_name'.upper())
    await role.save()

    found = await store.find_by_name('test_find_by_name'.upper())
    assert found is not None
    assert await store.find_by_name('UNDEFINED') is None


@pytest.mark.asyncio
async def test_claim(store):
    role = IdentityRole(name='test_claim', normalized_name='test_claim'.upper())
    await role.save()

    await store.add_claim(role, Claim("Name", 'test_claim'))
    await store.add_claim(role, Claim("Name", 'test_claim'))
    await store.add_claim(role, Claim("Email", 'test_claim@email.com'))

    claims = await store.get_claims(role)
    assert len(claims) == 3

    await store.remove_claim(role, Claim("Email", 'test_claim@email.com'))
    claims = await store.get_claims(role)
    assert len(claims) == 2

    await store.remove_claim(role, Claim("Name", 'test_claim'))
    claims = await store.get_claims(role)
    assert len(claims) == 0

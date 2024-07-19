from uuid import uuid4

import pytest
import pytest_asyncio
from tortoise.exceptions import IntegrityError

from pydentity_db_tortoise.models import IdentityRole


@pytest_asyncio.fixture
async def role_user():
    return await IdentityRole.get_or_none(normalized_name="USER")


@pytest.mark.asyncio
async def test_all(store):
    assert len(await store.all()) == 3


@pytest.mark.asyncio
async def test_create(store):
    role = store.create_model_from_dict(name="tester", normalized_name="TESTER")
    assert (await store.create(role)).succeeded is True


@pytest.mark.asyncio
async def test_create_raises(store):
    role = store.create_model_from_dict(name="tester", normalized_name="TESTER")
    with pytest.raises(IntegrityError):
        await store.create(role)


@pytest.mark.asyncio
async def test_update(store, role_user):
    role_user.name = "manager"
    role_user.normalized_name = "MANAGER"
    assert (await store.update(role_user)).succeeded is True


@pytest.mark.asyncio
async def test_delete(store, role_user):
    assert (await store.delete(role_user)).succeeded is True


@pytest.mark.asyncio
async def test_find_by_id(store, role_user):
    assert (await store.find_by_id(role_user.id)) is not None
    assert (await store.find_by_id(str(uuid4()))) is None


@pytest.mark.asyncio
async def test_find_by_name(store, role_user):
    assert (await store.find_by_name(role_user.normalized_name)) is not None
    assert (await store.find_by_name("TESTER")) is None

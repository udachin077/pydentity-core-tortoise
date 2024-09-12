from uuid import uuid4

from pydenticore import DefaultPersonalDataProtector
from pydenticore.interfaces import IPersonalDataProtector
from pydenticore.utils import get_device_uuid
from tortoise import fields as f, indexes

from pydentity_db_tortoise.models.abstract import (
    Model,
    AbstractIdentityUser,
    AbstractIdentityRole,
    AbstractIdentityUserRole,
    AbstractIdentityUserClaim,
    AbstractIdentityUserLogin,
    AbstractIdentityUserToken,
    AbstractIdentityRoleClaim
)
from pydentity_db_tortoise.models.fields import ProtectedPersonalDataField

__all__ = (
    'Model',
    'IdentityUser',
    'IdentityRole',
    'IdentityUserRole',
    'IdentityUserClaim',
    'IdentityUserLogin',
    'IdentityUserToken',
    'IdentityRoleClaim',
    'use_personal_data_protector',
)


def use_personal_data_protector(protector: IPersonalDataProtector | None = None):
    if not protector:
        protector = DefaultPersonalDataProtector(get_device_uuid())
    ProtectedPersonalDataField.protector = protector


class UniqueIndex(indexes.Index):
    INDEX_TYPE = 'UNIQUE'


class IdentityUser(AbstractIdentityUser):
    id = f.CharField(450, primary_key=True)
    roles: f.ManyToManyRelation['IdentityRole'] = f.ManyToManyField(
        'models.IdentityRole',
        related_name='users',
        through='pydentity_user_roles',
        forward_key='role_id',
        backward_key='user_id'
    )
    claims: f.ReverseRelation['IdentityUserClaim']
    logins: f.ReverseRelation['IdentityUserLogin']
    tokens: f.ReverseRelation['IdentityUserToken']

    def __init__(self, email: str, username: str | None = None, **kwargs):
        super().__init__(
            id=str(uuid4()),
            email=email,
            username=username,
            security_stamp=str(uuid4()),
            **kwargs
        )

    class Meta:
        table = 'pydentity_users'
        unique_together = (('normalized_email',), ('normalized_username',),)
        indexes = (
            UniqueIndex(fields=('normalized_email',), name='idx_pydentity_users_normalized_email'),
            UniqueIndex(fields=('normalized_username',), name='idx_pydentity_users_normalized_username'),
        )


class IdentityRole(AbstractIdentityRole):
    id = f.CharField(450, primary_key=True)
    claims: f.ReverseRelation['IdentityRoleClaim']
    users: f.ReverseRelation['IdentityUser']

    def __init__(self, name: str, **kwargs):
        super().__init__(
            id=str(uuid4()),
            name=name,
            **kwargs
        )

    class Meta:
        table = 'pydentity_roles'
        unique_together = (('normalized_name',),)
        indexes = (
            UniqueIndex(fields=('normalized_name',), name='idx_pydentity_roles_normalized_name'),
        )


class IdentityUserRole(AbstractIdentityUserRole):
    user = f.ForeignKeyField(
        'models.IdentityUser',
        to_field='id',
        on_delete=f.CASCADE
    )
    role = f.ForeignKeyField(
        'models.IdentityRole',
        to_field='id',
        on_delete=f.CASCADE
    )

    class Meta:
        table = 'pydentity_user_roles'
        unique_together = (('user_id', 'role_id'),)


class IdentityUserClaim(AbstractIdentityUserClaim):
    user = f.ForeignKeyField(
        'models.IdentityUser',
        to_field='id',
        on_delete=f.CASCADE,
        related_name='claims'
    )

    class Meta:
        table = 'pydentity_user_claims'


class IdentityUserLogin(AbstractIdentityUserLogin):
    user = f.ForeignKeyField(
        'models.IdentityUser',
        to_field='id',
        on_delete=f.CASCADE,
        related_name='logins'
    )

    class Meta:
        table = 'pydentity_user_logins'
        unique_together = (('login_provider', 'provider_key'),)
        indexes = (
            UniqueIndex(fields=('login_provider', 'provider_key'), name='idx_pydentity_user_logins_lp_pk'),
        )


class IdentityUserToken(AbstractIdentityUserToken):
    user = f.ForeignKeyField(
        'models.IdentityUser',
        to_field='id',
        on_delete=f.CASCADE,
        related_name='tokens'
    )

    class Meta:
        table = 'pydentity_user_tokens'
        unique_together = (('user_id', 'login_provider', 'name'),)
        indexes = (
            UniqueIndex(fields=('user_id', 'login_provider', 'name'), name='idx_pydentity_user_tokens_user_lp_name'),
        )


class IdentityRoleClaim(AbstractIdentityRoleClaim):
    role = f.ForeignKeyField(
        'models.IdentityRole',
        to_field='id',
        on_delete=f.CASCADE,
        related_name='claims'
    )

    class Meta:
        table = 'pydentity_role_claims'

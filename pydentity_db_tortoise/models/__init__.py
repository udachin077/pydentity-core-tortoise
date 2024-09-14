from uuid import uuid4

from tortoise import fields as f, indexes

from pydentity_db_tortoise.models.abstract import (
    AbstractIdentityUser,
    AbstractIdentityRole,
    AbstractIdentityUserRole,
    AbstractIdentityUserClaim,
    AbstractIdentityUserLogin,
    AbstractIdentityUserToken,
    AbstractIdentityRoleClaim
)
from pydentity_db_tortoise.models.base import Model

__all__ = (
    'IdentityRole',
    'IdentityRoleClaim',
    'IdentityUser',
    'IdentityUserClaim',
    'IdentityUserLogin',
    'IdentityUserRole',
    'IdentityUserToken',
    'Model',
)


class UniqueIndex(indexes.Index):
    INDEX_TYPE = 'UNIQUE'


class IdentityUser(AbstractIdentityUser):
    """The default implementation of AbstractIdentityUser which uses a string as a primary key."""

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
    """The default implementation of AbstractIdentityRole which uses a string as the primary key."""

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
    """Represents the link between a user and a role."""

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
    """Represents a claim that a user possesses."""

    user = f.ForeignKeyField(
        'models.IdentityUser',
        to_field='id',
        on_delete=f.CASCADE,
        related_name='claims'
    )

    class Meta:
        table = 'pydentity_user_claims'


class IdentityUserLogin(AbstractIdentityUserLogin):
    """Represents a login and its associated provider for a user."""

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
    """Represents an authentication token for a user."""

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
    """Represents a claim that is granted to all users within a role."""

    role = f.ForeignKeyField(
        'models.IdentityRole',
        to_field='id',
        on_delete=f.CASCADE,
        related_name='claims'
    )

    class Meta:
        table = 'pydentity_role_claims'

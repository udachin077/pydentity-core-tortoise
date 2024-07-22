"""
CREATE TABLE IF NOT EXISTS "pydentity_roles" (
    "concurrency_stamp" TEXT,
    "name" VARCHAR(256),
    "normalized_name" VARCHAR(256),
    "id" VARCHAR(450) NOT NULL  PRIMARY KEY,
    CONSTRAINT "uid_pydentity_r_normali_9396bc" UNIQUE ("normalized_name")
);

CREATE UNIQUE INDEX "idx_pydentity_roles_normalized_name" ON "pydentity_roles" ("normalized_name");

CREATE TABLE IF NOT EXISTS "pydentity_role_claims" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    "claim_type" VARCHAR(455) NOT NULL,
    "claim_value" TEXT,
    "role_id" VARCHAR(450) NOT NULL REFERENCES "pydentity_roles" ("id") ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS "pydentity_users" (
    "access_failed_count" INT NOT NULL  DEFAULT 0,
    "concurrency_stamp" TEXT,
    "email" VARCHAR(256),
    "email_confirmed" INT NOT NULL  DEFAULT 0,
    "lockout_enabled" INT NOT NULL  DEFAULT 1,
    "lockout_end" TIMESTAMP,
    "normalized_email" VARCHAR(256),
    "normalized_username" VARCHAR(256),
    "password_hash" TEXT,
    "phone_number" VARCHAR(256),
    "phone_number_confirmed" INT NOT NULL  DEFAULT 0,
    "security_stamp" CHAR(36),
    "two_factor_enabled" INT NOT NULL  DEFAULT 0,
    "username" VARCHAR(256),
    "id" VARCHAR(450) NOT NULL  PRIMARY KEY,
    CONSTRAINT "uid_pydentity_u_normali_871cc5" UNIQUE ("normalized_email"),
    CONSTRAINT "uid_pydentity_u_normali_968bba" UNIQUE ("normalized_username")
);

CREATE UNIQUE INDEX "idx_pydentity_users_normalized_email" ON "pydentity_users" ("normalized_email");
CREATE UNIQUE INDEX "idx_pydentity_users_normalized_username" ON "pydentity_users" ("normalized_username");

CREATE TABLE IF NOT EXISTS "pydentity_user_claims" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    "claim_type" TEXT,
    "claim_value" TEXT,
    "user_id" VARCHAR(450) NOT NULL REFERENCES "pydentity_users" ("id") ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS "pydentity_user_logins" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    "login_provider" VARCHAR(128) NOT NULL,
    "provider_key" VARCHAR(128) NOT NULL,
    "provider_display_name" TEXT,
    "user_id" VARCHAR(450) NOT NULL REFERENCES "pydentity_users" ("id") ON DELETE CASCADE,
    CONSTRAINT "uid_pydentity_u_login_p_a8df45" UNIQUE ("login_provider", "provider_key")
);

CREATE UNIQUE INDEX "idx_pydentity_user_logins_lp_pk" ON "pydentity_user_logins" ("login_provider", "provider_key");
CREATE TABLE IF NOT EXISTS "pydentity_user_roles" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    "role_id" VARCHAR(450) NOT NULL REFERENCES "pydentity_roles" ("id") ON DELETE CASCADE,
    "user_id" VARCHAR(450) NOT NULL REFERENCES "pydentity_users" ("id") ON DELETE CASCADE,
    CONSTRAINT "uid_pydentity_u_user_id_ceea6f" UNIQUE ("user_id", "role_id")
);

CREATE TABLE IF NOT EXISTS "pydentity_user_tokens" (
    "id" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    "login_provider" VARCHAR(128) NOT NULL,
    "name" VARCHAR(128) NOT NULL,
    "value" TEXT,
    "user_id" VARCHAR(450) NOT NULL REFERENCES "pydentity_users" ("id") ON DELETE CASCADE,
    CONSTRAINT "uid_pydentity_u_user_id_637c58" UNIQUE ("user_id", "login_provider", "name")
);

CREATE UNIQUE INDEX "idx_pydentity_user_tokens_user_lp_name" ON "pydentity_user_tokens" ("user_id", "login_provider", "name");
"""
from uuid import uuid4

from tortoise import fields, indexes

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

__all__ = (
    'Model',
    'IdentityUser',
    'IdentityRole',
    'IdentityUserRole',
    'IdentityUserClaim',
    'IdentityUserLogin',
    'IdentityUserToken',
    'IdentityRoleClaim',
)


class UniqueIndex(indexes.Index):
    INDEX_TYPE = 'UNIQUE'


class IdentityUser(AbstractIdentityUser):
    id = fields.CharField(450, primary_key=True)
    roles: fields.ManyToManyRelation['IdentityRole'] = fields.ManyToManyField(
        'models.IdentityRole',
        related_name='users',
        through='pydentity_user_roles',
        forward_key='role_id',
        backward_key='user_id'
    )
    claims: fields.ReverseRelation['IdentityUserClaim']
    logins: fields.ReverseRelation['IdentityUserLogin']
    tokens: fields.ReverseRelation['IdentityUserToken']

    def __init__(
            self,
            email: str,
            username: str | None = None,
            **kwargs
    ):
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
    id = fields.CharField(450, primary_key=True)
    claims: fields.ReverseRelation['IdentityRoleClaim']
    users: fields.ReverseRelation['IdentityUser']

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
    user = fields.ForeignKeyField(
        'models.IdentityUser',
        to_field='id',
        on_delete=fields.CASCADE
    )
    role = fields.ForeignKeyField(
        'models.IdentityRole',
        to_field='id',
        on_delete=fields.CASCADE
    )

    class Meta:
        table = 'pydentity_user_roles'
        unique_together = (('user_id', 'role_id'),)


class IdentityUserClaim(AbstractIdentityUserClaim):
    user = fields.ForeignKeyField(
        'models.IdentityUser',
        to_field='id',
        on_delete=fields.CASCADE,
        related_name='claims'
    )

    class Meta:
        table = 'pydentity_user_claims'


class IdentityUserLogin(AbstractIdentityUserLogin):
    user = fields.ForeignKeyField(
        'models.IdentityUser',
        to_field='id',
        on_delete=fields.CASCADE,
        related_name='logins'
    )

    class Meta:
        table = 'pydentity_user_logins'
        unique_together = (('login_provider', 'provider_key'),)
        indexes = (
            UniqueIndex(fields=('login_provider', 'provider_key'), name='idx_pydentity_user_logins_lp_pk'),
        )


class IdentityUserToken(AbstractIdentityUserToken):
    user = fields.ForeignKeyField(
        'models.IdentityUser',
        to_field='id',
        on_delete=fields.CASCADE,
        related_name='tokens'
    )

    class Meta:
        table = 'pydentity_user_tokens'
        unique_together = (('user_id', 'login_provider', 'name'),)
        indexes = (
            UniqueIndex(fields=('user_id', 'login_provider', 'name'), name='idx_pydentity_user_tokens_user_lp_name'),
        )


class IdentityRoleClaim(AbstractIdentityRoleClaim):
    role = fields.ForeignKeyField(
        'models.IdentityRole',
        to_field='id',
        on_delete=fields.CASCADE,
        related_name='claims'
    )

    class Meta:
        table = 'pydentity_role_claims'

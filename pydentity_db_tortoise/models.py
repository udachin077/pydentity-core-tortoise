import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from pydentity.types import TKey, GUID
from tortoise import Model, fields


class IdentityUser(Model):
    if TYPE_CHECKING:
        access_failed_count: int
        concurrency_stamp: Optional[GUID]
        email: Optional[str]
        email_confirmed: bool
        id: TKey
        lockout_enabled: bool
        lockout_end: Optional[datetime]
        normalized_email: Optional[str]
        normalized_username: Optional[str]
        password_hash: Optional[str]
        phone_number: Optional[str]
        phone_number_confirmed: bool
        security_stamp: Optional[GUID]
        two_factor_enabled: bool
        username: Optional[str]
    else:
        access_failed_count = fields.BooleanField(default=0)
        concurrency_stamp = fields.UUIDField(null=True)
        email = fields.CharField(256, null=True)
        email_confirmed = fields.BooleanField(default=False)
        id = fields.UUIDField(primary_key=True)
        lockout_enabled = fields.BooleanField(default=True)
        lockout_end = fields.DatetimeField(null=True)
        normalized_email = fields.CharField(256, null=True, unique=True)
        normalized_username = fields.CharField(256, null=True, unique=True)
        password_hash = fields.TextField(null=True)
        phone_number = fields.CharField(256, null=True)
        phone_number_confirmed = fields.BooleanField(default=False)
        security_stamp = fields.UUIDField(null=True)
        two_factor_enabled = fields.BooleanField(default=False)
        username = fields.CharField(256, null=True)

        roles: fields.ManyToManyRelation["IdentityRole"] = fields.ManyToManyField(
            "models.IdentityRole",
            related_name="users",
            through="pydentity_user_roles",
            forward_key="role_id",
            backward_key="user_id"
        )
        claims: fields.ReverseRelation["IdentityUserClaim"]
        logins: fields.ReverseRelation["IdentityUserLogin"]
        tokens: fields.ReverseRelation["IdentityUserToken"]

        class Meta:
            table = "pydentity_users"

        def __init__(
                self,
                username: str = None,
                email: str = None,
                **kwargs
        ):
            super().__init__(
                id=uuid.uuid4(),
                security_stamp=uuid.uuid4(),
                username=username,
                email=email,
                **kwargs
            )

        def __str__(self):
            return self.username or self.email or self.id


class IdentityRole(Model):
    if TYPE_CHECKING:
        concurrency_stamp: Optional[GUID]
        id: TKey
        name: Optional[str]
        normalized_name: Optional[str]
    else:
        concurrency_stamp = fields.UUIDField(null=True)
        id = fields.UUIDField(primary_key=True)
        name = fields.CharField(256, null=True)
        normalized_name = fields.CharField(256, null=True, unique=True)

        users: fields.ManyToManyRelation["IdentityUser"]

        class Meta:
            table = "pydentity_roles"

        def __init__(self, name: str = None, **kwargs):
            super().__init__(
                id=uuid.uuid4(),
                name=name,
                **kwargs
            )

        def __str__(self):
            return self.name or self.id


class IdentityUserRole(Model):
    if TYPE_CHECKING:
        user_id: TKey
        role_id: TKey
    else:
        user_id = fields.UUIDField()
        role_id = fields.UUIDField()

        class Meta:
            table = "pydentity_user_roles"
            unique_together = (("user_id", "role_id"),)


class IdentityUserClaim(Model):
    if TYPE_CHECKING:
        claim_type: Optional[str]
        claim_value: Optional[str]
        user_id: TKey
    else:
        claim_type = fields.CharField(455)
        claim_value = fields.TextField(null=True)
        user = fields.ForeignKeyField(
            "models.IdentityUser",
            to_field="id",
            on_delete=fields.CASCADE,
            related_name="claims"
        )

        class Meta:
            table = "pydentity_user_claims"
            unique_together = (("claim_type", "user_id"),)


class IdentityUserLogin(Model):
    if TYPE_CHECKING:
        login_provider: str
        provider_key: str
        provider_display_name: Optional[str]
        user_id: TKey
    else:
        login_provider = fields.CharField(256)
        provider_key = fields.CharField(256)
        provider_display_name = fields.TextField(null=True)
        user = fields.ForeignKeyField(
            "models.IdentityUser",
            to_field="id",
            on_delete=fields.CASCADE,
            related_name="logins"
        )

        class Meta:
            table = "pydentity_user_logins"
            unique_together = (("login_provider", "user_id"),)


class IdentityUserToken(Model):
    if TYPE_CHECKING:
        login_provider: str
        name: str
        value: Optional[str]
        user_id: TKey
    else:
        login_provider = fields.CharField(256)
        name = fields.CharField(256)
        value = fields.TextField(null=True)
        user = fields.ForeignKeyField(
            "models.IdentityUser",
            to_field="id",
            on_delete=fields.CASCADE,
            related_name="tokens"
        )

        class Meta:
            table = "pydentity_user_tokens"
            unique_together = (("login_provider", "user_id"),)

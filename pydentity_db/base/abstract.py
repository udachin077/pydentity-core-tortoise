from datetime import datetime
from typing import TYPE_CHECKING, Optional

from pydentity.types import GUID, TKey
from tortoise import fields

from pydentity_db.base.model import Model
from pydentity_db.fields import ProtectedPersonalDataField

__all__ = (
    'AbstractIdentityUser',
    'AbstractIdentityRole',
    'AbstractIdentityUserRole',
    'AbstractIdentityUserClaim',
    'AbstractIdentityRoleClaim',
    'AbstractIdentityUserToken',
    'AbstractIdentityUserLogin',
    'Model',
)

MAX_KEY_LENGTH = 128


class AbstractIdentityUser(Model):
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
        access_failed_count = fields.IntField(default=0)
        concurrency_stamp = fields.TextField(null=True)
        email = ProtectedPersonalDataField(256, null=True)
        email_confirmed = fields.BooleanField(default=False)
        lockout_enabled = fields.BooleanField(default=True)
        lockout_end = fields.DatetimeField(null=True)
        normalized_email = ProtectedPersonalDataField(256, null=True)
        normalized_username = ProtectedPersonalDataField(256, null=True)
        password_hash = fields.TextField(null=True)
        phone_number = ProtectedPersonalDataField(256, null=True)
        phone_number_confirmed = fields.BooleanField(default=False)
        security_stamp = fields.UUIDField(null=True)
        two_factor_enabled = fields.BooleanField(default=False)
        username = ProtectedPersonalDataField(256, null=True)

        class Meta:
            abstract = True

    def __str__(self) -> str:
        return self.username or self.email or self.id

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {str(self)} {id(self)}>"


class AbstractIdentityRole(Model):
    if TYPE_CHECKING:
        concurrency_stamp: Optional[GUID]
        id: TKey
        name: Optional[str]
        normalized_name: Optional[str]
    else:
        concurrency_stamp = fields.TextField(null=True)
        name = fields.CharField(256, null=True)
        normalized_name = fields.CharField(256, null=True)

        class Meta:
            abstract = True

    def __str__(self):
        return self.name or self.id

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {str(self)} {id(self)}>"


class AbstractIdentityUserRole(Model):
    if TYPE_CHECKING:
        user_id: TKey
        role_id: TKey

    class Meta:
        abstract = True

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} ({self.user_id=}, {self.role_id=}) {id(self)}>"


class AbstractIdentityUserClaim(Model):
    if TYPE_CHECKING:
        claim_type: Optional[str]
        claim_value: Optional[str]
        user_id: TKey
    else:
        id = fields.IntField(primary_key=True)
        claim_type = fields.TextField(null=True)
        claim_value = fields.TextField(null=True)

        class Meta:
            abstract = True

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} ({self.user_id=}, {self.claim_type=}) {id(self)}>"


class AbstractIdentityUserLogin(Model):
    if TYPE_CHECKING:
        login_provider: str
        provider_key: str
        provider_display_name: Optional[str]
        user_id: TKey
    else:
        login_provider = fields.CharField(128)
        provider_key = fields.CharField(128)
        provider_display_name = fields.TextField(null=True)

        class Meta:
            abstract = True

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} ({self.user_id=}, {self.login_provider=}) {id(self)}>"


class AbstractIdentityUserToken(Model):
    if TYPE_CHECKING:
        login_provider: str
        name: str
        value: Optional[str]
        user_id: TKey
    else:
        login_provider = fields.CharField(MAX_KEY_LENGTH)
        name = fields.CharField(MAX_KEY_LENGTH)
        value = fields.TextField(null=True)

        class Meta:
            abstract = True

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} ({self.user_id=}, {self.login_provider=}) {id(self)}>"


class AbstractIdentityRoleClaim(Model):
    if TYPE_CHECKING:
        id: int
        claim_type: Optional[str]
        claim_value: Optional[str]
        role_id: TKey
    else:
        id = fields.IntField(primary_key=True)
        claim_type = fields.CharField(455)
        claim_value = fields.TextField(null=True)

        class Meta:
            abstract = True

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} ({self.role_id=}, {self.claim_type=}) {id(self)}>"

from typing import override

from pydentity.interfaces import IPersonalDataProtector
from tortoise.fields import CharField


class ProtectedPersonalDataField(CharField):
    """A variably sized protected CharField.

    If a protector is installed, the data will be encrypted when writing and decrypted when receiving.
    """

    protector: IPersonalDataProtector | None = None

    @override
    def to_db_value(self, value, instance):
        if value and self.protector:
            value = self.protector.protect(value)
        return value

    @override
    def to_python_value(self, value):
        if value and self.protector:
            value = self.protector.unprotect(value)
        return value

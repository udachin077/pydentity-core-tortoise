from pydenticore.interfaces import IPersonalDataProtector
from tortoise.fields import CharField


class ProtectedPersonalDataField(CharField):
    protector: IPersonalDataProtector | None = None

    def to_db_value(self, value, instance):
        if value and self.protector:
            value = self.protector.protect(value)
        return value

    def to_python_value(self, value):
        if value and self.protector:
            value = self.protector.unprotect(value)
        return value

from tortoise import fields, Tortoise, run_async

from pydentity_db.base.abstract import AbstractIdentityUser
from pydentity_db.models import *


class Order(Model):
    id = fields.IntField(primary_key=True)
    number = fields.CharField(100)
    user = fields.ForeignKeyField(
        'base.IdentityUser',
        to_field='id',
        on_delete=fields.CASCADE,
    )


class CustomUser(AbstractIdentityUser):
    first_name = fields.CharField(100)


async def main():
    await Tortoise.init(db_url='sqlite://db.sqlite3', modules={'base': ['__main__']})
    await Tortoise.generate_schemas()


if __name__ == '__main__':
    run_async(main())

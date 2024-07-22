from tortoise import fields, Tortoise, run_async
from pydentity_db_tortoise.models import *


class Order(Model):
    id = fields.IntField(primary_key=True)
    number = fields.CharField(100)
    user = fields.ForeignKeyField(
        'models.IdentityUser',
        to_field='id',
        on_delete=fields.CASCADE,
    )


async def main():
    await Tortoise.init(db_url='sqlite://:memory:', modules={'models': ['__main__']})
    await Tortoise.generate_schemas()


if __name__ == '__main__':
    run_async(main())

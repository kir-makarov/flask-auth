import uuid

import click
from models.user import UserModel, RoleModel
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from core.config import settings
from uuid import uuid4

engine = create_engine(settings.postgres.uri)
session = Session(bind=engine)



# @click.command()
# @click.option('--username', prompt=True, help='Name of the password.')
# @click.option('--password', prompt=True, help='Name of the password.')
def hello(username, password):

    user = session.query(UserModel).filter(UserModel.username == username).first()
    if user:
        click.echo(f'the name is already taken')

    role = session.query(RoleModel).filter(RoleModel.name == 'admin').first()
    if not role:
        role = RoleModel(name='admin')

    user = UserModel(username=username, password=UserModel.generate_hash(password))
    print(user.id, role.id)

    # session.add(admin)
    # session.commit()


    #     # admin = UserModel(username=username, password=UserModel.generate_hash(password))
    #     #
    #     # session.add(admin)
    #     # session.commit()
    #     # click.echo(f'admin created successfully.')
    # except Exception as err:
    #     click.echo(f'admin created {err}')


if __name__ == '__main__':
    hello(username='petr', password='222')

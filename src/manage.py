import click
from models.user import UserModel, RoleModel, RoleUserModel
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from core.config import settings
from uuid import uuid4

engine = create_engine(settings.postgres.uri)
session = Session(bind=engine)

@click.command()
@click.option('--username', prompt=True, help='Name of the password.')
@click.option('--password', prompt=True, help='Name of the password.')
def hello(username, password):
    try:
        user = session.query(UserModel).filter(UserModel.username == username).first()
        if user:
            click.echo(f'the name is already taken')
        role = session.query(RoleModel).filter(RoleModel.name == 'admin').first()
        if not role:
            role = RoleModel(name='admin')
            role.id = uuid4()
        user = UserModel(username=username, password=UserModel.generate_hash(password))
        user.id = uuid4()
        session.add(user)
        session.commit()
        session.add(role)
        session.commit()
        role_user = RoleUserModel(
            user_id=user.id,
            role_id=role.id
        )
        session.add(role_user)
        session.commit()
        click.echo(f'admin created successfully.')
    except Exception as err:
        click.echo(f'admin created {err}')


if __name__ == '__main__':
    hello()

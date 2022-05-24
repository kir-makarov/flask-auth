import click
from models.user import UserModel, Access
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from core.config import settings


engine = create_engine(settings.postgres.uri)
session = Session(bind=engine)


@click.command()
@click.option('--username', prompt=True, help='Name of the password.')
@click.option('--password', prompt=True, help='Name of the password.')
def hello(username, password):
    try:
        admin = UserModel(username=username, password=UserModel.generate_hash(password))
        admin.access = Access.admin
        session.add(admin)
        session.commit()
        click.echo(f'admin created successfully.')
    except Exception as err:
        click.echo(f'admin created {err}')


if __name__ == '__main__':
    hello()

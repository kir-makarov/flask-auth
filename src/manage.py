import click

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from core.config import settings
from models.user import UserModel, RoleModel

engine = create_engine(settings.postgres.uri)
db = Session(bind=engine)

@click.command()
@click.option('--username', prompt=True, help='Name of the password.')
@click.option('--password', prompt=True, help='Name of the password.')
def manage(username, password):

    role = db.query(RoleModel).filter(RoleModel.name == 'admin').first()
    if not role:
        role = RoleModel(name='admin')
        db.add(role)
    user = db.query(UserModel).filter(UserModel.username == username).first()
    if user:
        click.echo('the name is already taken')
    else:
        user = UserModel(username=username, password=UserModel.generate_hash(password))
        user.roles.append(role)
        db.add(user)
        db.commit()
        click.echo('admin created successfully.')

if __name__ == '__main__':
    manage()

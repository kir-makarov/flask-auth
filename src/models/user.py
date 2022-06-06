import uuid

from sqlalchemy.dialects.postgresql import UUID
from passlib.hash import pbkdf2_sha256 as sha256
from sqlalchemy import UniqueConstraint

from db import db


def create_partition(target, connection, **kw) -> None:
    """creating partition by success_history"""
    connection.execute(
        """CREATE TABLE IF NOT EXISTS "auth_history_pc" PARTITION OF "auth_history" FOR VALUES IN ('pc')"""
    )
    connection.execute(
        """CREATE TABLE IF NOT EXISTS "auth_history_mobile" PARTITION OF "auth_history" FOR VALUES IN ('mobile')"""
    )
    connection.execute(
        """CREATE TABLE IF NOT EXISTS "auth_history_tablet" PARTITION OF "auth_history" FOR VALUES IN ('tablet')"""
    )
    connection.execute(
        """CREATE TABLE IF NOT EXISTS "auth_history_unknown" PARTITION OF "auth_history" FOR VALUES IN ('unknown')"""
    )


class RoleUserModel(db.Model):
    __tablename__ = 'roles_users'

    user_id = db.Column(
        UUID(as_uuid=True), db.ForeignKey('users.id'), primary_key=True)
    role_id = db.Column(
        UUID(as_uuid=True), db.ForeignKey('roles.id'), primary_key=True)

    __table_args__ = (
        UniqueConstraint('user_id', 'role_id', name='roles_users_ct'),
    )

    def __init__(self, user_id, role_id):
        self.user_id = user_id
        self.role_id = role_id

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

    def json(self):
        return {
            'user_id': str(self.user_id),
            'role_id': str(self.role_id)
        }


class RoleModel(db.Model):
    __tablename__ = 'roles'
    id = db.Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False
    )
    name = db.Column(db.String(255))

    def __init__(self, name):
        self.name = name

    def __str__(self):
        return self.name

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

    def json(self):
        return {'id': str(self.id), 'name': self.name}

    @classmethod
    def find_by_name(cls, name: str):
        return cls.query.filter_by(name=name).first()

    @classmethod
    def find_all(cls):
        return cls.query.all()


class UserModel(db.Model):
    __tablename__ = 'users'
    id = db.Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False
    )
    username = db.Column(db.String(255))
    password = db.Column(db.String())
    roles = db.relationship(
        'RoleModel',
        secondary='roles_users',
        backref=db.backref('users', lazy='dynamic')
    )

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

    def json(self):
        return {'id': str(self.id),
                'username': self.username,
                'roles': [role.json() for role in self.roles]
                }

    @property
    def roles_names_list(self) -> list[str]:
        return [role.name for role in self.roles]

    @classmethod
    def find_all(cls):
        return cls.query.all()

    @classmethod
    def find_by_id(cls, user_id: str):
        return cls.query.filter_by(id=user_id).first()

    @classmethod
    def find_by_username(cls, username: str):
        return cls.query.filter_by(username=username).first()

    @classmethod
    def update_password(cls, _id, new_password):
        cls.password = new_password
        db.session.commit()

    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)

    @staticmethod
    def verify_hash(password, hash):
        return sha256.verify(password, hash)


class AuthHistoryModel(db.Model):
    __tablename__ = 'auth_history'
    __table_args__ = (UniqueConstraint("id", "platform"),
                      {
                          "postgresql_partition_by": "LIST (platform)",
                          "listeners": [("after_create", create_partition)]
                      },
    )

    id = db.Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False
    )
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id"))
    ip_address = db.Column(db.String(length=50))
    user_agent = db.Column(db.Text(), nullable=False)
    platform = db.Column(db.Text, primary_key=True)
    browser = db.Column(db.Text)
    date = db.Column(db.DateTime, default=db.func.now())

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

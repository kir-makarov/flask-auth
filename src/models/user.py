import enum
import uuid

from db import db
from sqlalchemy import Enum
from sqlalchemy.dialects.postgresql import UUID
from passlib.hash import pbkdf2_sha256 as sha256


class Access(enum.Enum):
    guest = 0
    user = 1
    admin = 2


class UserModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    username = db.Column(db.String())
    password = db.Column(db.String())

    access = db.Column('value', Enum(Access), default=Access.user)

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def __repr__(self):
        return f'<User {self.username}>'

    def current_user(self, current_user_id):
        return current_user_id == self.id

    def is_admin(self):
        return self.access == Access.admin

    def allowed(self, access_level):
        return self.access.value >= access_level

    def json(self):
        return {
            'id': str(self.id),
            'username': self.username,
        }

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()


    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

    @classmethod
    def update_password(cls, _id, new_password):
        cls.password = new_password
        db.session.commit()

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()

    @classmethod
    def find_by_id(cls, _id):
        return cls.query.filter_by(id=_id).first()

    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)

    @staticmethod
    def verify_hash(password, hash):
        return sha256.verify(password, hash)

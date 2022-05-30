from uuid import uuid4

from sqlalchemy.dialects.postgresql import UUID

from db import db


class FilmModel(db.Model):
    __tablename__ = 'film'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid4, unique=True, nullable=False)
    name = db.Column(db.String())

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return f'<User {self.name}>'

    def json(self):
        return {
            'id': str(self.id),
            'name': self.name,
        }

    @classmethod
    def find_all(cls):
        return cls.query.all()

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

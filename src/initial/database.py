from db import db


def initialize_db(app):

    @app.before_first_request
    def create_tables():
        db.create_all()

    db.init_app(app)

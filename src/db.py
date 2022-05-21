import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv

load_dotenv()

db = SQLAlchemy()


def init_db(app: Flask):
    app.config[
        'SQLALCHEMY_DATABASE_URI'] = f'postgresql://{os.getenv("POSTGRES_USER")}:{os.getenv("POSTGRES_PASSWORD")}@{os.getenv("POSTGRES_HOST")}/{os.getenv("POSTGRES_DB")}'
    db.init_app(app)

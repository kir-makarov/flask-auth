from flask import Flask
from core.config import settings
from initial.database import initialize_db
from initial.jwt import initialize_jwt
from initial.routes import initialize_routes
from initial.swagger import initialize_swagger

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = settings.postgres.uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = settings.JWT_SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = settings.JWT_ACCESS_TOKEN_EXPIRES


def create_app(flask_app):
    initialize_db(app)
    initialize_jwt(app)
    initialize_routes(app)
    initialize_swagger(app)
    flask_app.run(host='0.0.0.0', port=5000, debug=True)


if __name__ == '__main__':
    initialize_db(app)
    initialize_jwt(app)
    initialize_routes(app)
    initialize_swagger(app)
    app.run(host='0.0.0.0', port=5000, debug=True)

from flask import Flask, request
from core.config import settings
from initial.database import initialize_db
from initial.jwt import initialize_jwt
from initial.oauth import initialize_oath
from initial.routes import initialize_routes
from initial.swagger import initialize_swagger

from opentelemetry.instrumentation.flask import FlaskInstrumentor
from core.tracer import configure_tracer

configure_tracer()
app = Flask(__name__)
FlaskInstrumentor().instrument_app(app)

app.config['SQLALCHEMY_DATABASE_URI'] = settings.postgres.uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = settings.JWT_SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = settings.JWT_ACCESS_TOKEN_EXPIRES


@app.before_request
def before_request():
    request_id = request.headers.get('X-Request-Id')
    if not request_id:
        raise RuntimeError('request id is required')

def create_app(app):
    initialize_db(app)
    initialize_jwt(app)
    initialize_routes(app)
    initialize_swagger(app)
    initialize_oath(app)
    app.run(host='0.0.0.0', port=5000, debug=True)


if __name__ == '__main__':
    create_app(app=app)

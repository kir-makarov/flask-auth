from flasgger import Swagger


def initialize_swagger(app):
    Swagger(app=app)

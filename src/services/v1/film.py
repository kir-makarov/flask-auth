import http
from flask_restful import Resource, reqparse
from models.film import FilmModel
from services.permissions import check_access_level


class Film(Resource):
    @classmethod
    @check_access_level(1)
    def get(cls):
        return {'stores': [x.json() for x in FilmModel.find_all()]}

    @classmethod
    def post(self):
        film_parser = reqparse.RequestParser()
        film_parser.add_argument(
            'name',
            type=str,
            required=True,
            help="This field cannot be blank."
        )
        data = film_parser.parse_args()
        film = FilmModel(data['name'])
        film.save_to_db()
        return {"message": "Film created successfully."}, http.HTTPStatus.CREATED




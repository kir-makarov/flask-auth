from http import HTTPStatus

from pydantic import BaseModel
from flask_restful import Resource
from flask_pydantic import validate

from core import const
from models.user import RoleModel
from services.permissions import check_access_level


class RoleRequestModel(BaseModel):
    role: str


class ResponseModel(BaseModel):
    message: str


class Role(Resource):

    @staticmethod
    @check_access_level(const.ACCESS_ADMIN)
    def get():
        return {'roles': [x.json() for x in RoleModel.find_all()]}

    @validate()
    @check_access_level(const.ACCESS_ADMIN)
    def post(self, body: RoleRequestModel):
        """
        Role create method for users
        ---
        tags:
            - user
        responses:
            200:
            description: Validate user's roles
            schema:
                properties:
                message:
                    type: string
                    description: Response data
               """
        if RoleModel.find_by_name(body.role):
            return ResponseModel(
                message='Role with that name already exists',
            ), HTTPStatus.BAD_REQUEST
        role = RoleModel(name=body.role)

        role.save_to_db()
        return ResponseModel(
            message='Role created successfully',
        ), HTTPStatus.OK

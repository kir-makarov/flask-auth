from http import HTTPStatus
from flask_restful import Resource, reqparse
from models.user import UserModel, RoleModel
from flask_pydantic import validate
from pydantic import BaseModel
from services.permissions import check_access_level

class RoleRequestModel(BaseModel):
    role: str


class ResponseModel(BaseModel):
    message: str


class Role(Resource):

    @staticmethod
    @check_access_level(8)
    def get():
        return {'roles': [x.json() for x in RoleModel.find_all()]}

    @validate()
    @check_access_level(8)
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

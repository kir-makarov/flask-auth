from http import HTTPStatus
from flask_restful import Resource, reqparse
from models.user import UserModel, RoleModel
from flask_pydantic import validate
from pydantic import BaseModel



class RoleRequestModel(BaseModel):
    role: str


class ResponseModel(BaseModel):
    message: str


class Role(Resource):

    @staticmethod
    def get():
        return {'roles': [x.json() for x in RoleModel.find_all()]}

    @validate()
    def post(self, body: RoleRequestModel):
        if RoleModel.find_by_name(body.role):
            return ResponseModel(
                message='Role with that name already exists',
                status=HTTPStatus.BAD_REQUEST
            )
        role = RoleModel(name=body.role)
        role.save_to_db()
        return ResponseModel(
            message='Role created successfully',
        ), HTTPStatus.OK


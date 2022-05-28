from resources.role import RoleRequestModel
from sqlalchemy.exc import IntegrityError
from http import HTTPStatus
from flask_restful import Resource
from models.user import UserModel, RoleModel, RoleUserModel
from core import const
from flask_pydantic import validate
from pydantic import BaseModel


class ResponseModel(BaseModel):
    message: str
    status: HTTPStatus


class RoleUser(Resource):

    @validate()
    def post(self, user_id, body: RoleRequestModel):
        user = UserModel.find_by_id(user_id)
        if not user:
            return ResponseModel(
                message=const.MSG_USER_ALREADY_EXIST,
                status=HTTPStatus.BAD_REQUEST
            )

        role = RoleModel.find_by_name(body.role)
        if not role:
            return ResponseModel(
                message=const.MSG_ROLE_ALREADY_EXIST,
                status=HTTPStatus.BAD_REQUEST
            )

        try:
            role_user = RoleUserModel(
                user_id=user.id,
                role_id=role.id
            )
            role_user.save_to_db()
            return ResponseModel(
                message=const.MSG_ROLE_SET_USER,
                status=HTTPStatus.OK
            )
        except IntegrityError:
            return ResponseModel(
                message=const.MSG_ROLE_ALREADY_USER,
                status=HTTPStatus.BAD_REQUEST
            )

    # TODO
    @validate()
    def delete(self, user_id, body: RoleRequestModel):
        user = UserModel.find_by_id(user_id)
        if not user:
            return ResponseModel(
                message=const.MSG_USER_ALREADY_EXIST,
                status=HTTPStatus.BAD_REQUEST
            )

        role = RoleModel.find_by_name(body.role)
        user.delete_role(role)

        return ResponseModel(
            message=const.MSG_ROLE_UNSET_USER,
            status=HTTPStatus.OK
        )

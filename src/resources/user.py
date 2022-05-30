from http import HTTPStatus
from flask import jsonify, request
from flask_restful import Resource, ResponseBase
from models.user import UserModel, AuthHistoryModel
from core import const
from services.permissions import user_must_match
from flask_pydantic import validate
from pydantic import BaseModel
from flask_jwt_extended import get_jwt_identity, jwt_required


class ResponseModel(BaseModel):
    message: str


class UserList(Resource):
    @staticmethod
    def get():
        return {'users': [x.json() for x in UserModel.find_all()]}


class User(Resource):
    @classmethod
    def get(cls, user_id):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {"message": const.MSG_USER_NOT_FOUND}, HTTPStatus.NOT_FOUND
        return user.json()


class UserRequestModel(BaseModel):
    username: str
    password: str


class UserRegister(Resource):
    @validate()
    def post(self, body: UserRequestModel):
        """
           Refresh token method for users
           ---
           tags:
             - user
           responses:
             200:
               description: Validate user's roles
               schema:
                 properties:
                   verified:
                     type: boolean
                     description: Response status
                   role:
                     type: string
                     description: Response data
             401:
               description: Authorization error response
               schema:
                 properties:
                   description:
                     type: string
                     description: Response status
                   error:
                     type: string
                     description: Response data
       """
        if UserModel.find_by_username(body.username):
            return {"message": const.MSG_USER_ALREADY_EXIST}, HTTPStatus.BAD_REQUEST
        user = UserModel(body.username, UserModel.generate_hash(body.password))
        user.save_to_db()
        return ResponseModel(
            message=const.MSG_USER_CREATED_SUCCESSFULLY,
        ), HTTPStatus.CREATED


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


class ChangePassword(Resource):
    @validate()
    def post(self, user_id, body: ChangePasswordRequest):
        """
           Refresh token method for users
           ---
           tags:
             - user
           responses:
             200:
               description: Validate user's roles
               schema:
                 properties:
                   verified:
                     type: boolean
                     description: Response status
                   role:
                     type: string
                     description: Response data
             401:
               description: Authorization error response
               schema:
                 properties:
                   description:
                     type: string
                     description: Response status
                   error:
                     type: string
                     description: Response data
       """
        user = UserModel.find_by_id(user_id)
        if user and UserModel.verify_hash(body.old_password, user.password):
            user.update_password(user_id, UserModel.generate_hash(body.new_password))
            return ResponseModel(
                message=const.MSG_PASSWORD_CHANGED_SUCCESSFULLY,
            ), HTTPStatus.OK
        return ResponseModel(
            message=const.MSG_USER_NOT_FOUND_OR_INCORRECT_PASSWORD,
        ), HTTPStatus.NOT_FOUND


class AuthHistory(Resource):
    @jwt_required()
    @user_must_match
    def get(self, user_id):
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 5, type=int)

        user_id = get_jwt_identity()
        user_data = AuthHistoryModel.query.filter_by(user_id=user_id).paginate(page=page, per_page=per_page)
        history = [{
                'date': usr.date,
                'ip_address': usr.ip_address,
                'user_agent': usr.user_agent,
                'browser': usr.browser,
                'platform': usr.platform,
                } for usr in user_data.items
        ]
        return jsonify(history)

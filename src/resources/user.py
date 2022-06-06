from http import HTTPStatus

from flask import jsonify, request
from flask_restful import Resource
from flask_pydantic import validate
from pydantic import BaseModel
from flask_jwt_extended import get_jwt_identity, jwt_required

from models.user import UserModel, AuthHistoryModel
from core import const
from services.permissions import user_must_match, check_access_level, limiter


class ResponseModel(BaseModel):
    message: str


class UserList(Resource):

    @staticmethod
    @check_access_level(8)
    def get():
        return {'users': [x.json() for x in UserModel.find_all()]}


class User(Resource):
    decorators = [limiter.limit("1/second", error_message="quota limit exceeded")]

    @classmethod
    @user_must_match
    def get(cls, user_id):
        """
            User page method for users
            ---
            tags:
              - user
            responses:
              200:
                description: Success user's page
                schema:
                  properties:
                    id:
                      type: string
                      description: Response message
                    username:
                      type: string
                      description: Response message
                    roles:
                      type: string
                      description: Response message
        """
        user = UserModel.find_by_id(user_id)
        if not user:
            return {"message": const.MSG_USER_NOT_FOUND}, HTTPStatus.NOT_FOUND
        return user.json()


class UserRequestModel(BaseModel):
    username: str
    password: str


class UserRegister(Resource):
    decorators = [limiter.limit("1/second", error_message="quota limit exceeded")]

    @validate()
    def post(self, body: UserRequestModel):
        """
            User register method for users
            ---
            tags:
              - user
            responses:
              200:
                description: Success user's register
                schema:
                  properties:
                    message:
                      type: string
                      description: Response message

        """
        if UserModel.find_by_username(body.username):
            return ResponseModel(
                message=const.MSG_USER_ALREADY_EXIST
            ), HTTPStatus.BAD_REQUEST
        user = UserModel(body.username, UserModel.generate_hash(body.password))
        user.save_to_db()
        return ResponseModel(
            message=const.MSG_USER_CREATED_SUCCESSFULLY,
        ), HTTPStatus.CREATED


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


class ChangePassword(Resource):
    decorators = [limiter.limit("1/second", error_message="quota limit exceeded")]

    @validate()
    @user_must_match
    def post(self, user_id, body: ChangePasswordRequest):
        """
           Change password method for users
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
        user = UserModel.find_by_id(user_id)
        if user and UserModel.verify_hash(body.old_password, user.password):
            user.update_password(
                user_id, UserModel.generate_hash(body.new_password)
            )
            return ResponseModel(
                message=const.MSG_PASSWORD_CHANGED_SUCCESSFULLY,
            ), HTTPStatus.OK
        return ResponseModel(
            message=const.MSG_USER_NOT_FOUND_OR_INCORRECT_PASSWORD,
        ), HTTPStatus.NOT_FOUND


class AuthHistory(Resource):
    decorators = [limiter.limit("1/second", error_message="quota limit exceeded")]

    @jwt_required()
    @user_must_match
    def get(self, user_id):
        """
                   Auth History method for users
                   ---
                   tags:
                     - user
                   responses:
                     200:
                       description: Validate user's roles
                       schema:
                         properties:
                           date:
                             type: string
                             description: Response data
                           ip_address:
                             type: string
                             description: Response data
                           user_agent:
                             type: string
                             description: Response data
                           browser:
                             type: string
                             description: Response data
                           platform:
                             type: string
                             description: Response data
               """

        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 5, type=int)

        user_id = get_jwt_identity()
        user_data = AuthHistoryModel.query.filter_by(
            user_id=user_id).paginate(page=page, per_page=per_page)
        history = [{
            'date': usr.date,
            'ip_address': usr.ip_address,
            'user_agent': usr.user_agent,
            'browser': usr.browser,
            'platform': usr.platform,
        } for usr in user_data.items
        ]
        return jsonify(history)

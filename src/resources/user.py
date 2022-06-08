from http import HTTPStatus

from flask import jsonify, request, Blueprint
from flask_pydantic import validate
from pydantic import BaseModel
from flask_jwt_extended import get_jwt_identity, jwt_required
from sqlalchemy.exc import IntegrityError

from models.user import UserModel, AuthHistoryModel, RoleModel
from core import const
from core.config import limiter
from services.permissions import user_must_match, check_access_level
from db import db

users = Blueprint("user", __name__, url_prefix="/v1/user")
limiter.limit("1/second", error_message="quota limit exceeded")(users)


class ResponseModel(BaseModel):
    message: str


@users.get('/')
@check_access_level(const.ACCESS_ADMIN)
def get_userlist():
    return {'users': [x.json() for x in UserModel.find_all()]}


@users.get('/<user_id>')
@user_must_match
def user_page(user_id):
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


# decorators = [limiter.limit("1/second", error_message="quota limit exceeded")]


@users.post('/register')
@validate()
def user_register(body: UserRequestModel):
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


@users.post('/<user_id>/change-password')
@validate()
@user_must_match
def change_password(user_id, body: ChangePasswordRequest):
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


@users.get('/<user_id>/history')
@jwt_required()
@user_must_match
def auth_history(user_id):
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


class RoleRequestModel(BaseModel):
    role: str


@users.route('/<user_id>/role', methods=['POST', 'DELETE'])
@validate()
@check_access_level(const.ACCESS_ADMIN)
def handle_role(user_id, body: RoleRequestModel):
    """
    СRUD Role method for users
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
    if not user:
        return ResponseModel(
            message=const.MSG_USER_ALREADY_EXIST), HTTPStatus.BAD_REQUEST
    role = RoleModel.find_by_name(body.role)
    if not role:
        return ResponseModel(
            message=const.MSG_ROLE_ALREADY_EXIST
        ), HTTPStatus.BAD_REQUEST
    if request.method == 'POST':
        try:
            user.roles.append(role)
            db.session.commit()
            return ResponseModel(
                message=const.MSG_ROLE_SET_USER
            ), HTTPStatus.BAD_REQUEST
        except IntegrityError:
            return ResponseModel(
                message=const.MSG_ROLE_ALREADY_EXIST
            ), HTTPStatus.BAD_REQUEST

    else:
        try:
            user.roles.remove(role)
            db.session.commit()
            return ResponseModel(
                message=const.MSG_ROLE_UNSET_USER
            ), HTTPStatus.OK
        except ValueError:
            return ResponseModel(
                message=const.MSG_ROLE_ALREADY_USER
            ), HTTPStatus.BAD_REQUEST


@users.route('/role', methods=['GET', 'POST'])
@check_access_level(const.ACCESS_ADMIN)
@validate()
def role_handle(body: RoleRequestModel):
    if request.method == 'GET':
        return {'roles': [x.json() for x in RoleModel.find_all()]}
    else:
        if RoleModel.find_by_name(body.role):
            return ResponseModel(
                message='Role with that name already exists',
            ), HTTPStatus.BAD_REQUEST
        role = RoleModel(name=body.role)

        role.save_to_db()
        return ResponseModel(
            message='Role created successfully',
        ), HTTPStatus.OK

from http import HTTPStatus
from functools import wraps
from flask_jwt_extended import get_jwt_identity, jwt_required

from core import const
from models.user import UserModel


def user_must_match(fn):
    @wraps(fn)
    @jwt_required(optional=True)
    def decorator(*args, user_id=None, **kwargs):
        current_user_id = get_jwt_identity()
        if user_id is not None and user_id != current_user_id:
            return {"message": const.MSG_USER_NOT_FOUND_OR_INCORRECT_PASSWORD}, HTTPStatus.NOT_FOUND
        return fn(*args, user_id=user_id, **kwargs)
    return decorator


ACCESS = dict(guest=const.ACCESS_GUEST,
              user=const.ACCESS_USER,
              editor=const.ACCESS_EDITOR,
              admin=const.ACCESS_ADMIN)


def get_access_level(roles_names_list: list):
    if not roles_names_list:
        return 0
    level = [ACCESS.get(role, 0) for role in roles_names_list]
    return max(level)


def check_access_level(access_level):
    def wrapper(fn):
        @wraps(fn)
        @jwt_required(optional=True)
        def decorator(*args, **kwargs):
            current_user_id = get_jwt_identity()
            user = UserModel.find_by_id(current_user_id)
            user_access_level = get_access_level(user.roles_names_list)
            if not user:
                return {'message': 'user not found'}, HTTPStatus.NOT_FOUND
            if user_access_level < access_level:
                return {'message': 'Access closed'}, HTTPStatus.NOT_FOUND
            return fn(*args, **kwargs)
        return decorator
    return wrapper

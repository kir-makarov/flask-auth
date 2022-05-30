from http import HTTPStatus
from functools import wraps
from flask_jwt_extended import get_jwt_identity, jwt_required
from models.user import UserModel



def user_must_match(fn):
    @wraps(fn)
    @jwt_required(optional=True)
    def decorator(*args, user_id=None, **kwargs):
        current_user_id = get_jwt_identity()
        if user_id is not None and user_id != current_user_id:
            return {"message": "User not found or incorrect password"}, HTTPStatus.NOT_FOUND
        return fn(*args, user_id=user_id, **kwargs)
    return decorator


def check_access_level(access_level):
    def wrapper(fn):
        @wraps(fn)
        @jwt_required(optional=True)
        def decorator(*args, **kwargs):
            current_user_id = get_jwt_identity()
            user = UserModel.find_by_id(current_user_id)
            if not user:
                return {'message': 'user not found'}, HTTPStatus.NOT_FOUND
            if not user.allowed(access_level):
                return {'message': 'Access closed'}, HTTPStatus.NOT_FOUND
            return fn(*args, **kwargs)
        return decorator
    return wrapper

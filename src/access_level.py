from functools import wraps
from models.user import UserModel
import http



def requires_access_level(access_level):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = UserModel.find_by_id(kwargs['user_id'])
            if not user:
                return {'message': 'user not found'}, http.HTTPStatus.NOT_FOUND
            if not user.allowed(access_level):
                return {'message': 'user not permission'}, http.HTTPStatus.NOT_ACCEPTABLE
            return f(*args, **kwargs)
        return decorated_function
    return decorator
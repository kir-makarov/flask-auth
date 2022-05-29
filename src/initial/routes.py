from resources.auth import TokenRefresh, Validate, Login, Logout
from resources.user import User, UserList, UserRegister, ChangePassword
from resources.role_user import RoleUser
from resources.role import Role
from flask_restful import Api

def initialize_routes(app):
    api = Api(app)
    # USER
    api.add_resource(UserList, '/v1/user/')
    api.add_resource(User, '/v1/user/<user_id>')
    api.add_resource(UserRegister, '/v1/register')
    api.add_resource(ChangePassword, '/v1/user/<user_id>/change-password')
    api.add_resource(RoleUser, '/v1/user/<user_id>/role/')
    # AUTH
    api.add_resource(Login, '/v1/login')
    api.add_resource(Logout, '/v1/logout')
    api.add_resource(TokenRefresh, '/v1/refresh')
    api.add_resource(Validate, '/v1/validate')
    # ROLE
    api.add_resource(Role, '/v1/role')
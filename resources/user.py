import re
from http import HTTPStatus

from flask_jwt_extended import (create_access_token, create_refresh_token,
                                get_jwt_identity, get_raw_jwt, jwt_optional,
                                jwt_refresh_token_required, jwt_required)
from flask_restful import Api, Resource
from webargs import validate
from webargs.fields import Email, Str
from webargs.flaskparser import use_kwargs
from werkzeug.security import check_password_hash, generate_password_hash

from api.models import User

api= Api()


black_list = set()

PASSWORD_VALIDATION = validate.Regexp(
    "^(?=.*[0-9]+.*)(?=.*[a-zA-Z]+.*).{7,16}$",
    error="Password must contain at least one letter, at"
    " least one number, be longer than six charaters "
    "and shorter than 16.")



class UserRegistrationResource(Resource):
    """Define endpoints for user registration."""

    form_validation = {
        "username":Str(required=True,location="json"),
        "email":  Email(required=True, location="json"),
        "password":Str(required=True, location="json",validate=PASSWORD_VALIDATION)
        
    }

    @use_kwargs(form_validation)
    def post(self, username, email, password):
        """Create new  user."""
        
        # Check if use and email exist before creation

        if User.get_by_username(username):
            return {'message': 'username already exist'}, HTTPStatus.BAD_REQUEST

        if User.get_by_email(email):
            return {'message': 'email already exist'}, HTTPStatus.BAD_REQUEST

        password= generate_password_hash(password)

        user = User(
            username=username,
            email=email,
            password=password
        )

        user.save()

        data = {
            'id': user.id,
            'username': user.username,
            'email': user.email
        }

        return data, HTTPStatus.CREATED
        



class UserLoginResource(Resource):
    """Define endpoints for user login."""

    user_login = {
        "email":Email(required=True,location="json"),
        "password":Str(required=True, location="json")
        
    }

    @use_kwargs(user_login)
    def post(self, email, password):
        """Create new  user."""
        
        user = User.get_by_email(email)
        if user and check_password_hash(user.password, password):
            return {
                "status": "success",
                "data": {
                    "user_id": user.id,
                    "email": user.email,
                    "access_token": create_access_token(identity=user.id, fresh=True),
                    "refresh_token": create_refresh_token(identity=user.id)
                }
            } , HTTPStatus.OK
        return {
            "status": "fail",
            "data": {
                "msg": "Unable to authenticate user: Invalid credentials"
            }
        }, HTTPStatus.UNAUTHORIZED



        

class UserInfoResource(Resource):

    @jwt_required
    def get(self):

        user = User.get_by_id(id=get_jwt_identity())
        if user:

            data = {
                'message':"welcome to your biodata page",
                'id': user.id,
                'username': user.username,
                'email': user.email,
            }

            return data, HTTPStatus.OK
        return {"status":"fail"}, HTTPStatus.UNAUTHORIZED



class RefreshAccessTokenResource(Resource):

    @jwt_refresh_token_required
    def post(self):
        
        current_user = get_jwt_identity()
        if current_user:

            token = create_access_token(identity=current_user, fresh=False)

            return {'token': token}, HTTPStatus.OK
        return {"message": "invalid user"}, HTTPStatus.UNAUTHORIZED


class RevokeAccessTokenResource(Resource):

    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']

        if jti:

            black_list.add(jti)

            return {'message': 'Successfully logged out'}, HTTPStatus.OK
        return {"message":"Something bad occurred while trying to log you out"
            }, HTTPStatus.BAD_REQUEST




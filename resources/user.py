import re
from http import HTTPStatus

from flask import request
from flask_jwt_extended import (create_access_token, create_refresh_token,
                                get_jwt_identity, get_raw_jwt, jwt_optional,
                                jwt_refresh_token_required, jwt_required)
from flask_restful import Api, Resource
from marshmallow import ValidationError
from webargs import validate
from webargs.fields import Email, Str
from webargs.flaskparser import use_args, use_kwargs
from werkzeug.security import check_password_hash, generate_password_hash

from api.models import User
from api.schemas import user_schema

api= Api()


black_list = set()



class UserRegistrationResource(Resource):
    """Define endpoints for user registration."""

  
    def post(self):
        """Create new  user."""
        json_input = request.get_json()

        try:
            data = user_schema.load(json_input)
        except ValidationError as err:
            return {"errors": err.messages}, 422
        
        # Check if use and email exist before creation

        if User.get_by_username(data['username']):
            return {'message': 'username already exist'}, HTTPStatus.BAD_REQUEST

        if User.get_by_email(data['email']):
            return {'message': 'email already exist'}, HTTPStatus.BAD_REQUEST

        

        user = User(**data)
        user.save()

        data = user_schema.dump(user)
        data["message"] = "Successfully created a new user"
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


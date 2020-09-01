import datetime
import os
import re
from http import HTTPStatus

from flask import current_app, render_template, request, url_for
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    get_raw_jwt,
    jwt_optional,
    jwt_refresh_token_required,
    jwt_required,
)
from flask_mail import Mail, Message
from flask_restful import Api, Resource
from marshmallow import ValidationError
from webargs import validate
from webargs.fields import Email, Str
from webargs.flaskparser import use_args, use_kwargs
from werkzeug.datastructures import FileStorage
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from api.models import User
from api.schemas import UserSchema

# from log import logger
from utils.email_token import confirm_token, generate_confirmation_token
from utils.send_emails import send_email

api = Api()

user_schema = UserSchema()

black_list = set()

mail = Mail()
# log = logger(__name__)


PASSWORD_VALIDATION = validate.Regexp(
    "^(?=.*[0-9]+.*)(?=.*[a-zA-Z]+.*).{7,16}$",
    error="Password must contain at least one letter, at"
    " least one number, be longer than six charaters "
    "and shorter than 16.",
)


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in current_app.config["ALLOWED_EXTENSIONS"]
    )


PASSWORD_VALIDATION = validate.Regexp(
    "^(?=.*[0-9]+.*)(?=.*[a-zA-Z]+.*).{7,16}$",
    error="Password must contain at least one letter, at"
    " least one number, be longer than six charaters "
    "and shorter than 16.",
)


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

        if User.get_by_username(data["username"]):
            return {"message": "username already exist"}, HTTPStatus.BAD_REQUEST

        if User.get_by_email(data["email"]):
            return {"message": "email already exist"}, HTTPStatus.BAD_REQUEST

        user = User(**data)
        user.save()

        token = generate_confirmation_token(user.email)

        # mail requirements
        subject = "Please confirm your email to be able to use our app."
        # Reverse routing
        link = url_for("useractivateresource", token=token, _external=True)

        body = f"Hi, Thanks for using our app! Please confirm your registration by clicking on the link: {link} . \
        Welcome to our family"

        send_email(user.email, subject, body)

        data = user_schema.dump(user)
        data["message"] = "Successfully created a new user"
        return data, HTTPStatus.CREATED


class UserLoginResource(Resource):
    user_login = {
        "email": Email(required=True, location="json"),
        "password": Str(required=True, location="json"),
    }

    @use_kwargs(user_login)
    def post(self, email, password):
        """login in existing user."""

        user = User.get_by_email(email)

        if not user or not check_password_hash(user.password, password):
            return (
                {"message": "username or password is incorrect"},
                HTTPStatus.UNAUTHORIZED,
            )

        if user.confirmed is False:
            return (
                {"message": "The user account is not activated yet"},
                HTTPStatus.FORBIDDEN,
            )

        access_token = create_access_token(identity=user.id, fresh=True)
        refresh_token = create_refresh_token(identity=user.id)

        # return (
        #     {"access_token": access_token, "refresh_token": refresh_token},
        #     HTTPStatus.OK,
        # )

        if user and check_password_hash(user.password, password):
            return (
                {
                    "status": "success",
                    "data": {
                        "user_id": user.id,
                        "email": user.email,
                        "access_token": create_access_token(
                            identity=user.id, fresh=True
                        ),
                        "refresh_token": create_refresh_token(identity=user.id),
                    },
                },
                HTTPStatus.OK,
            )
        return (
            {
                "status": "fail",
                "data": {"msg": "Unable to authenticate user: Invalid credentials"},
            },
            HTTPStatus.UNAUTHORIZED,
        )


class UserInfoResource(Resource):
    @jwt_required
    def get(self):

        user = User.get_by_id(id=get_jwt_identity())
        if user:

            data = {
                "message": "welcome to your biodata page",
                "id": user.id,
                "username": user.username,
                "email": user.email,
            }
            # log.info(
            #     f"Successfully gotten user information for  {user.username}."
            # )

            return data, HTTPStatus.OK
        # log.warning("Could not get the user information")
        return {"status": "fail"}, HTTPStatus.UNAUTHORIZED


class RefreshAccessTokenResource(Resource):
    @jwt_refresh_token_required
    def post(self):

        current_user = get_jwt_identity()
        if current_user:

            token = create_access_token(identity=current_user, fresh=False)

            return {"token": token}, HTTPStatus.OK
        return {"message": "invalid user"}, HTTPStatus.UNAUTHORIZED


class RevokeAccessTokenResource(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()["jti"]

        if jti:

            black_list.add(jti)

            return {"message": "Successfully logged out"}, HTTPStatus.OK
        return (
            {"message": "Something bad occurred while trying to log you out"},
            HTTPStatus.BAD_REQUEST,
        )


class UserDisplayPictureResource(Resource):
    @jwt_required
    def put(self):

        if "file" not in request.files:
            return {"message": "no file"}, HTTPStatus.BAD_REQUEST

        uploaded_file = request.files["file"]
        # Check if the file is one of the allowed types/extensions
        if not isinstance(uploaded_file, FileStorage):
            return (
                {"message": "File type not allowed, upload png, jpeg, svg files"},
                HTTPStatus.BAD_REQUEST,
            )

        mimetype = uploaded_file.content_type
        if mimetype not in current_app.config["ALLOWED_MIMETYPES_EXTENSIONS"]:
            return (
                {"message": "File type not allowed, upload png, jpeg, svg files"},
                HTTPStatus.BAD_REQUEST,
            )


        # Make the filename safe, remove unsupported chars
        filename = secure_filename(uploaded_file.filename)
        user = User.get_by_id(id=get_jwt_identity())

        uploaded_file.stream.seek(0)

        target = os.path.join(
            current_app.config["UPLOAD_FOLDER"], user.username, filename
        )

        uploaded_file.save(target)

        user.display_image = target
        user.save()

        return {"msg": "uploaded display image successfully"}, HTTPStatus.OK


class UserActivateResource(Resource):
    def get(self, token):

        email = confirm_token(token)

        if email is False:
            return {"message": "Invalid token or token expired"}, HTTPStatus.BAD_REQUEST

        user = User.get_by_email(email=email)

        if not user:
            return {"message": "User not found"}, HTTPStatus.NOT_FOUND

        if user.confirmed is True:
            return (
                {"message": "The user account is already activated"},
                HTTPStatus.BAD_REQUEST,
            )

        user.confirmed = True
        user.confirmed_on = datetime.datetime.now()

        user.save()

        return {"message": "The user account has been activated"}, HTTPStatus.OK


class ForgotPasswordResource(Resource):
    """Define endpoints for resetting user password."""

    user_reset = {"email": Email(required=True, location="json")}

    @use_kwargs(user_reset)
    def post(self, email):
        user = User.get_by_email(email)

        if not user:
            return {"message": "email is invalid"}, HTTPStatus.UNAUTHORIZED

        subject = "Password reset requested"

        # Here we use the URLSafeTimedSerializer
        token = generate_confirmation_token(user.email)

        recover_url = url_for("resetpasswordresource", token=token, _external=True)

        text = f"Hi {user.username}, Thanks for using our app! Please reset your password by clicking on the link: {recover_url} .\
        If you didn't ask for a password reset, ignore the mail."

        send_email(to_email=user.email, subject=subject, body=text)

        return {"msg": "succesfullly sent the reset mail to your email"}, HTTPStatus.OK


class ResetPasswordResource(Resource):
    @use_kwargs(
        {
            "password": Str(
                location="json", required=True, validate=PASSWORD_VALIDATION
            ),
            "confirmation_password": Str(
                location="json", required=True, validate=PASSWORD_VALIDATION
            ),
        }
    )
    def patch(self, token, password, confirmation_password):

        email = confirm_token(token)

        if email is False:
            return {"message": "Invalid token or token expired"}, HTTPStatus.BAD_REQUEST

        user = User.get_by_email(email=email)

        if not user:
            return {"message": "User not found"}, HTTPStatus.NOT_FOUND

        if password != confirmation_password:
            return {"message": "The two password do not match"}, HTTPStatus.BAD_REQUEST

        if user.confirmed is True:

            user.password = generate_password_hash(password)

            user.save()

            return (
                {
                    "status": "success",
                    "data": {"msg": "New password was successfully set"},
                },
                HTTPStatus.OK,
            )
        else:
            return {"message": "Confirm your email first"}, HTTPStatus.BAD_REQUEST

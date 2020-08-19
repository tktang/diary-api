from flasgger import Swagger
from flask import Flask
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from flask_restful import Api

from webargs.flaskparser import abort, parser
from werkzeug import exceptions

from api.config import env_config
from api.models import db
from resources.default import DefaultResource
from resources.notes import (DraftNoteListResource, NoteListResource,
                             NotePublishResource, NoteResource)
from resources.user import (RefreshAccessTokenResource,
                            RevokeAccessTokenResource, UserInfoResource,
                            UserLoginResource, UserRegistrationResource,
                            black_list,UserDisplayPictureResource)
from utils import errors

api = Api()


jwt = JWTManager()


def create_app(config_name):

    import resources

    app = Flask(__name__)

    app.config.from_object(env_config[config_name])

    db.init_app(app)  # Add db session, new code here

    Migrate(app, db)  # new code here
    # register api
    api.init_app(app)
    Swagger(app)

    jwt.init_app(app)
    # error handling
    @jwt.token_in_blacklist_loader
    def check_if_token_in_blacklist(decrypted_token):
        jti = decrypted_token["jti"]
        return jti in black_list



    app.register_error_handler(exceptions.NotFound, errors.handle_404_errors)

    app.register_error_handler(
        exceptions.InternalServerError, errors.handle_server_errors
    )

    app.register_error_handler(exceptions.BadRequest, errors.handle_400_errors)

    app.register_error_handler(FileNotFoundError, errors.handle_400_errors)

    app.register_error_handler(TypeError, errors.handle_400_errors)

    app.register_error_handler(KeyError, errors.handle_404_errors)

    app.register_error_handler(AttributeError, errors.handle_400_errors)

    app.register_error_handler(ValueError, errors.handle_400_errors)

    app.register_error_handler(AssertionError, errors.handle_400_errors)

    # new code
    @parser.error_handler
    def handle_request_parsing_error(
        err, req, schema, *, error_status_code, error_headers
    ):
        """webargs error handler that uses Flask-RESTful's abort function to return
        a JSON error response to the client.
        """
        abort(error_status_code, errors=err.messages)

    return app


# register our urls for user module
api.add_resource(
    UserRegistrationResource, "/v1/user/register/", endpoint="user_registration"
)
api.add_resource(UserLoginResource, "/v1/user/login/", endpoint="user_login")
api.add_resource(UserInfoResource, "/v1/user/user_info/", endpoint="user_info")

api.add_resource(
    RefreshAccessTokenResource, "/v1/user/refresh_token/", endpoint="refresh_token"
)

api.add_resource(
    RevokeAccessTokenResource, "/v1/user/signout_access/", endpoint="signout_access"
)
api.add_resource(
    UserDisplayPictureResource, "/v1/user/display_image/", endpoint="display_image"
)


# register our urls for note module
api.add_resource(NoteListResource, "/v1/notes/", endpoint="notes")
api.add_resource(NoteResource, "/v1/notes/<int:note_id>", endpoint="note_id")
api.add_resource(
    NotePublishResource, "/v1/publish_note/<int:note_id>", endpoint="publish_note"
)
api.add_resource(DraftNoteListResource, "/v1/notes/draft/", endpoint="draft")


# register url for default

api.add_resource(DefaultResource, "/", endpoint="home")

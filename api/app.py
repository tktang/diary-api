

from flasgger import Swagger
from flask import Flask
from flask_restful import Api
from webargs.flaskparser import abort, parser

from api.config import env_config
from utils import errors
from werkzeug import exceptions


api = Api()




def create_app(config_name):

    import resources

    app = Flask(__name__)

    app.config.from_object(env_config[config_name])
    
   
    
    #register api 
    api.init_app(app)
    Swagger(app)
    
   
    #error handling
    app.register_error_handler(exceptions.NotFound,
                               errors.handle_404_errors)

    app.register_error_handler(exceptions.InternalServerError,
                               errors.handle_server_errors)

    app.register_error_handler(exceptions.BadRequest,
                               errors.handle_400_errors)

    app.register_error_handler(FileNotFoundError,
                               errors.handle_400_errors)

    app.register_error_handler(TypeError, errors.handle_400_errors)

    app.register_error_handler(KeyError, errors.handle_404_errors)

    app.register_error_handler(AttributeError,
                               errors.handle_400_errors)

    app.register_error_handler(ValueError, errors.handle_400_errors)

    app.register_error_handler(AssertionError,
                               errors.handle_400_errors)
    
    
    #new code
    @parser.error_handler
    def handle_request_parsing_error(err, req, schema, *, error_status_code, error_headers):
        """webargs error handler that uses Flask-RESTful's abort function to return
        a JSON error response to the client.
        """
        abort(error_status_code, errors=err.messages)
        
    return app
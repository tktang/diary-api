
from flask_restful import Api, Resource


class DefaultResource(Resource):
    """Handle default route."""

    def get(self):
        """Get request for home page or response."""
        return {
            "status": "success",
            "data": {
                "msg": "Welcome to our diary API"
            }
        }



import os

from dotenv import load_dotenv

from api.app import create_app


load_dotenv(verbose=True)

app = create_app(os.getenv("FLASK_ENV"))








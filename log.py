import logging
import os

from api.config import env_config

FLASK_ENV = os.getenv("FLASK_ENV")


def logger(name):
    """Return logger for app wide usage."""
    level = "INFO"
    logging.basicConfig(
        level=level,
        format="[%(asctime)s] [%(filename)s] [method:%(funcName)s]"
        "  --->(%(message)s)")
    logger = logging.getLogger(name)
    return logger

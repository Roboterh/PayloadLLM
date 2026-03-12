import json
import os
import sys
from loguru import logger

def env_initial():
    with open("config.json", "r", encoding="utf-8") as f:
        config = json.load(f)
    for env in config["env"]:
        os.environ[env] = config["env"][env]

def init_logger():
    # logger.add("logs/app_log.log", rotation="10 MB", retention="10 days", level="DEBUG")
    logger.add("logs/info.log", rotation="1024 MB", mode='w', level="INFO", filter=lambda record: record["level"].name == "INFO")
    logger.add("logs/warning.log", rotation="1024 MB", mode='w', level="WARNING", filter=lambda record: record["level"].name == "WARNING")
    logger.add("logs/error.log", rotation="1024 MB", mode='w', level="ERROR", filter=lambda record: record["level"].name == "ERROR")
    logger.add("logs/debug.log", rotation="1024 MB", mode='w', level="DEBUG", filter=lambda record: record["level"].name == "DEBUG")
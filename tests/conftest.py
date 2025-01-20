import sys
from logging import config as logger_config

import pytest
import pytest_asyncio

from acme_client import ACMEClient, ACMESettings

pytest_plugins = [
    "fixtures.responses",
    "fixtures.rsa_keys",
]


@pytest_asyncio.fixture
async def client():
    config = ACMESettings(HOST="http://127.0.0.1:8010", EMAIL="nH0zB@example.com", CLIENT_TIMEOUT=1)
    async with ACMEClient(config=config) as cli:
        yield cli


@pytest.fixture(autouse=True)
def init_logger() -> None:
    logger_config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "verbose": {
                    "class": "logging.Formatter",
                    "format": "%(asctime)s [%(levelname)s] %(name)-5s: %(message)s",
                },
            },
            "handlers": {
                "console": {
                    "level": "DEBUG",
                    "class": "logging.StreamHandler",
                    "formatter": "verbose",
                    "stream": sys.stdout,
                }
            },
            "loggers": {
                "databases": {"level": "INFO"},
            },
            "root": {
                "level": "DEBUG",
                "formatter": "verbose",
                "handlers": [
                    "console",
                ],
            },
        }
    )

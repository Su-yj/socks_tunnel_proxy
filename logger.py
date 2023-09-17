import sys

from loguru import logger

import settings


logger.remove()
logger.add(sys.stderr, level=settings.LOG_LEVEL)

import re
import os
import logging


LOG_LEVEL = os.environ.get("SYS4_LOG_LEVEL", "INFO").upper()
OUTPUT_FILE = os.environ.get("SYS4_OUTPUT_FILE")

logging.basicConfig(
    format="(%(name)s) %(levelname)s: %(message)s",
    level=LOG_LEVEL,
    filename=OUTPUT_FILE,
)


class Logger:
    def __init__(self):
        self.log = logging.getLogger(" ".join(re.findall("[A-Z][a-z]*", self.__class__.__name__)))

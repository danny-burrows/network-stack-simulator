import re
import os
import sys
import logging
from dotenv import load_dotenv

load_dotenv()

ENABLE_MAIN_LOGGER = os.environ.get("SYS4_ENABLE_MAIN_LOGGER", "true") == "true"
LOG_FILE = os.environ.get("SYS4_LOG_FILE")
LOG_LEVEL = os.environ.get("SYS4_LOG_LEVEL", "DEBUG").upper()
LOG_CLASS_FILTER = os.environ.get("SYS4_LOG_CLASS_FILTER")
LOG_VERBOSE = os.environ.get("SYS4_LOG_VERBOSE", False)

ENABLE_EXAM_LOGGER = os.environ.get("SYS4_ENABLE_EXAM_LOGGER", "true") == "true"
EXAM_LOG_FILE = os.environ.get("SYS4_EXAM_LOG_FILE")


logging.basicConfig(level=LOG_LEVEL)


class CustomFormatter(logging.Formatter):
    FORMAT_PRE = "%(asctime)s (%(filename)s:%(lineno)d) [%(name)s/%(levelname)s]: "
    FORMAT_PRE_SHORT = "[%(name)s/%(levelname)s]: "
    FORMAT_POST = "%(message)s"

    COL_BLUE = "\x1b[34;20m"
    COL_GREEN = "\x1b[32;20m"
    COL_BOLD_YELLOW = "\x1b[33;1m"
    COL_RED = "\x1b[31;20m"
    COL_BOLD_RED = "\x1b[31;1m"
    COL_RESET = "\x1b[0m"

    LEVEL_COLOURS = {
        logging.DEBUG: COL_BLUE,
        logging.INFO: COL_GREEN,
        logging.WARNING: COL_BOLD_YELLOW,
        logging.ERROR: COL_BOLD_RED,
        logging.CRITICAL: COL_BOLD_RED,
    }

    formats: dict[int, str]

    def __init__(self, colour=True):
        self.formats = {}
        if colour:
            for level in CustomFormatter.LEVEL_COLOURS:
                self.formats[level] = (
                    CustomFormatter.LEVEL_COLOURS[level]
                    + (CustomFormatter.FORMAT_PRE if LOG_VERBOSE else CustomFormatter.FORMAT_PRE_SHORT)
                    + CustomFormatter.COL_RESET
                    + CustomFormatter.FORMAT_POST
                )
        else:
            for level in CustomFormatter.LEVEL_COLOURS:
                self.formats[level] = (
                    CustomFormatter.FORMAT_PRE if LOG_VERBOSE else CustomFormatter.FORMAT_PRE_SHORT
                ) + CustomFormatter.FORMAT_POST

    def format(self, record):
        log_fmt = self.formats.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


class DummyObject(object):
    def __getattr__(self, name):
        return lambda *args, **kwargs: None


class Logger:
    logger: logging.Logger
    logger_formatter = logging.Formatter
    logger_stream_handler: logging.StreamHandler

    def __init__(self):
        if self.__class__.__name__ == "Logger":
            class_name = "Root"
        elif self.__class__.__name__.islower():
            class_name = self.__class__.__name__.title()
        else:
            # (?: ... | ...) Non-capturing group of either:
            # - [A-Z]+(?=[A-Z][a-z]) Acronym followed by non acronym
            # - [A-Z][a-z]+ Word starting with first letter capital
            class_name = " ".join(re.findall("(?:[A-Z]+(?=[A-Z][a-z])|[A-Z][a-z]+)", self.__class__.__name__))

        if LOG_CLASS_FILTER and class_name != LOG_CLASS_FILTER:
            self.logger = DummyObject()

        if not ENABLE_MAIN_LOGGER:
            self.logger = DummyObject()

        else:
            if LOG_FILE:
                formatter = CustomFormatter(colour=False)
                stream_handler = logging.FileHandler(LOG_FILE, mode="w")
            else:
                formatter = CustomFormatter()
                stream_handler = logging.StreamHandler()

            stream_handler.setFormatter(formatter)

            self.logger = logging.getLogger(class_name)

            if not self.logger.handlers:
                self.logger.addHandler(stream_handler)
                self.logger.propagate = False

        if not ENABLE_EXAM_LOGGER:
            self.exam_logger = DummyObject()

        else:
            if EXAM_LOG_FILE:
                exam_stream_handler = logging.FileHandler(EXAM_LOG_FILE, mode="w")
            else:
                exam_stream_handler = logging.StreamHandler(sys.stdout)

            self.exam_logger = logging.getLogger("Exam Logger")

            if not self.exam_logger.handlers:
                self.exam_logger.addHandler(exam_stream_handler)
                self.exam_logger.propagate = False

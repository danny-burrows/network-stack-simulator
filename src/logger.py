import re
import os
import logging


LOG_LEVEL = os.environ.get("SYS4_LOG_LEVEL", "INFO").upper()
LOG_CLASS_FILTER = os.environ.get("SYS4_LOG_CLASS_FILTER")
LOG_VERBOSE = os.environ.get("SYS4_LOG_VERBOSE", False)
LOG_OUTPUT_FILE = os.environ.get("SYS4_LOG_OUTPUT_FILE")


logging.basicConfig(
    level=LOG_LEVEL,
    filename=LOG_OUTPUT_FILE,
)


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
        logging.CRITICAL: COL_BOLD_RED
    }

    formats: dict[int, str]

    def __init__(self):
        self.formats = {}
        for level in CustomFormatter.LEVEL_COLOURS:
            self.formats[level] =\
                CustomFormatter.LEVEL_COLOURS[level]\
                + (CustomFormatter.FORMAT_PRE if LOG_VERBOSE else CustomFormatter.FORMAT_PRE_SHORT)\
                + CustomFormatter.COL_RESET\
                + CustomFormatter.FORMAT_POST

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
            class_name = " ".join(re.findall("[A-Z][a-z]*", self.__class__.__name__))

        if LOG_CLASS_FILTER and class_name != LOG_CLASS_FILTER:
            self.logger = DummyObject()
            return

        self.logger = logging.getLogger(class_name)
        formatter = CustomFormatter()
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        
        if not self.logger.handlers:
            self.logger.addHandler(stream_handler)
            self.logger.propagate = False

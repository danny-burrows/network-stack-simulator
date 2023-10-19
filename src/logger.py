import re
import os
import logging


LOG_LEVEL = os.environ.get("SYS4_LOG_LEVEL", "INFO").upper()
OUTPUT_FILE = os.environ.get("SYS4_OUTPUT_FILE")

logging.basicConfig(
    level=LOG_LEVEL,
    filename=OUTPUT_FILE,
)


class CustomFormatter(logging.Formatter):
    blue = "\x1b[34;20m"
    green = "\x1b[32;20m"
    bold_yellow = "\x1b[33;1m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
<<<<<<< HEAD
    format_pre = "%(asctime)s (%(filename)s:%(lineno)d) [%(name)s/%(levelname)s]: "
    format_post = "%(message)s"

    FORMATS = {
        logging.DEBUG: blue + format_pre + reset + format_post,
        logging.INFO: green + format_pre + reset + format_post,
        logging.WARNING: bold_yellow + format_pre + reset + format_post,
        logging.ERROR: bold_red + format_pre + reset + format_post,
        logging.CRITICAL: bold_red + format_pre + reset + format_post
=======
    
    format_start = "%(asctime)s (%(filename)s:%(lineno)d) - (%(name)s) "
    format_context = "%(levelname)s"
    format_end = ": %(message)s"

    FORMATS = {
        logging.DEBUG: blue + format_context + reset,
        logging.INFO: green + format_context + reset,
        logging.WARNING: bold_yellow + format_context + reset,
        logging.ERROR: bold_red + format_context + reset,
        logging.CRITICAL: bold_red + format_context + reset
>>>>>>> ce2bb54d8a9ca4a133729bb06db26bb38433e120
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(self.format_start + log_fmt + self.format_end)
        return formatter.format(record)


class Logger:
    def __init__(self):
        if self.__class__.__name__ == "Logger":
            class_name = "Root"
        elif self.__class__.__name__.islower():
            class_name = self.__class__.__name__.title()
        else:
            class_name = " ".join(re.findall("[A-Z][a-z]*", self.__class__.__name__))
        
        self.log = logging.getLogger(class_name)
        
        ch = logging.StreamHandler()
        ch.setFormatter(CustomFormatter())
        
        if not self.log.handlers:
            self.log.addHandler(ch)
            self.log.propagate = False

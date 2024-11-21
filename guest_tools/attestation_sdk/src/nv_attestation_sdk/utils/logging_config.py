#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#

"""Config file for maintaining logging format"""

import logging
import sys
import os


class SimpleMessageHandler(logging.StreamHandler):
    """
    Customized logging handler to display logs in a box format.
    """

    def emit(self, record):
        """
        Emit a formatted record to the stream.

        This method is called by the logging framework whenever a log event occurs.
        It formats the record and writes it to the stream.

        Parameters:
        - record (logging.LogRecord): The log record to be emitted.

        Returns:
        None
        """
        try:
            msg = self.format(record)
            stream = self.stream
            formatted_msg = self.center_message(msg, width=75)  # Adjust width as needed
            stream.write(f"{formatted_msg}\n")
            self.flush()
        except Exception as e:
            self.handleError(record)
            logging.error("An error occurred while emitting the log record: %s", str(e))

    def center_message(self, msg, width):
        """
        This method centers a given message within a box of specified width.

        Parameters:
        - msg (str): The message to be centered.
        - width (int): The total width of the box.

        Returns:
        str: The centered message within a box.
        """
        # Define the total width of the box
        total_width = width
        # Calculate padding
        padding = (
            total_width - len(msg) - 2
        ) // 2  # Subtract 2 for the spaces around the message
        padding = max(padding, 0)
        # Construct the centered message
        centered_msg = f"{' ' * padding}{msg}{' ' * padding}"
        if len(centered_msg) < total_width:
            centered_msg = centered_msg[:-1]
        # Construct the full box with @ symbols
        box_top_bottom = "-" * total_width
        return f"\n{box_top_bottom}\n{centered_msg}\n{box_top_bottom}"


def setup_logging():
    """
    This method centers a given message within a box of specified width.

    Parameters:
    - msg (str): The message to be centered.
    - width (int): The total width of the box.

    Returns:
    str: The centered message within a box.
    """
    logger = logging.getLogger("nv-attestation-sdk")
    logger.setLevel(logging.DEBUG)

    handler = SimpleMessageHandler(sys.stdout)
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)
    return logger


def get_logger():
    logger = logging.getLogger("sdk-logger")
    if logger.hasHandlers():
        return logger

    logger.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler(sys.stdout)
    console_formatter = logging.Formatter("%(message)s")
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(logging.INFO)

    logger_file_path = os.path.join(os.getcwd(), "attestation_sdk.log")
    if os.path.exists(logger_file_path):
        os.remove(logger_file_path)
    file_handler = logging.FileHandler(logger_file_path)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
            logging.Formatter("%(asctime)s:%(levelname)s: %(message)s", "%m-%d-%Y %H:%M:%S")
        )

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger



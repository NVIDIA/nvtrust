#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#

import logging
import sys
import os


class SimpleMessageHandler(logging.StreamHandler):
    def emit(self, record):
        try:
            msg = self.format(record)
            stream = self.stream
            formatted_msg = self.center_message(msg, width=75)  # Adjust width as needed
            stream.write(f"{formatted_msg}\n")
            self.flush()
        except Exception:
            self.handleError(record)

    def center_message(self, msg, width):
        # Define the total width of the box
        total_width = width
        # Calculate padding
        padding = (total_width - len(msg) - 2) // 2  # Subtract 2 for the spaces around the message
        if padding < 0:
            padding = 0
        # Construct the centered message
        centered_msg = f"{' ' * padding}{msg}{' ' * padding}"
        if len(centered_msg) < total_width:
            centered_msg = centered_msg[:-1]
        # Construct the full box with @ symbols
        box_top_bottom = "-" * total_width
        return f"\n{box_top_bottom}\n{centered_msg}\n{box_top_bottom}"


def setup_logging():
    # nv_attestation_sdk Logger
    logger = logging.getLogger('nv-attestation-sdk')
    logger.setLevel(logging.INFO)

    handler = SimpleMessageHandler(sys.stdout)
    formatter = logging.Formatter('%(message)s')
    handler.setFormatter(formatter)

    if not logger.handlers:
        logger.addHandler(handler)

    # default Logger
    default_logger = logging.getLogger('sdk-console')
    default_logger.setLevel(logging.INFO)

    default_handler = logging.StreamHandler(sys.stdout)
    default_handler.setFormatter(formatter)

    if not default_logger.handlers:
        default_logger.addHandler(default_handler)

    # create file handler which logs even debug messages
    debug_logger = logging.getLogger('sdk-file')
    debug_logger.setLevel(logging.DEBUG)
    logger_file_path = os.path.join(os.getcwd(), "attestation_sdk.log")

    if os.path.exists(logger_file_path):
        os.remove(logger_file_path)

    debug_handler = logging.FileHandler(logger_file_path)
    debug_handler.setFormatter(logging.Formatter("%(asctime)s:%(levelname)s: %(message)s", '%m-%d-%Y %H:%M:%S'))

    if not debug_logger.handlers:
        debug_logger.addHandler(debug_handler)
    return logger


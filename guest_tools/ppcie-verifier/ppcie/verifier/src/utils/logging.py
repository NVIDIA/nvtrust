#    Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.

"""Configurable logging per module to ensure granular level control of displaying information"""

import logging
import sys

from ppcie.verifier.src.utils import SimpleMessageHandler


def get_logger(level=None):
    """Configure logging for root project"""
    ppcie_logger = logging.getLogger("ppcie-console")
    if level is not None:
        ppcie_logger.setLevel(level)
    return ppcie_logger


def setup_logging():
    logger = logging.getLogger("ppcie-console")
    logger.setLevel(logging.INFO)

    handler = SimpleMessageHandler(sys.stdout)
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)

    if not logger.handlers:
        logger.addHandler(handler)

    return logger

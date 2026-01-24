# SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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


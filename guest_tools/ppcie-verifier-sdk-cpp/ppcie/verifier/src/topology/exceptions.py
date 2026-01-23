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

""" Exceptions for Topology module """

from ..utils.logging import get_logger

logger = get_logger()


class TopologyValidationError(Exception):
    """Base exceptions."""


class ParsingError(TopologyValidationError):
    """ParsingError is thrown when invalid arguments are provided in the attestation report constructor"""


class MeasurementSpecificationError(TopologyValidationError):
    """ParsingError is thrown when invalid arguments are provided in the attestation report constructor"""


class GpuTopologyValidationError(TopologyValidationError):
    """GpuTopologyValidationError is thrown when invalid arguments are provided in the attestation report constructor
    to get switches connected to each GPU"""


class SwitchTopologyValidationError(TopologyValidationError):
    """SwitchTopologyValidationError is thrown when invalid arguments are provided in the attestation report constructor
    to get GPU connected to each Switch"""
